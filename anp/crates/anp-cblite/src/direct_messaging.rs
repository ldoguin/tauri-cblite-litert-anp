//! ANP-09 P5 messaging for the node: the endpoint another ANP stack talks to (`POST /anp/direct`).
//!
//! It answers the key-service call `direct.e2ee.get_prekey_bundle` (our signed prekey bundle, and one one-time prekey
//! when the asker is a known peer) and accepts `direct.send`:
//!
//! * an **init** message starts a session (X3DH, with the one-time prekey if one was issued, which is used up);
//! * a **follow-up** message continues it (Double Ratchet, out-of-order delivery within the skip window);
//! * the plaintext (`text`, or a JSON payload with a `text` member) goes to this node's agent as an ordinary A2A message,
//!   and the agent's answer is sealed into the same session and POSTed back to the peer's own endpoint, signed with
//!   ANP-02. The answer is a follow-up, so the first one carries `pn = 0, n = 0` and turns the ratchet.
//!
//! Who may talk to us: only peers whose DID document we hold (`--allow-caller`). The sender is authenticated by the key
//! exchange itself: an init only decrypts if it was made with the static key-agreement key that the peer's DID document
//! publishes. Sessions and one-time prekeys are kept on disk.
//!
//! The node can also **start** a conversation ([`DirectMessaging::open`], and [`DirectMessaging::send`] after it): it
//! fetches the peer's prekey bundle from the peer's own endpoint (`direct.e2ee.get_prekey_bundle`, signed with ANP-02),
//! checks it against the peer's DID document, seals the first message as an init and hands it to the same outbox the
//! replies use. Once a session exists either side can ask in it, whoever started it.
//!
//! What comes back is told apart by counting: each message sent with [`DirectMessaging::send`] is a question that
//! awaits one answer from that peer, and while one is awaited the next message from the peer is that **answer**. It is
//! not given to the agent (two nodes would otherwise answer each other's answers for ever) but kept in the conversation
//! log and announced to [`DirectMessaging::subscribe`]rs, which is how whoever asked gets it. A message that arrives
//! with nothing awaited is a question for the agent, whose reply is not itself a question. (If both sides ask at the
//! same moment, each takes the other's question for its answer: the protocol carries no reply-to link that every ANP
//! stack would keep.) Everything sent and received, both ways, is in the log ([`DirectMessaging::conversation`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anp_e2ee::session::{Binding, LocalBundle, OneTimePrekey, Session};
use anp_e2ee::wire;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};

use crate::httpauth::DomainTrust;
use crate::hub::{settled, Hub};
use crate::trust::Trust;

/// A JSON-RPC failure: a P5 code (4000-4012) or a standard one.
type Fail = (i32, String);

/// How long the agent has to answer before the reply is given up.
const AGENT_WAIT: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct Peer {
    doc: anp_did::Verified,
    /// Where to POST replies: from `--direct-peer`, or the document's `ANPMessageService`.
    endpoint: Option<String>,
}

/// How many one-time prekeys the node keeps for each device that publishes to it.
const MAX_PUBLISHED_OPKS: usize = 1000;
/// A reply that cannot be delivered is retried with a growing delay (2 s, 4 s, ... 5 min) until it is this old.
const OUTBOX_MAX_AGE: i64 = 24 * 3600;
const OUTBOX_MAX_ATTEMPTS: u32 = 40;
/// An attempt in progress holds its entry this long, so that the loop does not start a second one.
const LEASE: i64 = 60;

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// A sealed reply waiting to be delivered. It is already encrypted into the session (the ratchet has moved on), so a
/// retry sends the very same message: the peer sees one message id however often it arrives.
#[derive(Clone, Debug)]
struct Pending {
    id: String,
    peer_did: String,
    /// The JSON-RPC request, serialized.
    rpc: String,
    attempts: u32,
    next_at: i64,
    created: i64,
    last_error: String,
}

impl Pending {
    fn to_json(&self) -> Value {
        json!({ "id": self.id, "peer": self.peer_did, "rpc": self.rpc, "attempts": self.attempts, "next_at": self.next_at, "created": self.created, "last_error": self.last_error })
    }
    fn from_json(v: &Value) -> Option<Pending> {
        Some(Pending {
            id: v["id"].as_str()?.to_string(),
            peer_did: v["peer"].as_str()?.to_string(),
            rpc: v["rpc"].as_str()?.to_string(),
            attempts: v["attempts"].as_u64()? as u32,
            next_at: v["next_at"].as_i64()?,
            created: v["created"].as_i64()?,
            last_error: v["last_error"].as_str().unwrap_or("").to_string(),
        })
    }
}

enum Outcome {
    Delivered,
    Retry(String),
    Dead(String),
}

/// How many messages the log keeps per peer (the oldest go first).
const LOG_PER_PEER: usize = 200;

/// Sign `body` with ANP-02 and POST it to `url`: the status and the answer. Blocking (call it from `spawn_blocking`).
pub(crate) fn post_signed(trust: &Trust, url: &str, body: &str) -> Result<(u16, String), String> {
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut req = ureq::post(url).timeout(Duration::from_secs(20)).set("content-type", "application/json");
    for (k, v) in trust.sign_http("POST", url, body.as_bytes(), &nonce)? {
        req = req.set(&k, &v);
    }
    match req.send_string(body) {
        Ok(resp) => {
            let s = resp.status();
            Ok((s, resp.into_string().unwrap_or_default()))
        }
        Err(ureq::Error::Status(code, resp)) => Ok((code, resp.into_string().unwrap_or_default())),
        Err(e) => Err(e.to_string()),
    }
}

/// The `meta` of a `direct.send` in `session`'s direction (from us to the peer).
fn direct_meta(b: &Binding, message_id: &str, content_type: &str) -> Value {
    json!({
        "profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
        "sender_did": b.local_did, "sender_device_id": b.local_device_id,
        "target": { "kind": "agent", "did": b.peer_did }, "recipient_device_id": b.peer_device_id,
        "operation_id": message_id, "message_id": message_id, "content_type": content_type, "created_at": iso_now(),
    })
}

/// What an application sends: a text, or a JSON object (a quote, an acceptance) as the payload.
pub fn plaintext_of(message_id: &str, text: Option<&str>, payload: Option<&Value>) -> Result<Value, String> {
    match (text, payload) {
        (Some(t), None) => Ok(json!({ "application_content_type": "text/plain", "text": t })),
        (None, Some(p)) if p.is_object() => Ok(anp_e2ee::session::payload_plaintext(message_id, p)),
        (None, Some(_)) => Err("the payload must be a JSON object".into()),
        _ => Err("give either a text or a payload".into()),
    }
}

/// Bundles and one-time prekeys that other devices published to this node, which then acts as their key service.
#[derive(Default)]
struct Published {
    bundles: HashMap<String, Value>,
    opks: HashMap<String, Vec<Value>>,
}

impl Published {
    fn to_json(&self) -> Value {
        json!({ "bundles": self.bundles, "opks": self.opks })
    }
    fn from_json(v: &Value) -> Published {
        let mut p = Published::default();
        for (k, b) in v["bundles"].as_object().into_iter().flatten() {
            p.bundles.insert(k.clone(), b.clone());
        }
        for (k, a) in v["opks"].as_object().into_iter().flatten() {
            p.opks.insert(k.clone(), a.as_array().cloned().unwrap_or_default());
        }
        p
    }
}

pub struct DirectMessaging {
    trust: Arc<Trust>,
    file: PathBuf,
    outbox: Mutex<Vec<Pending>>,
    outbox_file: PathBuf,
    wake: tokio::sync::Notify,
    published: Mutex<Published>,
    published_file: PathBuf,
    /// Peers we were given the documents of.
    peers: HashMap<String, Peer>,
    /// Peers on trusted domains, resolved over HTTPS as they first appear.
    dynamic: Mutex<HashMap<String, Peer>>,
    domains: Option<Arc<DomainTrust>>,
    sessions: Mutex<HashMap<String, Session>>,
    /// Every message sent and received, per peer DID, oldest first.
    log: Mutex<HashMap<String, Vec<Value>>>,
    log_file: PathBuf,
    /// Each logged message as it happens.
    events: tokio::sync::broadcast::Sender<Value>,
    /// Per peer DID: how many of our questions still await an answer.
    awaiting: Mutex<HashMap<String, u64>>,
    awaiting_file: PathBuf,
    /// A counterparty's quote desk: quote-protocol messages go to it instead of the agent (see `quotes`).
    seller: Mutex<Option<Arc<crate::quotes::QuoteSeller>>>,
}

fn skey(did: &str, device: &str) -> String {
    format!("{did}|{device}")
}
fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn fail<T>(code: i32, msg: impl Into<String>) -> Result<T, Fail> {
    Err((code, msg.into()))
}
fn rpc_error(code: i32, msg: &str) -> Value {
    if code >= 4000 {
        wire::rpc_error(code, msg)
    } else {
        json!({ "code": code, "message": msg })
    }
}

impl DirectMessaging {
    /// `docs` are the DID documents of the peers we talk to (each must verify); `endpoints` maps a peer's DID to where
    /// replies go; `dir` is where sessions are kept.
    pub fn new(trust: Arc<Trust>, dir: &std::path::Path, docs: Vec<Value>, endpoints: HashMap<String, String>, domains: Option<Arc<DomainTrust>>) -> Result<DirectMessaging, String> {
        if trust.direct_identity().is_none() {
            return Err("direct messaging needs end-to-end encryption (--e2ee) in DID mode".into());
        }
        let mut peers = HashMap::new();
        for d in docs {
            let v = anp_did::verify_document(&d, None).map_err(|e| format!("peer DID document: {e}"))?;
            let endpoint = endpoints.get(&v.did_string).cloned().or_else(|| v.service_endpoint("ANPMessageService"));
            peers.insert(v.did_string.clone(), Peer { doc: v, endpoint });
        }
        for (old, new) in [("p5-sessions.json", "direct-sessions.json"), ("p5-outbox.json", "direct-outbox.json"), ("p5-published.json", "direct-published.json")] {
            crate::adopt_renamed_file(dir, old, new);
        }
        let file = dir.join("direct-sessions.json");
        let mut sessions = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&file) {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
            for s in v.as_array().ok_or_else(|| format!("{}: expected an array", file.display()))? {
                let s = Session::from_json(s).map_err(|e| format!("{}: {e}", file.display()))?;
                sessions.insert(skey(&s.binding.peer_did, &s.binding.peer_device_id), s);
            }
        }
        let load = |name: &str| -> Result<Option<Value>, String> {
            let f = dir.join(name);
            match std::fs::read_to_string(&f) {
                Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| format!("{}: {e}", f.display())),
                Err(_) => Ok(None),
            }
        };
        let outbox: Vec<Pending> = load("direct-outbox.json")?.map(|v| v.as_array().cloned().unwrap_or_default().iter().filter_map(Pending::from_json).collect()).unwrap_or_default();
        let published = load("direct-published.json")?.map(|v| Published::from_json(&v)).unwrap_or_default();
        let log: HashMap<String, Vec<Value>> = load("direct-conversations.json")?
            .and_then(|v| v.as_object().cloned())
            .map(|o| o.into_iter().map(|(k, v)| (k, v.as_array().cloned().unwrap_or_default())).collect())
            .unwrap_or_default();
        let awaiting: HashMap<String, u64> =
            load("direct-awaiting.json")?.and_then(|v| v.as_object().cloned()).map(|o| o.into_iter().filter_map(|(k, v)| v.as_u64().map(|n| (k, n))).collect()).unwrap_or_default();
        Ok(DirectMessaging {
            seller: Mutex::new(None),
            awaiting: Mutex::new(awaiting),
            awaiting_file: dir.join("direct-awaiting.json"),
            log: Mutex::new(log),
            log_file: dir.join("direct-conversations.json"),
            events: tokio::sync::broadcast::channel(256).0,
            trust,
            file,
            outbox: Mutex::new(outbox),
            outbox_file: dir.join("direct-outbox.json"),
            wake: tokio::sync::Notify::new(),
            published: Mutex::new(published),
            published_file: dir.join("direct-published.json"),
            peers,
            dynamic: Mutex::new(HashMap::new()),
            domains,
            sessions: Mutex::new(sessions),
        })
    }

    /// Start the loop that delivers the outbox (replies are queued, and retried while the peer is unreachable).
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let _ = tokio::time::timeout(Duration::from_secs(1), me.wake.notified()).await;
                me.run_outbox().await;
            }
        });
    }

    /// Replies not yet delivered.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().unwrap().len()
    }

    pub fn published_devices(&self) -> usize {
        self.published.lock().unwrap().bundles.len()
    }

    fn write_json(&self, file: &std::path::Path, v: &Value) {
        let tmp = file.with_extension("tmp");
        let r = std::fs::write(&tmp, v.to_string()).and_then(|_| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&tmp, file)
        });
        if let Err(e) = r {
            log::warn!("could not save {}: {e}", file.display());
        }
    }

    fn save_outbox(&self, o: &[Pending]) {
        self.write_json(&self.outbox_file, &Value::Array(o.iter().map(Pending::to_json).collect()));
    }

    /// One pass: try every reply that is due.
    async fn run_outbox(self: &Arc<Self>) {
        let now = unix_now();
        let due: Vec<Pending> = {
            let mut o = self.outbox.lock().unwrap();
            let due: Vec<Pending> = o.iter().filter(|p| p.next_at <= now).cloned().collect();
            for p in o.iter_mut().filter(|p| p.next_at <= now) {
                p.next_at = now + LEASE;
            }
            due
        };
        for p in due {
            let outcome = self.attempt(&p).await;
            let mut o = self.outbox.lock().unwrap();
            let Some(i) = o.iter().position(|x| x.id == p.id) else { continue };
            match outcome {
                Outcome::Delivered => {
                    log::info!("direct messaging: reply {} delivered (attempt {})", p.id, p.attempts + 1);
                    o.remove(i);
                }
                Outcome::Dead(why) => {
                    log::warn!("direct messaging: reply {} dropped, the peer will not take it: {why}", p.id);
                    o.remove(i);
                }
                Outcome::Retry(why) => {
                    let e = &mut o[i];
                    e.attempts += 1;
                    e.last_error = why.clone();
                    if e.attempts >= OUTBOX_MAX_ATTEMPTS || unix_now() - e.created > OUTBOX_MAX_AGE {
                        log::warn!("direct messaging: reply {} dropped after {} attempts: {why}", p.id, e.attempts);
                        o.remove(i);
                    } else {
                        let delay = (2i64 << e.attempts.min(8)).min(300);
                        e.next_at = unix_now() + delay;
                        log::warn!("direct messaging: reply {} not delivered ({why}); next attempt in {delay} s", p.id);
                    }
                }
            }
            self.save_outbox(&o);
        }
    }

    /// Send one queued reply: signed with ANP-02 afresh each time, to the peer's current endpoint.
    async fn attempt(&self, p: &Pending) -> Outcome {
        let Some(url) = self.peer(&p.peer_did).and_then(|x| x.endpoint) else {
            return Outcome::Retry("no endpoint for the peer (--direct-peer DID=URL, or an ANPMessageService in its document)".into());
        };
        let (trust, rpc) = (self.trust.clone(), p.rpc.clone());
        let r = tokio::task::spawn_blocking(move || post_signed(&trust, &url, &rpc)).await;
        match r {
            Err(e) => Outcome::Retry(format!("delivery task failed: {e}")),
            Ok(Err(e)) => Outcome::Retry(e),
            Ok(Ok((200, body))) => match serde_json::from_str::<Value>(&body).ok().filter(|v| v.get("error").is_some()) {
                // the peer reached its P5 layer and refused: sending the same bytes again will not change that
                Some(v) => Outcome::Dead(format!("the peer answered with an error: {}", v["error"])),
                None => Outcome::Delivered,
            },
            // 401/403/404 can be a peer that has not yet learned who we are, or an endpoint being set up: bounded retries
            Ok(Ok((c, _))) if matches!(c, 401 | 403 | 404 | 408 | 425 | 429) || c >= 500 =>Outcome::Retry(format!("the peer answered HTTP {c}")),
            Ok(Ok((c, _))) => Outcome::Dead(format!("the peer answered HTTP {c}")),
        }
    }

    pub fn peers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.peers.keys().cloned().chain(self.dynamic.lock().unwrap().keys().cloned()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Answer quote-protocol messages with this desk rather than the agent.
    pub fn set_seller(&self, s: Arc<crate::quotes::QuoteSeller>) {
        *self.seller.lock().unwrap() = Some(s);
    }

    /// The verified DID document of a peer (given, or resolved from a trusted domain).
    pub fn peer_document(&self, did: &str) -> Option<anp_did::Verified> {
        self.peer(did).map(|p| p.doc)
    }

    /// A peer: one we were given, or one resolved from a trusted domain.
    fn peer(&self, did: &str) -> Option<Peer> {
        self.peers.get(did).cloned().or_else(|| self.dynamic.lock().unwrap().get(did).cloned())
    }

    /// A DID we do not know yet, on a domain we trust: fetch its document over HTTPS (verified, e1 only) and remember it.
    /// Its `ANPMessageService` is where replies go.
    async fn learn(&self, did: &str) {
        if self.peer(did).is_some() {
            return;
        }
        let Some(d) = &self.domains else { return };
        if !d.allows(did) {
            return;
        }
        match d.resolve(did).await {
            Ok(r) => match r.verified {
                Some(doc) => {
                    let endpoint = doc.service_endpoint("ANPMessageService");
                    log::info!("direct messaging: resolved {did} from {} (reply endpoint: {})", r.domain, endpoint.as_deref().unwrap_or("none"));
                    self.dynamic.lock().unwrap().insert(did.to_string(), Peer { doc, endpoint });
                }
                None => log::warn!("direct messaging: {did} is not a did:wba e1 DID, so it cannot take part in a direct-messaging (P5) session"),
            },
            Err(e) => log::warn!("direct messaging: could not resolve {did}: {e}"),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    // ── the conversation log ────────────────────────────────────────────────────────────────────────

    /// Each message as it is sent or received: `{peer, direction: "in"|"out", message_id, at, plaintext, answer}`
    /// (`answer` is true for a message received in a conversation this node started).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Value> {
        self.events.subscribe()
    }

    /// The messages exchanged with `peer_did`, oldest first.
    pub fn conversation(&self, peer_did: &str) -> Vec<Value> {
        self.log.lock().unwrap().get(peer_did).cloned().unwrap_or_default()
    }

    /// One line per peer: how many messages, the last one, and the state of the session.
    pub fn conversations(&self) -> Vec<Value> {
        let log = self.log.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        let mut out: Vec<Value> = log
            .iter()
            .map(|(peer, msgs)| {
                let s = sessions.values().find(|s| &s.binding.peer_did == peer);
                json!({
                    "peer": peer,
                    "messages": msgs.len(),
                    "last": msgs.last(),
                    "session": s.map(|s| if !s.is_established() { "waiting for the first answer" } else if s.is_initiator() { "started here" } else { "started by the peer" }),
                })
            })
            .collect();
        out.sort_by(|a, b| a["peer"].as_str().cmp(&b["peer"].as_str()));
        out
    }

    fn record(&self, peer_did: &str, direction: &str, message_id: &str, plaintext: &Value, answer: bool) {
        let entry = json!({ "peer": peer_did, "direction": direction, "message_id": message_id, "at": iso_now(), "plaintext": plaintext, "answer": answer });
        {
            let mut log = self.log.lock().unwrap();
            let msgs = log.entry(peer_did.to_string()).or_default();
            msgs.push(entry.clone());
            if msgs.len() > LOG_PER_PEER {
                let extra = msgs.len() - LOG_PER_PEER;
                msgs.drain(..extra);
            }
            self.write_json(&self.log_file, &json!(*log));
        }
        let _ = self.events.send(entry); // nobody listening is fine
    }

    /// Count one more question to `peer_did` (`up`), or take one answer off (returns whether one was awaited).
    fn awaited(&self, peer_did: &str, up: bool) -> bool {
        let mut a = self.awaiting.lock().unwrap();
        let n = a.entry(peer_did.to_string()).or_insert(0);
        let was = *n > 0;
        if up {
            *n += 1;
        } else if was {
            *n -= 1;
        }
        a.retain(|_, n| *n > 0);
        self.write_json(&self.awaiting_file, &json!(*a));
        was
    }

    /// Queue a `direct.send` for the outbox and wake it.
    fn enqueue(&self, peer_did: &str, message_id: &str, request: &Value) {
        let rpc = json!({ "jsonrpc": "2.0", "id": message_id, "method": request["method"], "params": request["params"] }).to_string();
        {
            let mut o = self.outbox.lock().unwrap();
            o.push(Pending { id: message_id.to_string(), peer_did: peer_did.to_string(), rpc, attempts: 0, next_at: 0, created: unix_now(), last_error: String::new() });
            self.save_outbox(&o);
        }
        self.wake.notify_one();
    }

    fn save(&self, sessions: &HashMap<String, Session>) {
        let arr: Vec<Value> = sessions.values().map(Session::to_json).collect();
        let tmp = self.file.with_extension("tmp");
        let r = std::fs::write(&tmp, Value::Array(arr).to_string()).and_then(|_| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&tmp, &self.file)
        });
        if let Err(e) = r {
            log::warn!("could not save the direct-messaging sessions: {e}");
        }
    }

    /// Handle one JSON-RPC request and return the response object.
    /// `caller` is the DID that signed the HTTP request (ANP-02), when the node requires that.
    pub async fn handle(self: &Arc<Self>, hub: &Arc<Hub>, req: Value, caller: Option<String>) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req["method"].as_str().unwrap_or("").to_string();
        // the wire objects are {method, params}; the JSON-RPC binding adds jsonrpc and id around them
        let call = json!({ "method": req["method"], "params": req["params"] });
        if let Some(sender) = call["params"]["meta"]["sender_did"].as_str() {
            self.learn(sender).await; // a sender on a trusted domain is resolved before its message is looked at
        }
        let result = match method.as_str() {
            wire::METHOD_GET => self.get_bundle(&call),
            wire::METHOD_PUBLISH => self.publish(&call, caller.as_deref()),
            wire::METHOD_DIRECT_SEND => self.direct_send(hub, &call),
            _ => fail(-32601, format!("method not found: {method}")),
        };
        match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": rpc_error(code, &msg) }),
        }
    }

    fn me(&self) -> (String, String, String, [u8; 32]) {
        self.trust.direct_identity().expect("checked in new")
    }

    fn get_bundle(&self, req: &Value) -> Result<Value, Fail> {
        let (meta, did, device, _suite, require_opk) = wire::parse_get_prekey_bundle_request(req).map_err(|e| (-32602, e.0))?;
        let (my_did, my_device, _, _) = self.me();
        if did != my_did || device != my_device {
            return self.get_published(&meta, &did, &device, require_opk);
        }
        let bundle = self.trust.e2ee_bundle().ok_or((4000, "no bundle".to_string()))?;
        // one-time prekeys are scarce: only known peers may take one
        let known = meta["sender_did"].as_str().map_or(false, |d| self.peer(d).is_some());
        let opk = if known { self.trust.direct_issue_one_time_prekey() } else { None };
        if require_opk && opk.is_none() {
            return fail(4003, "no one-time prekey available");
        }
        Ok(wire::get_prekey_bundle_result(&did, &device, &bundle, opk.as_ref()))
    }

    fn direct_send(self: &Arc<Self>, hub: &Arc<Hub>, req: &Value) -> Result<Value, Fail> {
        let (meta, body, init) = wire::parse_direct_send_request(req).map_err(|e| (-32602, e.0))?;
        let (my_did, my_device, my_ka_id, my_ka_secret) = self.me();
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let (sender_did, sender_device, message_id) = (s(&meta["sender_did"]), s(&meta["sender_device_id"]), s(&meta["message_id"]));
        if s(&meta["target"]["did"]) != my_did || s(&meta["recipient_device_id"]) != my_device {
            return fail(4012, "this message is not addressed to this device");
        }
        let peer = self.peer(&sender_did).ok_or((4012, format!("{sender_did} is not a peer of this node")))?;
        let (peer_ka_id, peer_ka_pub) = peer.doc.key_agreement().ok_or((4004, "the sender's DID document publishes no key-agreement key".to_string()))?;
        if peer.doc.device_for_key_agreement(&peer_ka_id).as_deref() != Some(sender_device.as_str()) {
            return fail(4012, "the sender's device is not the one its DID document lists for that key");
        }
        let binding = Binding {
            local_did: my_did.clone(),
            local_device_id: my_device.clone(),
            local_ka_id: my_ka_id,
            peer_did: sender_did.clone(),
            peer_device_id: sender_device.clone(),
            peer_ka_id: peer_ka_id.clone(),
        };
        let key = skey(&sender_did, &sender_device);
        let plaintext;
        {
            let mut sessions = self.sessions.lock().unwrap();
            if init {
                if body["sender_static_key_agreement_id"].as_str() != Some(peer_ka_id.as_str()) {
                    return fail(4012, "the init's sender key-agreement id is not the one in the sender's DID document");
                }
                let (spk_id, spk_secret) = self.trust.direct_prekey_for_bundle(body["recipient_bundle_id"].as_str().unwrap_or("")).ok_or((4007, "unknown or deleted bundle".to_string()))?;
                if body["recipient_signed_prekey_id"].as_str() != Some(spk_id.as_str()) {
                    return fail(4007, "the signed prekey is not the bundle's");
                }
                if sessions.get(&key).map_or(false, |s| s.session_id() == body["session_id"].as_str().unwrap_or("")) {
                    return fail(4008, "this init was already accepted");
                }
                let opk_id = body["recipient_one_time_prekey_id"].as_str().map(str::to_string);
                let opk_secret = match &opk_id {
                    Some(id) => Some(self.trust.direct_consume_one_time_prekey(id).ok_or((4003, format!("one-time prekey {id} was not issued or is used up")))?),
                    None => None,
                };
                let local = LocalBundle {
                    bundle_id: body["recipient_bundle_id"].as_str().unwrap_or(""),
                    signed_prekey_id: &spk_id,
                    signed_prekey_secret: &spk_secret,
                    one_time_prekey: opk_id.as_deref().zip(opk_secret.as_ref()),
                };
                let (session, plain) = Session::accept(&binding, &message_id, &my_ka_secret, &local, &peer_ka_pub, &body).map_err(|e| (wire::error_code_for(&e), e.0))?;
                sessions.insert(key.clone(), session); // a new init replaces an older session with this peer device
                plaintext = plain;
            } else {
                let session = sessions.get_mut(&key).ok_or((4005, "no session with this device".to_string()))?;
                if body["session_id"].as_str() != Some(session.session_id()) {
                    return fail(4005, "no such session");
                }
                plaintext = session.decrypt(&message_id, &body).map_err(|e| (wire::error_code_for(&e), e.0))?;
            }
            self.save(&sessions);
        }
        // the answer to a question we asked: for whoever asked, not for the agent
        let answer = self.awaited(&sender_did, false);
        self.record(&sender_did, "in", &message_id, &plaintext, answer);
        if answer {
            return Ok(wire::direct_send_result(&s(&meta["message_id"]), &my_did, &my_device, &iso_now()));
        }
        let hub = hub.clone();
        let me = self.clone();
        tokio::spawn(async move { me.deliver(hub, key, message_id, plaintext).await });
        Ok(wire::direct_send_result(&s(&meta["message_id"]), &my_did, &my_device, &iso_now()))
    }

    /// Run the message through the agent and send its answer back to the peer, sealed into the session.
    async fn deliver(self: Arc<Self>, hub: Arc<Hub>, key: String, in_id: String, plaintext: Value) {
        // a quote-protocol message for a counterparty's desk: it answers with a signed message, the agent is not involved
        let seller = self.seller.lock().unwrap().clone();
        if let (Some(desk), Some(msg)) = (seller, crate::quotes::quote_message(&plaintext)) {
            let peer = self.sessions.lock().unwrap().get(&key).and_then(|s| self.peer(&s.binding.peer_did));
            let Some(peer) = peer else { return };
            match desk.handle(&peer.doc, msg) {
                Ok(answer) => {
                    let id = answer["id"].as_str().unwrap_or("answer").to_string();
                    let sent = plaintext_of(&id, None, Some(&answer)).and_then(|p| self.seal_and_queue(&key, &p, false));
                    if let Err(e) = sent {
                        log::warn!("quote desk: cannot send the answer to {in_id}: {e}");
                    }
                }
                Err(e) => log::warn!("quote desk: {in_id} not answered: {e}"),
            }
            return;
        }
        // a text, or a structured payload (a quote, an acceptance) handed over as its JSON
        let text = plaintext["text"]
            .as_str()
            .or_else(|| plaintext["payload"]["text"].as_str())
            .map(str::to_string)
            .or_else(|| plaintext.get("payload").filter(|p| p.is_object()).map(Value::to_string));
        let Some(text) = text else {
            log::warn!("direct message {in_id}: nothing the agent can read (needs a text)");
            return;
        };
        let req = match serde_json::from_value(json!({ "message": { "messageId": uuid::Uuid::new_v4().to_string(), "role": "ROLE_USER", "parts": [{ "text": text }] } })) {
            Ok(r) => r,
            Err(e) => return log::warn!("direct messaging: cannot build the A2A message: {e}"),
        };
        let mut rx = hub.subscribe();
        let (tid, baseline) = match hub.send_message(&req).await {
            Ok(x) => x,
            Err(e) => return log::warn!("direct messaging: the agent refused the message: {}", e.message),
        };
        let task = match hub.wait_for(&tid, &mut rx, AGENT_WAIT, |t| settled(t, baseline.as_deref())).await {
            Ok(Some(t)) => t,
            other => return log::warn!("direct messaging: no answer from the agent: {other:?}"),
        };
        let tv = serde_json::to_value(&task).unwrap_or(Value::Null);
        let reply: String = tv["artifacts"].as_array().into_iter().flatten().flat_map(|a| a["parts"].as_array().into_iter().flatten()).filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("");
        let reply = if reply.is_empty() { format!("({})", tv["status"]["state"].as_str().unwrap_or("done")) } else { reply };

        let peer_did = match self.sessions.lock().unwrap().get(&key) {
            Some(s) => s.binding.peer_did.clone(),
            None => return,
        };
        let plain = json!({ "application_content_type": "text/plain", "text": reply });
        if let Err(e) = self.seal_and_queue(&key, &plain, false) {
            log::warn!("direct messaging: cannot send the reply to {peer_did}: {e}");
        }
    }

    /// Encrypt `plaintext` into the established session `key` and queue it; a `question` awaits an answer. Returns the
    /// message id.
    fn seal_and_queue(&self, key: &str, plaintext: &Value, question: bool) -> Result<String, String> {
        let (peer_did, request, out_id) = {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions.get_mut(key).ok_or("no session with that peer")?;
            if self.peer(&session.binding.peer_did).is_none() {
                return Err("that peer is no longer known".into());
            }
            let out_id = format!("direct-{}", uuid::Uuid::new_v4());
            let body = session.encrypt(&out_id, plaintext).map_err(|e| e.to_string())?;
            let request = wire::direct_send_request(&direct_meta(&session.binding, &out_id, wire::CIPHER_CT), &body).map_err(|e| e.to_string())?;
            let peer_did = session.binding.peer_did.clone();
            self.save(&sessions);
            (peer_did, request, out_id)
        };
        // sealed and the session saved; from here it is the outbox's job to get it there
        if question {
            self.awaited(&peer_did, true);
        }
        self.record(&peer_did, "out", &out_id, plaintext, false);
        self.enqueue(&peer_did, &out_id, &request);
        Ok(out_id)
    }

    // ── starting a conversation ─────────────────────────────────────────────────────────────────────

    /// Ask `peer_did` (see [`plaintext_of`]): in the session we already have with it if there is one that can send,
    /// whoever started it, or by starting a new one ([`DirectMessaging::open`]). The next message from that peer is
    /// taken as the answer. Returns the message id.
    pub async fn send(self: &Arc<Self>, peer_did: &str, plaintext: &Value) -> Result<String, String> {
        let key = self.sessions.lock().unwrap().iter().find(|(_, s)| s.binding.peer_did == peer_did).map(|(k, s)| (k.clone(), s.is_established()));
        match key {
            Some((k, true)) => self.seal_and_queue(&k, plaintext, true),
            Some((_, false)) => Err("the conversation with that peer is waiting for its first answer; send again once it has come".into()),
            None => self.open(peer_did, plaintext).await,
        }
    }

    /// Start a conversation with `peer_did`: resolve it if it is on a trusted domain, fetch its prekey bundle from its
    /// endpoint (with a one-time prekey when it has one for us), check the bundle against its DID document, and queue
    /// the init. A session we had with that peer is replaced. Returns the message id.
    pub async fn open(self: &Arc<Self>, peer_did: &str, plaintext: &Value) -> Result<String, String> {
        self.learn(peer_did).await;
        let peer = self.peer(peer_did).ok_or_else(|| format!("{peer_did} is not a peer of this node (give its document with --allow-caller, or trust its domain)"))?;
        let url = peer.endpoint.clone().ok_or("no endpoint for that peer (--direct-peer DID=URL, or an ANPMessageService in its document)")?;
        let (peer_ka_id, _) = peer.doc.key_agreement().ok_or("the peer's DID document publishes no key-agreement key")?;
        let device = peer.doc.device_for_key_agreement(&peer_ka_id).ok_or("the peer's DID document lists no device for its key-agreement key")?;
        let (my_did, my_device, my_ka_id, my_ka_secret) = self.me();

        // the key-service call, to the peer itself
        let op = format!("op-{}", uuid::Uuid::new_v4());
        let meta = json!({ "profile": "anp.direct.e2ee.v2", "security_profile": wire::TRANSPORT_PROTECTED, "sender_did": my_did, "sender_device_id": my_device,
                           "target": { "kind": "service", "did": peer_did }, "operation_id": op });
        let get = wire::get_prekey_bundle_request(&meta, peer_did, &device, None, None).map_err(|e| e.to_string())?;
        let rpc = json!({ "jsonrpc": "2.0", "id": op, "method": get["method"], "params": get["params"] }).to_string();
        let trust = self.trust.clone();
        let (status, text) = tokio::task::spawn_blocking(move || post_signed(&trust, &url, &rpc)).await.map_err(|e| e.to_string())??;
        let answer: Value = serde_json::from_str(&text).map_err(|_| format!("the peer's key service answered HTTP {status} with no JSON"))?;
        if let Some(e) = answer.get("error") {
            return Err(format!("the peer's key service refused: {e}"));
        }
        let result = &answer["result"];
        wire::parse_get_prekey_bundle_result(result).map_err(|e| format!("the peer's key service: {e}"))?;
        let bundle = anp_e2ee::parse_bundle(&result["prekey_bundle"], &peer.doc, &iso_now()).map_err(|e| format!("the peer's prekey bundle: {e}"))?;
        let opk = match result.get("one_time_prekey") {
            Some(o) => {
                let raw = B64U.decode(o["public_key_b64u"].as_str().unwrap_or("")).map_err(|_| "a malformed one-time prekey")?;
                Some(OneTimePrekey { id: o["key_id"].as_str().unwrap_or("").to_string(), public: raw.try_into().map_err(|_| "a one-time prekey that is not 32 bytes")? })
            }
            None => None,
        };

        let binding = Binding { local_did: my_did, local_device_id: my_device, local_ka_id: my_ka_id, peer_did: peer_did.to_string(), peer_device_id: device.clone(), peer_ka_id };
        let out_id = format!("direct-{}", uuid::Uuid::new_v4());
        let (session, body) = Session::initiate(&binding, &out_id, &my_ka_secret, &bundle, opk.as_ref(), plaintext).map_err(|e| e.to_string())?;
        let request = wire::direct_send_request(&direct_meta(&binding, &out_id, wire::INIT_CT), &body).map_err(|e| e.to_string())?;
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, s| s.binding.peer_did != peer_did); // one conversation per peer: the new one replaces it
            sessions.insert(skey(peer_did, &device), session);
            self.save(&sessions);
        }
        log::info!("direct messaging: started a conversation with {peer_did} ({})", if opk.is_some() { "with a one-time prekey" } else { "signed prekey only" });
        self.awaited(peer_did, true);
        self.record(peer_did, "out", &out_id, plaintext, false);
        self.enqueue(peer_did, &out_id, &request);
        Ok(out_id)
    }

    // ── key service for other devices ───────────────────────────────────────────────────────────────

    fn pkey(did: &str, device: &str) -> String {
        format!("{did}|{device}")
    }

    fn save_published(&self, p: &Published) {
        self.write_json(&self.published_file, &p.to_json());
    }

    /// `direct.e2ee.publish_prekey_bundle`: a peer stores its bundle (and one-time prekeys) here, so that others can fetch
    /// them while it is offline. Only the peer itself may publish: the request must have been signed (ANP-02) by the
    /// publisher's DID, and the bundle must verify against that DID's document.
    fn publish(&self, req: &Value, caller: Option<&str>) -> Result<Value, Fail> {
        let (meta, bundle, opks) = wire::parse_publish_prekey_bundle_request(req).map_err(|e| (-32602, e.0))?;
        let sender = meta["sender_did"].as_str().unwrap_or("").to_string();
        let peer = self.peer(&sender).ok_or((4012, format!("{sender} is not a peer of this node")))?;
        if caller != Some(sender.as_str()) {
            return fail(4012, "publishing needs a request signed by the publisher's own DID (run the node with --require-auth)");
        }
        let now = iso_now();
        let b = anp_e2ee::parse_bundle(&bundle, &peer.doc, &now).map_err(|e| (if e.0.contains("expired") { 4002 } else { 4001 }, e.0))?;
        let key = Self::pkey(&b.owner_did, &b.device_id);
        let count = {
            let mut p = self.published.lock().unwrap();
            p.bundles.insert(key.clone(), bundle);
            let pool = p.opks.entry(key).or_default();
            for o in opks {
                if !pool.iter().any(|x| x["key_id"] == o["key_id"]) && pool.len() < MAX_PUBLISHED_OPKS {
                    pool.push(o);
                }
            }
            let n = pool.len() as u64;
            self.save_published(&p);
            n
        };
        Ok(wire::publish_prekey_bundle_result(&b.owner_did, &b.device_id, &b.bundle_id, &now, count))
    }

    /// `direct.e2ee.get_prekey_bundle` for a device that published here. The bundle is checked again against the
    /// owner's DID document if we have it, and one one-time prekey is handed out (and gone) to a known peer.
    fn get_published(&self, meta: &Value, did: &str, device: &str, require_opk: bool) -> Result<Value, Fail> {
        let key = Self::pkey(did, device);
        let mut p = self.published.lock().unwrap();
        let Some(bundle) = p.bundles.get(&key).cloned() else { return fail(4000, "no bundle for that device here") };
        if bundle["signed_prekey"]["expires_at"].as_str().map_or(true, |e| e <= iso_now().as_str()) {
            return fail(4002, "the published bundle has expired");
        }
        let known = meta["sender_did"].as_str().map_or(false, |d| self.peer(d).is_some());
        let opk = if known { p.opks.get_mut(&key).filter(|v| !v.is_empty()).map(|v| v.remove(0)) } else { None };
        if require_opk && opk.is_none() {
            return fail(4003, "no one-time prekey available");
        }
        if opk.is_some() {
            self.save_published(&p);
        }
        Ok(wire::get_prekey_bundle_result(did, device, &bundle, opk.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::io::{Read, Write};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("anp-direct-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn node(name: &str, seed: u8, d: &std::path::Path) -> Arc<Trust> {
        Arc::new(Trust::new(name, SigningKey::from_bytes(&[seed; 32])).with_did(&format!("{name}.example.com"), None, None).unwrap().with_e2ee(d).unwrap())
    }
    fn service_meta(sender: &(String, String, String, [u8; 32]), op: &str) -> Value {
        json!({ "profile": "anp.direct.e2ee.v2", "security_profile": "transport-protected", "sender_did": sender.0, "sender_device_id": sender.1,
                "target": { "kind": "service", "did": "did:wba:me.example.com:services:message" }, "operation_id": op })
    }

    #[tokio::test]
    async fn a_peer_can_publish_its_bundle_and_others_fetch_it_one_prekey_at_a_time() {
        let (dm, dp) = (dir("pub-me"), dir("pub-peer"));
        let (me, peer) = (node("me", 1, &dm), node("peer", 2, &dp));
        let direct = DirectMessaging::new(me.clone(), &dm, vec![peer.did_document().unwrap()], HashMap::new(), None).unwrap();
        let id = peer.direct_identity().unwrap();
        let bundle = peer.e2ee_bundle().unwrap();
        let opks = vec![peer.direct_issue_one_time_prekey().unwrap(), peer.direct_issue_one_time_prekey().unwrap()];
        let req = wire::publish_prekey_bundle_request(&service_meta(&id, "op-pub"), &bundle, &opks).unwrap();

        assert_eq!(direct.publish(&req, None).unwrap_err().0, 4012, "an unauthenticated publish is refused");
        assert_eq!(direct.publish(&req, Some("did:wba:eve.example.com:agents:eve:e1_x")).unwrap_err().0, 4012, "so is one signed by someone else");
        let r = direct.publish(&req, Some(&id.0)).unwrap();
        assert!(wire::parse_publish_prekey_bundle_result(&r).is_ok());
        assert_eq!(r["published_opk_count"], 2);
        direct.publish(&req, Some(&id.0)).unwrap();
        assert_eq!(direct.published.lock().unwrap().opks.values().next().unwrap().len(), 2, "the same one-time prekeys are not stored twice");

        let ask = |sender: &(String, String, String, [u8; 32]), require| {
            let g = wire::get_prekey_bundle_request(&service_meta(sender, "op-get"), &id.0, &id.1, None, Some(require)).unwrap();
            direct.get_bundle(&g)
        };
        let first = ask(&id, true).unwrap();
        assert!(wire::parse_get_prekey_bundle_result(&first).is_ok());
        assert_eq!(first["one_time_prekey"]["key_id"], opks[0]["key_id"]);
        assert_eq!(first["prekey_bundle"], bundle);
        assert_eq!(ask(&id, true).unwrap()["one_time_prekey"]["key_id"], opks[1]["key_id"], "each is handed out once, in order");
        assert_eq!(ask(&id, true).unwrap_err().0, 4003, "none left");
        let plain = ask(&id, false).unwrap();
        assert!(plain.get("one_time_prekey").is_none() && plain.get("prekey_bundle").is_some(), "the bundle is still served without one");
        let stranger = ("did:wba:eve.example.com:agents:eve:e1_x".to_string(), "dev-eve".to_string(), String::new(), [0u8; 32]);
        let g = wire::get_prekey_bundle_request(&service_meta(&stranger, "op-get"), &id.0, &id.1, None, Some(false)).unwrap();
        direct.publish(&req, Some(&id.0)).unwrap(); // refill
        assert!(direct.get_bundle(&g).unwrap().get("one_time_prekey").is_none(), "a stranger gets no one-time prekey");
        let none = wire::get_prekey_bundle_request(&service_meta(&id, "op-get"), &id.0, "dev-other", None, None).unwrap();
        assert_eq!(direct.get_bundle(&none).unwrap_err().0, 4000);

        // kept on disk
        let again = DirectMessaging::new(me, &dm, vec![peer.did_document().unwrap()], HashMap::new(), None).unwrap();
        assert_eq!(again.published_devices(), 1);
        assert_eq!(ask_count(&again), 2, "the pool survived a restart");

        // a bundle that does not verify against the publisher's document is refused
        let mut bad = bundle.clone();
        bad["signed_prekey"]["public_key_b64u"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let req = wire::publish_prekey_bundle_request(&service_meta(&id, "op-bad"), &bad, &[]).unwrap();
        assert_eq!(direct.publish(&req, Some(&id.0)).unwrap_err().0, 4001);
    }
    fn ask_count(p: &DirectMessaging) -> usize {
        p.published.lock().unwrap().opks.values().next().map_or(0, |v| v.len())
    }

    /// A one-thread HTTP server that answers with the given statuses in turn (the last repeats) and records the requests.
    fn server(codes: Vec<u16>) -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for (i, conn) in l.incoming().enumerate() {
                let Ok(mut c) = conn else { continue };
                // read the whole request (headers, then the body they announce) so the client is never reset mid-send
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let mut got: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end].to_ascii_lowercase().split("content-length:").nth(1).and_then(|s| s.split("\r\n").next()).and_then(|s| s.trim().parse::<usize>().ok()).unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                s2.lock().unwrap().push(String::from_utf8_lossy(&got).to_string());
                let code = codes.get(i).or(codes.last()).copied().unwrap_or(200);
                let body = if code == 200 { r#"{"jsonrpc":"2.0","id":"x","result":{}}"# } else { "no" };
                let _ = write!(c, "HTTP/1.1 {code} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}", body.len());
            }
        });
        (port, seen)
    }
    fn pending(peer: &str, id: &str) -> Pending {
        Pending { id: id.into(), peer_did: peer.into(), rpc: r#"{"jsonrpc":"2.0","id":"x","method":"direct.send","params":{}}"#.into(), attempts: 0, next_at: 0, created: unix_now(), last_error: String::new() }
    }

    #[tokio::test]
    async fn a_reply_that_cannot_be_delivered_is_kept_and_retried_until_it_goes_through() {
        let (dm, dp) = (dir("ob-me"), dir("ob-peer"));
        let (me, peer) = (node("me", 1, &dm), node("peer", 2, &dp));
        let peer_did = peer.did().unwrap().to_string();
        let (port, seen) = server(vec![503, 503, 200]);
        let endpoints = HashMap::from([(peer_did.clone(), format!("http://127.0.0.1:{port}/inbox"))]);
        let direct = Arc::new(DirectMessaging::new(me.clone(), &dm, vec![peer.did_document().unwrap()], endpoints.clone(), None).unwrap());
        direct.outbox.lock().unwrap().push(pending(&peer_did, "r1"));

        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 1, "the peer was down: the reply stays");
        {
            let o = direct.outbox.lock().unwrap();
            assert_eq!(o[0].attempts, 1);
            assert!(o[0].last_error.contains("503"));
            assert!(o[0].next_at > unix_now(), "and waits before the next attempt");
        }
        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 1, "a pass before the time is up does nothing");
        assert_eq!(seen.lock().unwrap().len(), 1);

        // a restart in between loses nothing
        let direct = Arc::new(DirectMessaging::new(me, &dm, vec![peer.did_document().unwrap()], endpoints, None).unwrap());
        assert_eq!(direct.outbox_len(), 1);
        direct.outbox.lock().unwrap()[0].next_at = 0;
        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 1);
        direct.outbox.lock().unwrap()[0].next_at = 0;
        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 0, "the third attempt got through");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|r| r.to_ascii_lowercase().contains("signature-input:")), "every attempt is signed afresh");
        let nonces: std::collections::HashSet<&str> = seen.iter().filter_map(|r| r.split("nonce=\"").nth(1)).filter_map(|s| s.split('"').next()).collect();
        assert_eq!(nonces.len(), 3, "with a new nonce each time");
        assert_eq!(std::fs::read_to_string(dm.join("direct-outbox.json")).unwrap().trim(), "[]");
    }

    #[tokio::test]
    async fn a_reply_the_peer_refuses_for_good_is_dropped_and_one_without_an_endpoint_waits() {
        let (dm, dp) = (dir("dead-me"), dir("dead-peer"));
        let (me, peer) = (node("me", 1, &dm), node("peer", 2, &dp));
        let peer_did = peer.did().unwrap().to_string();
        let (port, _) = server(vec![400]);
        let direct = Arc::new(DirectMessaging::new(me.clone(), &dm, vec![peer.did_document().unwrap()], HashMap::from([(peer_did.clone(), format!("http://127.0.0.1:{port}/inbox"))]), None).unwrap());
        direct.outbox.lock().unwrap().push(pending(&peer_did, "r-bad"));
        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 0, "HTTP 400 will not get better by repeating it");

        let d2 = dir("noep-me");
        let direct = Arc::new(DirectMessaging::new(node("me", 1, &d2), &d2, vec![peer.did_document().unwrap()], HashMap::new(), None).unwrap());
        direct.outbox.lock().unwrap().push(pending(&peer_did, "r-wait"));
        direct.run_outbox().await;
        let o = direct.outbox.lock().unwrap();
        assert_eq!(o.len(), 1);
        assert!(o[0].last_error.contains("no endpoint"));
    }

    #[test]
    fn what_an_application_sends_is_a_text_or_an_object() {
        assert_eq!(plaintext_of("m", Some("hi"), None).unwrap(), json!({ "application_content_type": "text/plain", "text": "hi" }));
        let p = plaintext_of("m", None, Some(&json!({ "type": "Quote" }))).unwrap();
        assert_eq!(p["payload"]["type"], "Quote");
        assert_eq!(p["logical_message_id"], "m");
        assert!(plaintext_of("m", None, Some(&json!([1]))).is_err(), "a payload is an object");
        assert!(plaintext_of("m", Some("a"), Some(&json!({}))).is_err(), "not both");
        assert!(plaintext_of("m", None, None).is_err(), "not neither");
    }

    #[test]
    fn the_operator_controls_answer_only_this_machine_and_never_a_proxy() {
        use axum::extract::ConnectInfo;
        use axum::http::{HeaderMap, HeaderValue};
        let local = ConnectInfo("127.0.0.1:5000".parse::<std::net::SocketAddr>().unwrap());
        let local6 = ConnectInfo("[::1]:5000".parse::<std::net::SocketAddr>().unwrap());
        let remote = ConnectInfo("192.0.2.10:5000".parse::<std::net::SocketAddr>().unwrap());
        let none = HeaderMap::new();
        assert!(crate::server::local_caller(Some(&local), &none));
        assert!(crate::server::local_caller(Some(&local6), &none));
        assert!(!crate::server::local_caller(Some(&remote), &none));
        assert!(!crate::server::local_caller(None, &none), "no address known: refused");
        for h in ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip"] {
            let mut proxied = HeaderMap::new();
            proxied.insert(h, HeaderValue::from_static("203.0.113.7"));
            assert!(!crate::server::local_caller(Some(&local), &proxied), "{h}");
        }
    }

    #[tokio::test]
    async fn questions_await_one_answer_each_and_survive_a_restart() {
        let (dm, dp) = (dir("await-me"), dir("await-peer"));
        let (me, peer) = (node("me", 1, &dm), node("peer", 2, &dp));
        let peer_did = peer.did().unwrap().to_string();
        let direct = DirectMessaging::new(me.clone(), &dm, vec![peer.did_document().unwrap()], HashMap::new(), None).unwrap();
        assert!(!direct.awaited(&peer_did, false), "nothing asked: a message is a question for the agent");
        direct.awaited(&peer_did, true);
        direct.awaited(&peer_did, true);
        assert!(direct.awaited(&peer_did, false), "the first answer");
        let again = DirectMessaging::new(me, &dm, vec![peer.did_document().unwrap()], HashMap::new(), None).unwrap();
        assert!(again.awaited(&peer_did, false), "the second, after a restart");
        assert!(!again.awaited(&peer_did, false), "and then nothing more is awaited");
    }

    #[tokio::test]
    async fn an_old_reply_is_given_up() {
        let (dm, dp) = (dir("old-me"), dir("old-peer"));
        let (me, peer) = (node("me", 1, &dm), node("peer", 2, &dp));
        let peer_did = peer.did().unwrap().to_string();
        let (port, _) = server(vec![503]);
        let direct = Arc::new(DirectMessaging::new(me, &dm, vec![peer.did_document().unwrap()], HashMap::from([(peer_did.clone(), format!("http://127.0.0.1:{port}/inbox"))]), None).unwrap());
        let mut p = pending(&peer_did, "r-old");
        p.created = unix_now() - OUTBOX_MAX_AGE - 10;
        direct.outbox.lock().unwrap().push(p);
        direct.run_outbox().await;
        assert_eq!(direct.outbox_len(), 0);
    }
}