//! Message-level trust for the replicated collections.
//!
//! Couchbase Lite replication moves documents between peers, but once a peer is
//! allowed to replicate it can write *any* document in the shared collections.
//! This module closes that gap on the receiving side: every document is signed
//! by the node that wrote it, and a node only acts on documents that pass
//! [`Trust::verify`].
//!
//! A document is accepted when
//! 1. its signature is valid for the claimed author,
//! 2. the author is this node or an *enrolled* peer (the allowlist),
//! 3. the author is allowed to write *this kind* of document (below), and
//! 4. it is not an older revision than one already accepted (rollback).
//!
//! Authorization rules follow the single-writer design of the collections:
//! * `agents`  – doc id and `nodeId` must equal the author (a node publishes only its own card)
//! * `tasks`   – `owner` must equal the author (only the executing node writes task state)
//! * `inbox`   – `from` must equal the author (a node cannot forge another node's commands)
//!
//! What this does **not** do: stop an enrolled peer from overwriting or deleting
//! a document at the database level. That is detected (the bad revision is
//! ignored and logged), not prevented. A compromised enrolled node can still
//! sign lies *about itself*; revoking its key limits the damage.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anp_authz::{Claim, Revocation};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::docs::Coll;

const DOMAIN: &str = "anp-cblite/v1";
/// The one top-level field [`Trust::sign`] adds (`{author, seq, sig}`); never part
/// of the signed content. It must not start with `_`: Couchbase Lite replication
/// strips reserved underscore-prefixed top-level properties from replicated docs.
const META: &str = "trust";
const MAX_REJECTIONS: usize = 200;

/// Why a document was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    Unsigned,
    Malformed(&'static str),
    UnknownAuthor(String),
    BadSignature,
    NotAuthorized(String),
    Rollback { newest: i64, got: i64 },
    /// Biscuit mode: the author presented no token.
    NoCredential(String),
    /// Biscuit mode: the token is invalid, expired, revoked, or does not allow this.
    BadCredential(String),
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::Unsigned => write!(f, "unsigned document"),
            Reject::Malformed(m) => write!(f, "malformed: {m}"),
            Reject::UnknownAuthor(a) => write!(f, "author '{a}' is not enrolled"),
            Reject::BadSignature => write!(f, "signature does not match the content"),
            Reject::NotAuthorized(m) => write!(f, "not authorized: {m}"),
            Reject::Rollback { newest, got } => write!(f, "older revision than accepted (seq {got} < {newest})"),
            Reject::NoCredential(a) => write!(f, "author '{a}' presented no token"),
            Reject::BadCredential(m) => write!(f, "credential refused: {m}"),
        }
    }
}

/// One distinct rejection, with how often it was seen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rejection {
    pub first_at: i64,
    pub last_at: i64,
    pub count: u64,
    pub collection: String,
    pub doc_id: String,
    pub author: Option<String>,
    pub reason: String,
}

/// How long a successful token check is reused (tokens expire, so not forever).
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(30);

/// Biscuit mode: peers are trusted through tokens issued by one authority, not
/// through a list of keys.
struct BiscuitMode {
    root: anp_authz::PublicKey,
    /// This node's own token, attached to every document it writes.
    token: String,
    /// Hex revocation ids that are no longer accepted.
    revoked: Mutex<HashSet<String>>,
    /// Recent successful checks: key -> (when, revocation ids).
    cache: Mutex<HashMap<String, (Instant, Vec<String>)>>,
}

impl BiscuitMode {
    /// Is `token` valid, unexpired and does it let `author` (holding `key_b64`) write this
    /// kind of document? Returns the token's revocation ids.
    fn check(&self, token: &str, author: &str, key_b64: &str, coll: Coll, target: Option<&str>, did: Option<&str>) -> Result<Vec<String>, String> {
        let ck = format!("{token}|{author}|{key_b64}|{}|{}|{}", coll.name(), target.unwrap_or(""), did.unwrap_or(""));
        if let Some((at, ids)) = self.cache.lock().unwrap().get(&ck) {
            if at.elapsed() < TOKEN_CACHE_TTL {
                return Ok(ids.clone());
            }
        }
        let ok = anp_authz::authorize_with(
            token,
            &self.root,
            &Claim { node: author, key_b64, collection: coll.name(), target },
            did,
        )?;
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(ck, (Instant::now(), ok.revocation_ids.clone()));
        Ok(ok.revocation_ids)
    }
}

impl BiscuitMode {
    /// Cached admission check, see [`Trust::admit`].
    fn admit(&self, token: &str, node: &str, did: Option<&str>) -> Result<Vec<String>, String> {
        let ck = format!("admit|{token}|{node}|{}", did.unwrap_or(""));
        if let Some((at, ids)) = self.cache.lock().unwrap().get(&ck) {
            if at.elapsed() < TOKEN_CACHE_TTL {
                return Ok(ids.clone());
            }
        }
        let ok = anp_authz::admit_with(token, &self.root, node, did)?;
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(ck, (Instant::now(), ok.revocation_ids.clone()));
        Ok(ok.revocation_ids)
    }
}
/// How long an admission assertion stays valid. Devices' clocks differ, so this is generous.
const ADMIT_WINDOW_MS: i64 = 10 * 60 * 1000;

/// DID mode (ANP): a node *is* its `did:wba` identifier. Its signed DID document travels with every document it
/// writes, so a receiver needs no web lookup (the document is self-certifying) and no central authority.
///
/// Offline, a document proves only that the key belongs to the DID, not that the DID's *domain* vouches for it:
/// anyone can mint a document that names any host. So trust is by explicit DID (pinned out of band). Trusting a
/// whole domain needs a document actually fetched over HTTPS from that domain (not implemented yet).
struct DidMode {
    did: String,
    doc: Value,
    trusted_dids: Mutex<HashSet<String>>,
    /// Documents already verified: canonical JSON -> the verified document.
    verified: Mutex<HashMap<String, anp_did::Verified>>,
}

impl DidMode {
    /// The key bound to `did` by its self-certifying document, if the DID is the identity of `name`. Says nothing
    /// about whether anyone *trusts* this DID: that is the pin list (DID mode) or the token (with Biscuit).
    fn verify_identity(&self, name: &str, did: &str, doc: &Value) -> Result<VerifyingKey, String> {
        self.verify_doc(name, did, doc).map(|v| v.key)
    }

    /// [`DidMode::verify_identity`], returning the whole verified document.
    fn verify_doc(&self, name: &str, did: &str, doc: &Value) -> Result<anp_did::Verified, String> {
        let parsed = anp_did::WbaDid::parse(did).map_err(|e| e.to_string())?;
        // The name is part of the identity: did:wba:<host>[:<port>]:agents:<name>:e1_<fingerprint>.
        let n = parsed.path.len();
        if n < 2 || parsed.path[n - 2] != name {
            return Err(format!("{did} is not the identity of '{name}'"));
        }
        let canon = anp_did::jcs(doc).map_err(|e| e.to_string())?;
        if let Some(v) = self.verified.lock().unwrap().get(&canon) {
            return Ok(v.clone());
        }
        let v = anp_did::verify_document(doc, Some(did)).map_err(|e| e.to_string())?;
        let mut cache = self.verified.lock().unwrap();
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(canon, v.clone());
        Ok(v)
    }

    /// DID mode alone: [`DidMode::verify_identity`], and the DID must be one this node pinned.
    fn key_for(&self, name: &str, did: &str, doc: &Value) -> Result<VerifyingKey, String> {
        if !self.trusted_dids.lock().unwrap().contains(did) {
            // say "not the identity of" first when the name is wrong: it is the more useful message
            self.verify_identity(name, did, doc)?;
            return Err(format!("{did} is not a trusted identity"));
        }
        self.verify_identity(name, did, doc)
    }
}

/// `host` or `host:port`, the form a DID's authority takes in a URL.
fn authority(host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

fn admit_message(name: &str, did: &str, ts: i64) -> String {
    format!("ANP-ADMIT-v1\n{name}\n{did}\n{ts}")
}
/// A new signed prekey every this often (the older ones stay usable for opening).
const SPK_ROTATE_MS: i64 = 7 * 86_400_000;
/// How long a published bundle stays valid for senders (a peer offline for less than this can still be written to).
const SPK_VALID_MS: i64 = 30 * 86_400_000;
/// Old prekeys are deleted after this. Messages sealed to a deleted prekey can never be opened again.
const SPK_KEEP_MS: i64 = 90 * 86_400_000;

/// End-to-end encryption state (needs DID mode).
struct E2eeState {
    file: std::path::PathBuf,
    ka_secret: [u8; 32],
    ka_id: String,
    /// Signed prekeys, newest last.
    prekeys: Mutex<Vec<anp_e2ee::Prekey>>,
    /// Verified bundles of the peers we have learned from their replicated cards, by node name.
    peers: Mutex<HashMap<String, anp_e2ee::Bundle>>,
    /// One-time prekeys (P5): not yet handed out, and handed out but not yet used. A key is used once.
    opks: Mutex<Opks>,
}

/// How many one-time prekeys are kept ready.
const OPK_POOL: usize = 10;

#[derive(Default)]
struct Opks {
    available: Vec<(String, [u8; 32])>,
    issued: HashMap<String, [u8; 32]>,
}

/// Why a document could not be sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// We hold no verified keys for this peer yet (its card has not been read).
    NeedPeer(String),
    Other(String),
}

/// What happened when a document read from the store was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// Nothing was encrypted in it.
    Plain,
    /// Decrypted in place.
    Decrypted,
    /// Encrypted, but not to this node: a relay holds it and cannot read it.
    NotForUs,
    /// Not acceptable (a downgrade to plaintext, an altered ciphertext, a prekey that has been deleted).
    Refused(String),
}

pub struct Trust {
    node_id: String,
    biscuit: Option<BiscuitMode>,
    did: Option<DidMode>,
    e2ee: Option<E2eeState>,
    key: SigningKey,
    /// Enrolled peers (never contains this node).
    peers: Mutex<HashMap<String, VerifyingKey>>,
    /// Newest accepted sequence number per document, for rollback detection (in memory).
    newest: Mutex<HashMap<(Coll, String), i64>>,
    rejections: Mutex<Vec<Rejection>>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Trust {
    pub fn new(node_id: impl Into<String>, key: SigningKey) -> Trust {
        Trust {
            node_id: node_id.into(),
            biscuit: None,
            did: None,
            e2ee: None,
            key,
            peers: Mutex::new(HashMap::new()),
            newest: Mutex::new(HashMap::new()),
            rejections: Mutex::new(Vec::new()),
        }
    }

    /// Load this node's key from `<dir>/node.key`, creating it (and `node.pub`)
    /// on first use. The key file is the base64 of a 32-byte Ed25519 seed.
    pub fn load_or_create(dir: &Path, node_id: &str) -> Result<Trust, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let key_path = dir.join("node.key");
        let key = if key_path.exists() {
            let text = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
            let raw = B64.decode(text.trim()).map_err(|e| format!("{}: {e}", key_path.display()))?;
            let seed: [u8; 32] = raw.try_into().map_err(|_| format!("{}: expected a 32-byte seed", key_path.display()))?;
            SigningKey::from_bytes(&seed)
        } else {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| format!("no randomness available: {e}"))?;
            std::fs::write(&key_path, B64.encode(seed)).map_err(|e| format!("{}: {e}", key_path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            SigningKey::from_bytes(&seed)
        };
        let t = Trust::new(node_id, key);
        std::fs::write(dir.join("node.pub"), t.public_key()).map_err(|e| e.to_string())?;
        Ok(t)
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Switch to Biscuit mode: trust any peer holding a token issued by the authority
    /// whose public key is `root_pub_b64`. `own_token` (base64) is this node's token;
    /// it must name this node and its key and be valid now, or the node could not
    /// write anything its peers would accept.
    pub fn with_biscuit(mut self, root_pub_b64: &str, own_token: &str) -> Result<Trust, String> {
        let root = anp_authz::parse_public_key(root_pub_b64)?;
        let own_key = self.public_key();
        for coll in [Coll::Agents, Coll::Tasks] {
            anp_authz::authorize_with(
                own_token.trim(),
                &root,
                &Claim { node: &self.node_id, key_b64: &own_key, collection: coll.name(), target: None },
                self.did.as_ref().map(|d| d.did.as_str()),
            )
            .map_err(|e| format!("this node's token is not usable for '{}': {e}", self.node_id))?;
        }
        self.biscuit = Some(BiscuitMode {
            root,
            token: own_token.trim().to_string(),
            revoked: Mutex::new(HashSet::new()),
            cache: Mutex::new(HashMap::new()),
        });
        Ok(self)
    }

    /// `"did+biscuit"`, `"did"`, `"biscuit"` or `"allowlist"`.
    pub fn mode(&self) -> &'static str {
        if self.did.is_some() && self.biscuit.is_some() {
            return "did+biscuit";
        }
        if self.did.is_some() {
            return "did";
        }
        if self.biscuit.is_some() {
            "biscuit"
        } else {
            "allowlist"
        }
    }

    /// Switch to DID mode: this node becomes `did:wba:<host>[%3A<port>]:agents:<name>:e1_<fingerprint>` and peers
    /// are trusted by DID (see [`Trust::trust_did`]). `ad_endpoint` is advertised in the DID
    /// document as the node's `AgentDescription` service. Add [`Trust::with_biscuit`] afterwards to combine them: the
    /// authority's tokens then do the trusting (scoping, expiry, revocation) and pins are not needed.
    pub fn with_did(self, host: &str, port: Option<u16>, ad_endpoint: Option<&str>) -> Result<Trust, String> {
        self.with_did_services(host, port, ad_endpoint, vec![])
    }

    /// [`Trust::with_did`], with more entries for the DID document's `service` array (for example an `ANPMessageService`).
    pub fn with_did_services(mut self, host: &str, port: Option<u16>, ad_endpoint: Option<&str>, extra: Vec<Value>) -> Result<Trust, String> {
        if self.biscuit.is_some() {
            return Err("call with_did before with_biscuit (a DID-bound token is checked against the DID)".into());
        }
        let pk = self.key.verifying_key().to_bytes();
        let did = anp_did::did_for_key(host, port, &["agents", &self.node_id], &pk);
        // Where the agent description is served: https://<host>[:<port>]/agents/<name>/ad.json (ANP-07).
        let endpoint = ad_endpoint.map(str::to_string).unwrap_or_else(|| format!("https://{}/agents/{}/ad.json", authority(host, port), self.node_id));
        let mut services = vec![serde_json::json!({ "id": format!("{did}#ad"), "type": "AgentDescription", "serviceEndpoint": endpoint })];
        // a relative id ("#message") is a fragment of this DID
        services.extend(extra.into_iter().map(|mut s| {
            if let Some(frag) = s["id"].as_str().filter(|i| i.starts_with('#')).map(str::to_string) {
                s["id"] = Value::String(format!("{did}{frag}"));
            }
            s
        }));
        let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let ka_public = anp_e2ee::public_of(&anp_e2ee::ka_secret_from_seed(&self.key.to_bytes()));
        let device = Self::device_id(&self.node_id);
        let doc = anp_did::build_document_full(&did, &self.key, &services, &created, Some(&ka_public), Some(&device)).map_err(|e| e.to_string())?;
        self.did = Some(DidMode {
            did,
            doc,
            trusted_dids: Mutex::new(HashSet::new()),
            verified: Mutex::new(HashMap::new()),
        });
        Ok(self)
    }

    /// Is the authority's token (Biscuit) in use, alone or together with DIDs?
    pub fn has_biscuit(&self) -> bool {
        self.biscuit.is_some()
    }

    /// Does this mode check who connects (a token, or a DID assertion)?
    pub fn admits(&self) -> bool {
        self.did.is_some() || self.biscuit.is_some()
    }

    /// This node's DID, in DID mode.
    pub fn did(&self) -> Option<&str> {
        self.did.as_ref().map(|d| d.did.as_str())
    }

    /// This node's DID document (what `https://<host>/…/did.json` should serve), in DID mode.
    pub fn did_document(&self) -> Option<Value> {
        self.did.as_ref().map(|d| d.doc.clone())
    }

    /// This node's ANP-07 agent description, built from its A2A agent card and signed with its DID key. The proof
    /// is bound to the DID's host (`domain`) with a fresh `challenge`. Only in DID mode.
    pub fn agent_description(&self, card: &Value) -> Result<Value, String> {
        let d = self.did.as_ref().ok_or("not in DID mode")?;
        let parsed = anp_did::WbaDid::parse(&d.did).map_err(|e| e.to_string())?;
        let auth = authority(&parsed.host, parsed.port);
        let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut ad = anp_ad::from_a2a_card(
            card,
            &d.did,
            &format!("https://{auth}/agents/{}/ad.json", self.node_id),
            &format!("https://{auth}/.well-known/agent-card.json"),
            &created,
        );
        // the structured interface the SDKs read their methods from (served by `openrpc_document`)
        if let Some(i) = ad["interfaces"].as_array_mut() {
            i.push(serde_json::json!({ "type": "StructuredInterface", "protocol": "openrpc", "url": format!("https://{auth}/agents/{}/openrpc.json", self.node_id), "description": "JSON-RPC methods of this agent (OpenRPC)" }));
        }
        let challenge = uuid::Uuid::new_v4().to_string();
        anp_ad::sign(&mut ad, &self.key, &d.did, &created, Some((&auth, &challenge))).map_err(|e| e.to_string())?;
        Ok(ad)
    }

    /// The OpenRPC description of this node's JSON-RPC interface, calling `https://<did host>/`.
    pub fn openrpc_document(&self, title: &str, version: &str) -> Result<Value, String> {
        let d = self.did.as_ref().ok_or("not in DID mode")?;
        let parsed = anp_did::WbaDid::parse(&d.did).map_err(|e| e.to_string())?;
        Ok(anp_ad::openrpc::a2a_interface(title, version, &format!("https://{}/", authority(&parsed.host, parsed.port))))
    }

    /// Turn on end-to-end encryption: the payload fields of tasks and commands are sealed to the node they are for
    /// (and to this node), so a peer that only relays them cannot read them. Needs DID mode (the keys are published in
    /// the DID document). The signed prekeys live in `<dir>/e2ee-prekeys.json`, next to the node's key.
    pub fn with_e2ee(mut self, dir: &Path) -> Result<Trust, String> {
        let d = self.did.as_ref().ok_or("end-to-end encryption needs DID mode (--did-host)")?;
        let ka_secret = anp_e2ee::ka_secret_from_seed(&self.key.to_bytes());
        let ka_id = anp_did::key_agreement_id(&d.did);
        let file = dir.join("e2ee-prekeys.json");
        let mut prekeys: Vec<anp_e2ee::Prekey> = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&file) {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
            for e in v.as_array().ok_or_else(|| format!("{}: expected an array", file.display()))? {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(e["secret"].as_str().unwrap_or("")).map_err(|_| format!("{}: bad prekey", file.display()))?;
                let secret: [u8; 32] = raw.try_into().map_err(|_| format!("{}: bad prekey length", file.display()))?;
                prekeys.push(anp_e2ee::Prekey {
                    id: e["id"].as_str().unwrap_or("").to_string(),
                    public: anp_e2ee::public_of(&secret),
                    secret,
                    created_ms: e["createdMs"].as_i64().unwrap_or(0),
                });
            }
        }
        self.e2ee = Some(E2eeState { file, ka_secret, ka_id, prekeys: Mutex::new(prekeys), peers: Mutex::new(HashMap::new()), opks: Mutex::new(Opks::default()) });
        self.rotate_prekeys()?; // makes sure there is a current one and saves
        self.load_opks(dir)?;
        Ok(self)
    }

    pub fn e2ee_enabled(&self) -> bool {
        self.e2ee.is_some()
    }

    /// Add a new signed prekey if the newest is old (or there is none), drop the ones past their keep time, save.
    fn rotate_prekeys(&self) -> Result<(), String> {
        let e = self.e2ee.as_ref().ok_or("end-to-end encryption is off")?;
        let now = now_ms();
        let mut keys = e.prekeys.lock().unwrap();
        let mut changed = false;
        if keys.last().map_or(true, |k| now - k.created_ms >= SPK_ROTATE_MS) {
            keys.push(anp_e2ee::new_prekey(now));
            changed = true;
        }
        let newest = keys.last().map(|k| k.id.clone());
        let before = keys.len();
        keys.retain(|k| now - k.created_ms < SPK_KEEP_MS || Some(&k.id) == newest.as_ref());
        changed |= keys.len() != before;
        if changed {
            let arr: Vec<Value> = keys
                .iter()
                .map(|k| serde_json::json!({ "id": k.id, "secret": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k.secret), "createdMs": k.created_ms }))
                .collect();
            let tmp = e.file.with_extension("tmp");
            std::fs::write(&tmp, Value::Array(arr).to_string()).map_err(|er| format!("{}: {er}", tmp.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&tmp, &e.file).map_err(|er| format!("{}: {er}", e.file.display()))?;
        }
        Ok(())
    }

    /// The id of the one device a node is, in its DID document's `deviceManifest` and in its prekey bundle.
    fn device_id(node_id: &str) -> String {
        format!("dev-{node_id}")
    }

    fn iso(ms: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    /// This node's current prekey bundle (signed with its DID key), to publish with its agent card. Rotates the prekey
    /// when it is due. `None` without end-to-end encryption.
    pub fn e2ee_bundle(&self) -> Option<Value> {
        let e = self.e2ee.as_ref()?;
        let d = self.did.as_ref()?;
        if let Err(er) = self.rotate_prekeys() {
            log::warn!("prekey rotation failed: {er}");
        }
        let spk = e.prekeys.lock().unwrap().last()?.clone();
        anp_e2ee::make_bundle(&d.did, &Self::device_id(&self.node_id), &e.ka_id, &spk, &Self::iso(now_ms()), &Self::iso(spk.created_ms + SPK_VALID_MS), &self.key).ok()
    }

    /// Learn a peer's encryption keys from its replicated agent card (a document that already passed
    /// [`Trust::verify`]): its DID document, which is self-certifying, and the prekey bundle signed by that DID.
    pub fn learn_peer(&self, card: &Value) {
        let (Some(e), Some(d)) = (&self.e2ee, &self.did) else { return };
        let Some(name) = card["nodeId"].as_str() else { return };
        if name == self.node_id {
            return;
        }
        let meta = &card[META];
        let (Some(did), Some(doc), Some(bundle)) = (meta["did"].as_str(), meta.get("didDoc"), card.get("e2eeBundle")) else { return };
        let outcome = d.verify_doc(name, did, doc).map_err(|er| er).and_then(|v| anp_e2ee::parse_bundle(bundle, &v, &Self::iso(now_ms())).map_err(|er| er.to_string()));
        match outcome {
            Ok(b) => {
                e.peers.lock().unwrap().insert(name.to_string(), b);
            }
            Err(er) => {
                log::debug!("not using {name}'s encryption keys: {er}");
                e.peers.lock().unwrap().remove(name);
            }
        }
    }

    /// Which field of a document is encrypted, and for whom besides the author.
    fn e2ee_plan(coll: Coll, body: &Value) -> Option<(&'static str, Option<String>)> {
        match coll {
            Coll::Inbox => Some(("message", body["to"].as_str().map(str::to_string))),
            Coll::Tasks => Some(("task", body["origin"].as_str().map(str::to_string))),
            _ => None,
        }
    }

    /// Encrypt the payload field of `body` (before it is signed) to the node it is for and to this node. A no-op
    /// without end-to-end encryption and for documents that carry no payload.
    pub fn seal_doc(&self, coll: Coll, id: &str, body: &mut Value) -> Result<(), SealError> {
        let (Some(e), Some(d)) = (&self.e2ee, &self.did) else { return Ok(()) };
        let Some((field, other)) = Self::e2ee_plan(coll, body) else { return Ok(()) };
        if body.get(field).map_or(true, Value::is_null) {
            return Ok(());
        }
        let mut names: Vec<String> = Vec::new();
        for n in other.into_iter().chain(std::iter::once(self.node_id.clone())) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let spk = e.prekeys.lock().unwrap().last().cloned().ok_or_else(|| SealError::Other("no signed prekey".into()))?;
        // the field is part of the message id, so the associated data binds a ciphertext to one field of one document
        let message_id = format!("{}/{id}#{field}", coll.name());
        let my_device = Self::device_id(&self.node_id);
        let payload = body[field].clone();
        let mut recipients = Vec::new();
        for name in &names {
            let bundle = if *name == self.node_id {
                anp_e2ee::Bundle {
                    bundle_id: format!("bundle-{}", spk.id),
                    owner_did: d.did.clone(),
                    device_id: my_device.clone(),
                    ka_id: e.ka_id.clone(),
                    ka_public: anp_e2ee::public_of(&e.ka_secret),
                    spk_id: spk.id.clone(),
                    spk_public: spk.public,
                    expires_at: String::new(),
                }
            } else {
                match e.peers.lock().unwrap().get(name) {
                    // a bundle can run out while we hold it: do not seal to an expired prekey
                    Some(b) if b.expires_at > Self::iso(now_ms()) => b.clone(),
                    _ => return Err(SealError::NeedPeer(name.clone())),
                }
            };
            let ctx = anp_e2ee::Ctx {
                message_id: &message_id,
                sender_did: &d.did,
                sender_device_id: &my_device,
                sender_ka_id: &e.ka_id,
                recipient_did: &bundle.owner_did,
                recipient_device_id: &bundle.device_id,
            };
            let init = anp_e2ee::seal(&payload, &ctx, &e.ka_secret, &bundle).map_err(|er| SealError::Other(er.to_string()))?;
            recipients.push(serde_json::json!({ "did": bundle.owner_did, "init": init }));
        }
        let m = body.as_object_mut().ok_or_else(|| SealError::Other("not an object".into()))?;
        m.remove(field);
        m.insert("enc".into(), serde_json::json!({ "v": 1, "field": field, "suite": anp_e2ee::SUITE, "recipients": recipients }));
        Ok(())
    }

    /// Decrypt the payload field of a document that passed [`Trust::verify`], in place. A refusal is also recorded
    /// (see [`Trust::rejections`]).
    pub fn open_doc(&self, coll: Coll, id: &str, body: &mut Value) -> Opened {
        let author = body[META]["author"].as_str().map(str::to_string);
        let r = self.open_inner(coll, id, body);
        if let Opened::Refused(why) = &r {
            self.note_raw(coll.name(), id, author, why.clone());
        }
        r
    }

    fn open_inner(&self, coll: Coll, id: &str, body: &mut Value) -> Opened {
        let (Some(e), Some(d)) = (&self.e2ee, &self.did) else { return Opened::Plain };
        let Some((field, _)) = Self::e2ee_plan(coll, body) else { return Opened::Plain };
        let author = body[META]["author"].as_str().unwrap_or("").to_string();
        let Some(enc) = body.get("enc").cloned() else {
            // Plaintext where the payload belongs. Our own earlier documents are fine; from anyone else it would be a
            // silent downgrade, which a peer (or a relay that cannot forge a signature) must not get away with.
            return if author == self.node_id || body.get(field).map_or(true, Value::is_null) {
                Opened::Plain
            } else {
                Opened::Refused(format!("'{author}' sent the {field} in plaintext (encryption is required)"))
            };
        };
        if enc["field"].as_str() != Some(field) || body.get(field).is_some() {
            return Opened::Refused("malformed encrypted document".into());
        }
        let Some(mine) = enc["recipients"].as_array().and_then(|r| r.iter().find(|x| x["did"].as_str() == Some(d.did.as_str()))) else {
            return Opened::NotForUs;
        };
        // the sender's key-agreement key: ours if we wrote it, else from its verified DID document
        let (sender_did, sender_device, sender_ka_id, sender_ka) = if author == self.node_id {
            (d.did.clone(), Self::device_id(&self.node_id), e.ka_id.clone(), anp_e2ee::public_of(&e.ka_secret))
        } else {
            let meta = &body[META];
            let (Some(did), Some(doc)) = (meta["did"].as_str(), meta.get("didDoc")) else {
                return Opened::Refused("no DID document with the encrypted document".into());
            };
            match d.verify_doc(&author, did, doc).ok().and_then(|v| {
                let (id, k) = v.key_agreement()?;
                let device = v.device_for_key_agreement(&id)?;
                Some((v.did_string.clone(), device, id, k))
            }) {
                Some(x) => x,
                None => return Opened::Refused(format!("'{author}' publishes no key-agreement key or device manifest")),
            }
        };
        let init = &mine["init"];
        let Some(spk_id) = anp_e2ee::init_spk_id(init) else { return Opened::Refused("no prekey id".into()) };
        let Some(spk) = e.prekeys.lock().unwrap().iter().find(|k| k.id == spk_id).cloned() else {
            return Opened::Refused(format!("the signed prekey {spk_id} has been deleted: this message can no longer be opened"));
        };
        let message_id = format!("{}/{id}#{field}", coll.name());
        let my_device = Self::device_id(&self.node_id);
        let ctx = anp_e2ee::Ctx {
            message_id: &message_id,
            sender_did: &sender_did,
            sender_device_id: &sender_device,
            sender_ka_id: &sender_ka_id,
            recipient_did: &d.did,
            recipient_device_id: &my_device,
        };
        match anp_e2ee::open(init, &ctx, &e.ka_secret, &spk.secret, &sender_ka) {
            Ok(payload) => {
                if let Some(m) = body.as_object_mut() {
                    m.remove("enc");
                    m.insert(field.into(), payload);
                }
                Opened::Decrypted
            }
            Err(er) => Opened::Refused(er.to_string()),
        }
    }
    // ── P5 (ANP-09) key material ────────────────────────────────────────────────────────────────────────

    fn opk_file(&self) -> Option<std::path::PathBuf> {
        self.e2ee.as_ref().map(|e| e.file.with_file_name("e2ee-opks.json"))
    }

    /// Read the one-time prekey pool from disk and top it up.
    fn load_opks(&self, _dir: &Path) -> Result<(), String> {
        let (Some(e), Some(file)) = (&self.e2ee, self.opk_file()) else { return Ok(()) };
        let mut pool = Opks::default();
        if let Ok(text) = std::fs::read_to_string(&file) {
            let v: Value = serde_json::from_str(&text).map_err(|er| format!("{}: {er}", file.display()))?;
            let dec = |x: &Value| -> Result<(String, [u8; 32]), String> {
                let id = x["id"].as_str().ok_or("opk without id")?.to_string();
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x["secret"].as_str().unwrap_or("")).map_err(|_| "bad opk")?;
                Ok((id, raw.try_into().map_err(|_| "bad opk length")?))
            };
            for x in v["available"].as_array().into_iter().flatten() {
                pool.available.push(dec(x)?);
            }
            for x in v["issued"].as_array().into_iter().flatten() {
                let (id, s) = dec(x)?;
                pool.issued.insert(id, s);
            }
        }
        *e.opks.lock().unwrap() = pool;
        self.top_up_opks()
    }

    fn save_opks(&self, pool: &Opks) -> Result<(), String> {
        let Some(file) = self.opk_file() else { return Ok(()) };
        let enc = |id: &String, s: &[u8; 32]| serde_json::json!({ "id": id, "secret": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s) });
        let v = serde_json::json!({
            "available": pool.available.iter().map(|(i, s)| enc(i, s)).collect::<Vec<_>>(),
            "issued": pool.issued.iter().map(|(i, s)| enc(i, s)).collect::<Vec<_>>(),
        });
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, v.to_string()).map_err(|er| format!("{}: {er}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &file).map_err(|er| format!("{}: {er}", file.display()))
    }

    fn top_up_opks(&self) -> Result<(), String> {
        let e = self.e2ee.as_ref().ok_or("end-to-end encryption is off")?;
        let mut pool = e.opks.lock().unwrap();
        let before = pool.available.len();
        while pool.available.len() < OPK_POOL {
            let k = anp_e2ee::new_prekey(now_ms());
            pool.available.push((format!("opk-{}", k.id), k.secret));
        }
        if pool.available.len() != before {
            self.save_opks(&pool)?;
        }
        Ok(())
    }

    /// Who we are for P5: DID, device id, key-agreement key id and secret. `None` without end-to-end encryption.
    pub fn direct_identity(&self) -> Option<(String, String, String, [u8; 32])> {
        let (e, d) = (self.e2ee.as_ref()?, self.did.as_ref()?);
        Some((d.did.clone(), Self::device_id(&self.node_id), e.ka_id.clone(), e.ka_secret))
    }

    /// The signed prekey a bundle id names, if we still hold it: its id and secret.
    pub fn direct_prekey_for_bundle(&self, bundle_id: &str) -> Option<(String, [u8; 32])> {
        let e = self.e2ee.as_ref()?;
        e.prekeys.lock().unwrap().iter().find(|k| format!("bundle-{}", k.id) == bundle_id).map(|k| (k.id.clone(), k.secret))
    }

    /// Hand out one one-time prekey (and never again): `{key_id, public_key_b64u}`. `None` when the pool is empty.
    pub fn direct_issue_one_time_prekey(&self) -> Option<Value> {
        let e = self.e2ee.as_ref()?;
        let issued = {
            let mut pool = e.opks.lock().unwrap();
            let (id, secret) = pool.available.pop()?;
            pool.issued.insert(id.clone(), secret);
            if let Err(er) = self.save_opks(&pool) {
                log::warn!("could not save the one-time prekeys: {er}");
            }
            (id, secret)
        };
        let _ = self.top_up_opks();
        Some(serde_json::json!({ "key_id": issued.0, "public_key_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(anp_e2ee::public_of(&issued.1)) }))
    }

    /// Use up a one-time prekey that was handed out: its secret, once. A second call for the same id returns `None`.
    pub fn direct_consume_one_time_prekey(&self, id: &str) -> Option<[u8; 32]> {
        let e = self.e2ee.as_ref()?;
        let mut pool = e.opks.lock().unwrap();
        let secret = pool.issued.remove(id)?;
        if let Err(er) = self.save_opks(&pool) {
            log::warn!("could not save the one-time prekeys: {er}");
        }
        Some(secret)
    }

    /// ANP-02 headers for a request this node makes, signed with its DID key.
    pub fn sign_http(&self, method: &str, url: &str, body: &[u8], nonce: &str) -> Result<Vec<(String, String)>, String> {
        let d = self.did.as_ref().ok_or("not in DID mode")?;
        let parsed = anp_did::WbaDid::parse(&d.did).map_err(|e| e.to_string())?;
        let fp = parsed.e1().ok_or("no e1 fingerprint")?;
        anp_httpauth::sign(&self.key, &format!("{}#{fp}", d.did), method, url, body, now_ms() / 1000, nonce).map_err(|e| e.to_string())
    }
    /// Trust exactly this DID.
    pub fn trust_did(&self, did: &str) -> Result<(), String> {
        let d = self.did.as_ref().ok_or("not in DID mode")?;
        anp_did::WbaDid::parse(did).map_err(|e| e.to_string())?;
        d.trusted_dids.lock().unwrap().insert(did.to_string());
        Ok(())
    }

    /// Refuse tokens with this revocation id (hex, see `anp-admin inspect`).
    pub fn revoke_token(&self, revocation_id: &str) {
        if let Some(b) = &self.biscuit {
            b.revoked.lock().unwrap().insert(revocation_id.trim().to_lowercase());
        }
    }

    /// Load a deny-list: one hex revocation id per line, `#` comments allowed.
    pub fn load_revocations(&self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut n = 0;
        for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty()) {
            self.revoke_token(line);
            n += 1;
        }
        Ok(n)
    }

    /// This node's public key, base64. Hand it to the peers that should trust it.
    pub fn public_key(&self) -> String {
        B64.encode(self.key.verifying_key().to_bytes())
    }

    /// Trust `node_id` with the given base64 public key. Replaces an earlier key.
    pub fn enroll(&self, node_id: &str, public_key_b64: &str) -> Result<(), String> {
        let raw = B64.decode(public_key_b64.trim()).map_err(|e| format!("key for '{node_id}': {e}"))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| format!("key for '{node_id}': expected 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|e| format!("key for '{node_id}': {e}"))?;
        if node_id == self.node_id {
            return if vk == self.key.verifying_key() {
                Ok(())
            } else {
                Err(format!("trust list has a different key for this node ('{node_id}')"))
            };
        }
        self.peers.lock().unwrap().insert(node_id.to_string(), vk);
        Ok(())
    }

    /// Stop trusting a node. Documents it already wrote stay in the database but
    /// are ignored from now on.
    pub fn revoke(&self, node_id: &str) {
        self.peers.lock().unwrap().remove(node_id);
    }

    /// Load `{"nodes": {"alice": "<base64 key>", ...}}` (or the bare map).
    pub fn load_trust_file(&self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let nodes = v.get("nodes").unwrap_or(&v).as_object().ok_or_else(|| format!("{}: expected an object", path.display()))?;
        for (id, key) in nodes {
            let key = key.as_str().ok_or_else(|| format!("{}: key for '{id}' must be a string", path.display()))?;
            self.enroll(id, key)?;
        }
        Ok(nodes.len())
    }

    pub fn enrolled(&self) -> Vec<String> {
        let mut v: Vec<String> = self.peers.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    pub fn rejections(&self) -> Vec<Rejection> {
        self.rejections.lock().unwrap().clone()
    }

    /// Sign `body` (which must be a JSON object) as this node, in place.
    pub fn sign(&self, coll: Coll, id: &str, body: &mut Value) {
        self.sign_next(coll, id, body, None);
    }

    /// Sign `body` as the next revision of a document whose stored revision carried sequence
    /// number `prev_seq`. The sequence is `max(prev_seq + 1, now)`: it always rises, even if
    /// this node's clock was set back, and for a brand-new document it starts from the clock.
    pub fn sign_next(&self, coll: Coll, id: &str, body: &mut Value, prev_seq: Option<i64>) {
        let seq = prev_seq.map_or_else(now_ms, |p| (p + 1).max(now_ms()));
        self.sign_at(coll, id, body, seq);
    }

    /// The sequence number a stored, signed document carries.
    pub fn seq_of(doc: &Value) -> Option<i64> {
        doc.pointer("/trust/seq").and_then(Value::as_i64)
    }
    #[doc(hidden)] // for tests and tooling that need a specific sequence number
    pub fn sign_at(&self, coll: Coll, id: &str, body: &mut Value, ts: i64) {
        if let Value::Object(m) = body {
            m.remove(META);
        } else {
            return; // left unsigned; verification will reject it
        }
        let sig = self.key.sign(message(coll, id, &self.node_id, ts, &canonical_str(body)).as_bytes());
        if let Value::Object(m) = body {
            let mut meta = serde_json::json!({ "author": self.node_id, "seq": ts, "sig": B64.encode(sig.to_bytes()) });
            if let Some(b) = &self.biscuit {
                // The credential travels with the document: receivers need nothing but the
                // authority's public key to check it.
                meta["token"] = Value::String(b.token.clone());
                meta["key"] = Value::String(self.public_key());
            }
            if let Some(d) = &self.did {
                meta["did"] = Value::String(d.did.clone());
                meta["didDoc"] = d.doc.clone();
            }
            m.insert(META.into(), meta);
        }
    }

    /// Check a document read from the database. Returns the author on success;
    /// on failure the reason is also recorded (see [`Trust::rejections`]).
    pub fn verify(&self, coll: Coll, id: &str, body: &Value) -> Result<String, Reject> {
        let r = self.verify_inner(coll, id, body);
        if let Err(e) = &r {
            let author = body.pointer("/trust/author").and_then(Value::as_str).map(str::to_owned);
            self.note(coll, id, author, e);
        }
        r
    }

    fn verify_inner(&self, coll: Coll, id: &str, body: &Value) -> Result<String, Reject> {
        if coll == Coll::Revocations {
            // Not a node's document: its proof is the authority's signature.
            return self.verify_revocation_doc(id, body).map(|_| "authority".to_string());
        }
        let m = body.as_object().ok_or(Reject::Malformed("not an object"))?;
        let meta = m.get(META).ok_or(Reject::Unsigned)?;
        let sig_b64 = meta.get("sig").and_then(Value::as_str).ok_or(Reject::Malformed("missing signature"))?;
        let author = meta.get("author").and_then(Value::as_str).ok_or(Reject::Malformed("missing author"))?;
        let ts = meta.get("seq").and_then(Value::as_i64).ok_or(Reject::Malformed("missing seq"))?;

        let mut content = m.clone();
        content.remove(META);
        let content = Value::Object(content);

        let key = self.resolve_key(coll, author, meta, &content)?;
        let raw = B64.decode(sig_b64).map_err(|_| Reject::Malformed("signature encoding"))?;
        let arr: [u8; 64] = raw.try_into().map_err(|_| Reject::Malformed("signature length"))?;
        let sig = Signature::from_bytes(&arr);

        key.verify_strict(message(coll, id, author, ts, &canonical_str(&content)).as_bytes(), &sig)
            .map_err(|_| Reject::BadSignature)?;

        authorize(coll, id, &content, author)?;

        let mut newest = self.newest.lock().unwrap();
        let seen = newest.entry((coll, id.to_string())).or_insert(i64::MIN);
        if ts < *seen {
            return Err(Reject::Rollback { newest: *seen, got: ts });
        }
        *seen = ts;
        Ok(author.to_string())
    }

    /// Check a revocation document and, if it is genuine, start refusing the token it names.
    fn verify_revocation_doc(&self, id: &str, body: &Value) -> Result<(), Reject> {
        let Some(b) = &self.biscuit else {
            return Err(Reject::NotAuthorized("revocations need Biscuit mode".into()));
        };
        let rev = Revocation::from_json(body).map_err(Reject::BadCredential)?;
        if !rev.revoked.eq_ignore_ascii_case(id) {
            return Err(Reject::NotAuthorized("revocation id does not match its document id".into()));
        }
        anp_authz::verify_revocation(&rev, &b.root).map_err(Reject::BadCredential)?;
        b.revoked.lock().unwrap().insert(rev.revoked.to_lowercase());
        Ok(())
    }

    /// Verify a revocation received out of band (the HTTP endpoint) and apply it.
    pub fn accept_revocation(&self, rev: &Revocation) -> Result<(), String> {
        let b = self.biscuit.as_ref().ok_or("revocations need Biscuit mode")?;
        anp_authz::verify_revocation(rev, &b.root)?;
        b.revoked.lock().unwrap().insert(rev.revoked.to_lowercase());
        Ok(())
    }

    /// Hex ids of the tokens this node refuses.
    pub fn revoked_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.biscuit.as_ref().map(|b| b.revoked.lock().unwrap().iter().cloned().collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// Biscuit mode: may a peer that presents `password` (its token) as `user` (its node id)
    /// open a connection? Always `false` outside Biscuit mode (there is nothing to check).
    pub fn admit(&self, user: &str, password: &str) -> bool {
        if let Some(d) = &self.did {
            return match self.admit_did(d, user, password) {
                Ok(()) => true,
                Err(e) => {
                    self.note_raw("connection", user, None, format!("connection refused: {e}"));
                    false
                }
            };
        }
        let Some(b) = &self.biscuit else { return false };
        let result = b.admit(password.trim(), user, None).and_then(|ids| {
            let revoked = b.revoked.lock().unwrap();
            match ids.iter().find(|i| revoked.contains(*i)) {
                Some(id) => Err(format!("token revoked ({id})")),
                None => Ok(()),
            }
        });
        match result {
            Ok(()) => true,
            Err(e) => {
                self.note_raw("connection", user, None, format!("connection refused: {e}"));
                false
            }
        }
    }

    /// Biscuit mode: the `(node id, token)` this node presents when it dials a peer.
    pub fn credential(&self) -> Option<(String, String)> {
        if let Some(d) = &self.did {
            // A fresh assertion each time we dial: our DID and document, signed over our name and the time.
            let ts = now_ms();
            let sig = self.key.sign(admit_message(&self.node_id, &d.did, ts).as_bytes());
            let mut body = serde_json::json!({ "did": d.did, "doc": d.doc, "ts": ts, "sig": B64.encode(sig.to_bytes()) });
            if let Some(b) = &self.biscuit {
                body["token"] = Value::String(b.token.clone());
            }
            return Some((self.node_id.clone(), B64.encode(body.to_string())));
        }
        self.biscuit.as_ref().map(|b| (self.node_id.clone(), b.token.clone()))
    }
    /// DID mode: does `password` prove that `user` holds the key behind a trusted DID?
    fn admit_did(&self, d: &DidMode, user: &str, password: &str) -> Result<(), String> {
        let raw = B64.decode(password.trim()).map_err(|_| "not an assertion")?;
        let a: Value = serde_json::from_slice(&raw).map_err(|_| "not an assertion")?;
        let (Some(did), Some(ts), Some(sig_b64)) = (a["did"].as_str(), a["ts"].as_i64(), a["sig"].as_str()) else {
            return Err("incomplete assertion".into());
        };
        if (now_ms() - ts).abs() > ADMIT_WINDOW_MS {
            return Err("assertion is stale (check the clocks)".into());
        }
        // With Biscuit the authority's token is the trust anchor (below); alone, the pin list is.
        let key = if self.biscuit.is_some() { d.verify_identity(user, did, &a["doc"])? } else { d.key_for(user, did, &a["doc"])? };
        let sig: [u8; 64] = B64.decode(sig_b64).ok().and_then(|r| r.try_into().ok()).ok_or("bad signature encoding")?;
        key.verify_strict(admit_message(user, did, ts).as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| "signature does not verify".to_string())?;
        if let Some(b) = &self.biscuit {
            let token = a["token"].as_str().ok_or("no token with the assertion")?;
            let ids = b.admit(token.trim(), user, Some(did))?;
            if let Some(id) = ids.iter().find(|i| b.revoked.lock().unwrap().contains(*i)) {
                return Err(format!("token revoked ({id})"));
            }
        }
        Ok(())
    }

    /// The key to verify `author`'s signature with: our own, the enrolled key
    /// (allowlist mode), or the key named by a valid token (Biscuit mode).
    fn resolve_key(&self, coll: Coll, author: &str, meta: &Value, content: &Value) -> Result<VerifyingKey, Reject> {
        if author == self.node_id {
            return Ok(self.key.verifying_key());
        }
        if let Some(d) = &self.did {
            let did = meta.get("did").and_then(Value::as_str).ok_or_else(|| Reject::NoCredential(author.to_string()))?;
            let doc = meta.get("didDoc").ok_or_else(|| Reject::NoCredential(author.to_string()))?;
            let Some(b) = &self.biscuit else {
                return d.key_for(author, did, doc).map_err(Reject::BadCredential);
            };
            // DID + Biscuit: the key comes from the self-certifying DID document, and the authority's token must
            // vouch for exactly that DID and key, and allow this kind of document.
            let key = d.verify_identity(author, did, doc).map_err(Reject::BadCredential)?;
            let key_b64 = B64.encode(key.to_bytes());
            let token = meta.get("token").and_then(Value::as_str).ok_or_else(|| Reject::NoCredential(author.to_string()))?;
            let target = if coll == Coll::Inbox { content.get("to").and_then(Value::as_str) } else { None };
            let ids = b.check(token, author, &key_b64, coll, target, Some(did)).map_err(Reject::BadCredential)?;
            let revoked = b.revoked.lock().unwrap();
            if let Some(id) = ids.iter().find(|i| revoked.contains(*i)) {
                return Err(Reject::BadCredential(format!("token revoked ({id})")));
            }
            return Ok(key);
        }
        let Some(b) = &self.biscuit else {
            return self.key_for(author).ok_or_else(|| Reject::UnknownAuthor(author.to_string()));
        };
        let token = meta.get("token").and_then(Value::as_str).ok_or_else(|| Reject::NoCredential(author.to_string()))?;
        let key_b64 = meta.get("key").and_then(Value::as_str).ok_or(Reject::Malformed("missing key"))?;
        let target = if coll == Coll::Inbox { content.get("to").and_then(Value::as_str) } else { None };
        let ids = b.check(token, author, key_b64, coll, target, None).map_err(Reject::BadCredential)?;
        {
            let revoked = b.revoked.lock().unwrap();
            if let Some(id) = ids.iter().find(|i| revoked.contains(*i)) {
                return Err(Reject::BadCredential(format!("token revoked ({id})")));
            }
        }
        let raw = B64.decode(key_b64).map_err(|_| Reject::Malformed("key encoding"))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| Reject::Malformed("key length"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| Reject::Malformed("key"))
    }

    fn key_for(&self, author: &str) -> Option<VerifyingKey> {
        if author == self.node_id {
            Some(self.key.verifying_key())
        } else {
            self.peers.lock().unwrap().get(author).copied()
        }
    }

    fn note(&self, coll: Coll, id: &str, author: Option<String>, why: &Reject) {
        self.note_reason(coll, id, author, why.to_string());
    }
    /// Record that a tampered or deleted document was answered from, and rewritten as,
    /// the last verified copy.
    pub fn note_restored(&self, coll: Coll, id: &str, deleted: bool) {
        let reason = if deleted {
            "deleted by a peer; restored the last verified copy"
        } else {
            "overwritten by an invalid revision; restored the last verified copy"
        };
        self.note_reason(coll, id, None, reason.to_string());
    }

    fn note_reason(&self, coll: Coll, id: &str, author: Option<String>, reason: String) {
        self.note_raw(coll.name(), id, author, reason);
    }

    fn note_raw(&self, collection: &str, id: &str, author: Option<String>, reason: String) {
        let now = now_ms();
        let mut list = self.rejections.lock().unwrap();
        if let Some(r) = list
            .iter_mut()
            .find(|r| r.collection == collection && r.doc_id == id && r.reason == reason && r.author == author)
        {
            r.count += 1;
            r.last_at = now;
            return;
        }
        log::warn!("rejected {collection}/{id}{}: {reason}", author.as_deref().map(|a| format!(" (author {a})")).unwrap_or_default());
        if list.len() >= MAX_REJECTIONS {
            list.remove(0);
        }
        list.push(Rejection {
            first_at: now,
            last_at: now,
            count: 1,
            collection: collection.into(),
            doc_id: id.into(),
            author,
            reason,
        });
    }
}

/// May `author` write this kind of document?
fn authorize(coll: Coll, id: &str, content: &Value, author: &str) -> Result<(), Reject> {
    let field = |name: &str| content.get(name).and_then(Value::as_str);
    let ok = |cond: bool, msg: String| if cond { Ok(()) } else { Err(Reject::NotAuthorized(msg)) };
    match coll {
        Coll::Agents => ok(
            id == author && field("nodeId") == Some(author),
            format!("'{author}' may only publish its own agent card, not '{id}'"),
        ),
        Coll::Tasks => ok(
            field("owner") == Some(author),
            format!("'{author}' is not the owner of this task ({:?})", field("owner")),
        ),
        Coll::Revocations => Ok(()), // checked by `verify_revocation_doc` before this is reached
        Coll::Inbox => ok(
            field("from") == Some(author),
            format!("'{author}' cannot issue a command from '{}'", field("from").unwrap_or("?")),
        ),
    }
}

/// The exact bytes that are signed. Binds the collection and id (so a document
/// cannot be copied to another id) and the author and timestamp.
fn message(coll: Coll, id: &str, author: &str, ts: i64, canon: &str) -> String {
    format!("{DOMAIN}\n{}\n{id}\n{author}\n{ts}\n{canon}", coll.name())
}

fn canonical_str(v: &Value) -> String {
    let mut s = String::new();
    canonical(v, &mut s);
    s
}

/// Deterministic JSON: object keys sorted, no whitespace, and whole-number
/// floats written as integers (Fleece may store `1.0` as `1`).
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                if let Some(f) = n.as_f64() {
                    if f.fract() == 0.0 && f.abs() < 9.0e15 {
                        out.push_str(&(f as i64).to_string());
                        return;
                    }
                }
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(name: &str, seed: u8) -> Trust {
        Trust::new(name, SigningKey::from_bytes(&[seed; 32]))
    }

    /// bob trusts alice (and only alice).
    fn pair() -> (Trust, Trust) {
        let (alice, bob) = (node("alice", 1), node("bob", 2));
        bob.enroll("alice", &alice.public_key()).unwrap();
        alice.enroll("bob", &bob.public_key()).unwrap();
        (alice, bob)
    }

    fn command(from: &str, to: &str) -> Value {
        json!({ "kind": "send", "taskId": "t1", "contextId": "c1", "to": to, "from": from, "ts": 5 })
    }

    #[test]
    fn accepts_a_signed_document_from_an_enrolled_peer() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Ok("alice".into()));
    }

    #[test]
    fn accepts_own_documents() {
        let (alice, _) = pair();
        let mut d = json!({ "nodeId": "alice", "ts": 1 });
        alice.sign(Coll::Agents, "alice", &mut d);
        assert_eq!(alice.verify(Coll::Agents, "alice", &d), Ok("alice".into()));
    }

    #[test]
    fn rejects_unsigned_documents() {
        let (_, bob) = pair();
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &command("alice", "bob")), Err(Reject::Unsigned));
    }

    #[test]
    fn rejects_a_forged_document_from_an_unenrolled_node() {
        let (_, bob) = pair();
        let mallory = node("mallory", 9);
        let mut d = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::UnknownAuthor("mallory".into())));
    }

    #[test]
    fn rejects_an_impersonator_signing_as_alice_with_their_own_key() {
        let (_, bob) = pair();
        // mallory claims to be alice but only has her own key
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut d = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_a_tampered_document() {
        let (alice, bob) = pair();
        let mut d = json!({ "owner": "alice", "task": { "state": "TASK_STATE_WORKING" } });
        alice.sign(Coll::Tasks, "t1", &mut d);
        d["task"]["state"] = json!("TASK_STATE_COMPLETED");
        assert_eq!(bob.verify(Coll::Tasks, "t1", &d), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_a_document_copied_to_another_id_or_collection() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t2", &d), Err(Reject::BadSignature));
        assert!(bob.verify(Coll::Tasks, "send::t1", &d).is_err());
    }

    #[test]
    fn enforces_who_may_write_what() {
        let (alice, bob) = pair();
        // an agent card for someone else
        let mut card = json!({ "nodeId": "bob", "card": {} });
        alice.sign(Coll::Agents, "bob", &mut card);
        assert!(matches!(bob.verify(Coll::Agents, "bob", &card), Err(Reject::NotAuthorized(_))));
        // a task claiming bob as owner
        let mut task = json!({ "owner": "bob", "task": {} });
        alice.sign(Coll::Tasks, "t1", &mut task);
        assert!(matches!(bob.verify(Coll::Tasks, "t1", &task), Err(Reject::NotAuthorized(_))));
        // a command issued "from" bob
        let mut cmd = command("bob", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::NotAuthorized(_))));
    }

    #[test]
    fn detects_a_rollback_to_an_older_revision() {
        let (alice, bob) = pair();
        let mut old = json!({ "owner": "alice", "n": 1 });
        let mut new = json!({ "owner": "alice", "n": 2 });
        alice.sign_at(Coll::Tasks, "t1", &mut old, 1000);
        alice.sign_at(Coll::Tasks, "t1", &mut new, 2000);
        assert!(bob.verify(Coll::Tasks, "t1", &new).is_ok());
        assert_eq!(bob.verify(Coll::Tasks, "t1", &old), Err(Reject::Rollback { newest: 2000, got: 1000 }));
        assert!(bob.verify(Coll::Tasks, "t1", &new).is_ok(), "the current revision still verifies");
    }

    #[test]
    fn a_clock_set_back_does_not_make_a_node_look_like_a_rollback() {
        let (alice, bob) = pair();
        // a revision written while alice's clock ran an hour ahead
        let ahead = now_ms() + 3_600_000;
        let mut first = json!({ "owner": "alice", "n": 1 });
        alice.sign_at(Coll::Tasks, "t1", &mut first, ahead);
        assert!(bob.verify(Coll::Tasks, "t1", &first).is_ok());

        // alice restarts with the clock back to normal; the next revision continues from the stored one
        let mut next = json!({ "owner": "alice", "n": 2 });
        alice.sign_next(Coll::Tasks, "t1", &mut next, Trust::seq_of(&first));
        assert_eq!(Trust::seq_of(&next), Some(ahead + 1));
        assert!(bob.verify(Coll::Tasks, "t1", &next).is_ok());

        // the clock alone would have been rejected as a rollback
        let mut by_clock = json!({ "owner": "alice", "n": 3 });
        alice.sign_at(Coll::Tasks, "t1", &mut by_clock, now_ms());
        assert!(matches!(bob.verify(Coll::Tasks, "t1", &by_clock), Err(Reject::Rollback { .. })));

        // a document with no stored revision (fresh database) starts from the clock
        let mut fresh = json!({ "owner": "alice" });
        alice.sign_next(Coll::Tasks, "t2", &mut fresh, None);
        assert!(Trust::seq_of(&fresh).unwrap() >= now_ms() - 5_000);
    }

    #[test]
    fn revoking_a_node_stops_accepting_its_documents() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(bob.verify(Coll::Inbox, "send::t1", &d).is_ok());
        bob.revoke("alice");
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::UnknownAuthor("alice".into())));
    }

    #[test]
    fn records_each_distinct_rejection_once_with_a_count() {
        let (_, bob) = pair();
        let d = command("alice", "bob");
        for _ in 0..3 {
            let _ = bob.verify(Coll::Inbox, "send::t1", &d);
        }
        let r = bob.rejections();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].count, 3);
        assert_eq!(r[0].reason, "unsigned document");
    }

    #[test]
    fn signatures_survive_key_reordering_and_integer_floats() {
        let (alice, bob) = pair();
        let mut d: Value = serde_json::from_str(r#"{"owner":"alice","b":1.0,"a":{"y":2,"x":[1,2.0]}}"#).unwrap();
        alice.sign(Coll::Tasks, "t1", &mut d);
        // what the database might hand back: other key order, floats stored as ints
        let mut back: Value = serde_json::from_str(r#"{"a":{"x":[1,2],"y":2},"b":1,"owner":"alice"}"#).unwrap();
        back["trust"] = d["trust"].clone();
        assert!(bob.verify(Coll::Tasks, "t1", &back).is_ok());
    }

    #[test]
    fn keys_and_trust_files_round_trip() {
        let dir = std::env::temp_dir().join(format!("a2a-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Trust::load_or_create(&dir, "alice").unwrap();
        let again = Trust::load_or_create(&dir, "alice").unwrap();
        assert_eq!(a.public_key(), again.public_key(), "the key is persisted");

        let file = dir.join("trust.json");
        std::fs::write(&file, format!(r#"{{"nodes":{{"bob":"{}","alice":"{}"}}}}"#, node("bob", 2).public_key(), a.public_key())).unwrap();
        assert_eq!(a.load_trust_file(&file).unwrap(), 2);
        assert_eq!(a.enrolled(), vec!["bob".to_string()], "this node is not listed as a peer");

        std::fs::write(&file, format!(r#"{{"alice":"{}"}}"#, node("x", 7).public_key())).unwrap();
        assert!(a.load_trust_file(&file).is_err(), "a different key for our own id is refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Biscuit mode --------------------------------------------------------

    use anp_authz::{attenuate, Attenuation, Authority, Grant};

    fn grant_for(t: &Trust, targets: &[&str]) -> Grant {
        Grant {
            node: t.node_id().into(),
            node_key_b64: t.public_key(),
            inbox_targets: targets.iter().map(|s| s.to_string()).collect(),
            expires: None,
            did: None,
            spend: None,
        }
    }

    /// A node holding a token from `auth` that lets it message `targets`.
    fn token_node(auth: &Authority, name: &str, seed: u8, targets: &[&str]) -> Trust {
        let t = node(name, seed);
        let token = auth.issue(&grant_for(&t, targets)).unwrap();
        t.with_biscuit(&auth.public_b64(), &token).unwrap()
    }

    #[test]
    fn biscuit_accepts_a_peer_whose_token_allows_the_document() {
        let auth = Authority::generate();
        let (alice, bob) = (token_node(&auth, "alice", 1, &["bob"]), token_node(&auth, "bob", 2, &["alice"]));
        assert_eq!(bob.mode(), "biscuit");
        assert!(bob.rejections().is_empty());

        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &cmd), Ok("alice".into()));

        let mut card = json!({ "nodeId": "alice", "card": {} });
        alice.sign(Coll::Agents, "alice", &mut card);
        assert!(bob.verify(Coll::Agents, "alice", &card).is_ok());
    }

    #[test]
    fn biscuit_refuses_a_peer_with_no_token() {
        let auth = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mallory = node("mallory", 9); // signs, but has no credential
        let mut cmd = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::NoCredential("mallory".into())));
    }

    #[test]
    fn biscuit_refuses_a_token_from_a_different_authority() {
        let real = Authority::generate();
        let fake = Authority::generate();
        let bob = token_node(&real, "bob", 2, &["*"]);
        let mallory = token_node(&fake, "mallory", 9, &["*"]);
        let mut cmd = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::BadCredential(_))));
    }

    #[test]
    fn biscuit_limits_who_a_node_may_message() {
        let auth = Authority::generate();
        let carol = token_node(&auth, "carol", 3, &["bob"]); // may only message bob
        let (alice, bob) = (token_node(&auth, "alice", 1, &["*"]), token_node(&auth, "bob", 2, &["*"]));
        let mut to_bob = command("carol", "bob");
        carol.sign(Coll::Inbox, "send::t1", &mut to_bob);
        assert!(bob.verify(Coll::Inbox, "send::t1", &to_bob).is_ok());
        let mut to_alice = command("carol", "alice");
        carol.sign(Coll::Inbox, "send::t2", &mut to_alice);
        let r = alice.verify(Coll::Inbox, "send::t2", &to_alice);
        assert!(matches!(r, Err(Reject::BadCredential(_))), "{r:?}");
        // and she still may publish her own card and task state
        let mut card = json!({ "nodeId": "carol", "card": {} });
        carol.sign(Coll::Agents, "carol", &mut card);
        assert!(alice.verify(Coll::Agents, "carol", &card).is_ok());
    }

    #[test]
    fn a_stolen_token_is_useless_without_the_key() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut real = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut real);
        let stolen_token = real["trust"]["token"].clone();
        let alice_key = real["trust"]["key"].clone();

        // mallory poses as alice with her own key and alice's token
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut forged = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut forged);
        forged["trust"]["token"] = stolen_token.clone();
        forged["trust"]["key"] = Value::String(mallory.public_key());
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &forged), Err(Reject::BadCredential(_))), "token names alice's key");

        forged["trust"]["key"] = alice_key; // claim alice's key instead: the signature then fails
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &forged), Err(Reject::BadSignature));
    }

    #[test]
    fn biscuit_revocation_cuts_a_node_off() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok());

        let id = anp_authz::authorize(
            cmd["trust"]["token"].as_str().unwrap(),
            &anp_authz::parse_public_key(&auth.public_b64()).unwrap(),
            &anp_authz::Claim { node: "alice", key_b64: &alice.public_key(), collection: "tasks", target: None },
        )
        .unwrap()
        .revocation_ids[0]
            .clone();
        bob.revoke_token(&id);
        let r = bob.verify(Coll::Inbox, "send::t1", &cmd);
        assert!(matches!(&r, Err(Reject::BadCredential(m)) if m.contains("revoked")), "{r:?}");
    }

    #[test]
    fn a_node_cannot_start_with_a_token_it_could_not_use() {
        let auth = Authority::generate();
        let a = node("alice", 1);
        // expired
        let mut g = grant_for(&a, &["*"]);
        g.expires = Some(std::time::SystemTime::now() - Duration::from_secs(60));
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &auth.issue(&g).unwrap()).is_err());
        // issued for someone else's key
        let other = node("alice", 7);
        let t = auth.issue(&grant_for(&other, &["*"])).unwrap();
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &t).is_err());
        // issued for another node id
        let t = auth.issue(&grant_for(&node("zed", 1), &["*"])).unwrap();
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &t).is_err());
    }

    #[test]
    fn a_narrowed_token_is_enforced_by_receivers() {
        let auth = Authority::generate();
        let a = node("alice", 1);
        let full = auth.issue(&grant_for(&a, &["*"])).unwrap();
        let root = anp_authz::parse_public_key(&auth.public_b64()).unwrap();
        // alice hands herself (or a helper) a token that only reaches hq
        let narrowed = attenuate(&full, &root, &Attenuation { inbox_targets: Some(vec!["hq".into()]), ..Default::default() }).unwrap();
        let alice = node("alice", 1).with_biscuit(&auth.public_b64(), &narrowed).unwrap();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut to_hq = command("alice", "hq");
        alice.sign(Coll::Inbox, "send::t1", &mut to_hq);
        assert!(bob.verify(Coll::Inbox, "send::t1", &to_hq).is_ok());
        let mut to_bob = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t2", &mut to_bob);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t2", &to_bob), Err(Reject::BadCredential(_))));
    }

    #[test]
    fn an_authority_signed_revocation_document_cuts_a_node_off() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok());
        assert!(bob.revoked_ids().is_empty());

        // the authority revokes alice's token; the document reaches bob by replication
        let rev = auth.revoke(cmd["trust"]["token"].as_str().unwrap(), "tablet lost").unwrap();
        let doc = rev.to_json();
        assert_eq!(bob.verify(Coll::Revocations, &rev.revoked, &doc), Ok("authority".into()));
        assert_eq!(bob.revoked_ids(), vec![rev.revoked.clone()]);

        let r = bob.verify(Coll::Inbox, "send::t1", &cmd);
        assert!(matches!(&r, Err(Reject::BadCredential(m)) if m.contains("revoked")), "{r:?}");
    }

    #[test]
    fn a_forged_misplaced_or_unsupported_revocation_is_ignored() {
        let auth = Authority::generate();
        let impostor = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        let token = cmd["trust"]["token"].as_str().unwrap().to_string();

        // signed by someone who is not the authority
        let id = auth.revoke(&token, "x").unwrap().revoked;
        let forged = impostor.revoke_id(&id, "mallory says so").unwrap();
        assert!(matches!(bob.verify(Coll::Revocations, &id, &forged.to_json()), Err(Reject::BadCredential(_))));
        // a genuine one stored under a different document id
        let real = auth.revoke(&token, "x").unwrap();
        assert!(matches!(bob.verify(Coll::Revocations, "somethingelse", &real.to_json()), Err(Reject::NotAuthorized(_))));
        assert!(bob.revoked_ids().is_empty(), "nothing was applied");
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok(), "alice is still accepted");

        // allowlist mode has no authority, so it never honours revocation documents
        let plain = node("carol", 3);
        assert!(matches!(plain.verify(Coll::Revocations, &real.revoked, &real.to_json()), Err(Reject::NotAuthorized(_))));
    }

    #[test]
    fn admission_accepts_valid_tokens_and_refuses_revoked_or_foreign_ones() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let (user, token) = alice.credential().unwrap();
        assert_eq!(user, "alice");
        assert!(bob.admit(&user, &token), "a genuine token admits its node");
        assert!(!bob.admit("mallory", &token), "someone else's token is not admitted under another name");
        assert!(!bob.admit(&user, "not a token"));
        let fake = token_node(&Authority::generate(), "alice", 1, &["*"]);
        assert!(!bob.admit("alice", &fake.credential().unwrap().1), "token from another authority");

        bob.accept_revocation(&auth.revoke(&token, "lost").unwrap()).unwrap();
        assert!(!bob.admit(&user, &token), "a revoked token is refused at the door");
        assert!(bob.rejections().iter().any(|r| r.collection == "connection" && r.reason.contains("revoked")));
        // and there is nothing to admit against without Biscuit
        assert!(!node("zed", 9).admit("zed", &token));
        assert!(node("zed", 9).credential().is_none());
    }
    #[test]
    fn revocation_lists_load_from_a_file() {
        let auth = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let dir = std::env::temp_dir().join(format!("a2a-revoked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("revoked.txt");
        std::fs::write(&f, "# lost tablet\nAABBCC # inline comment\n\nddeeff\n").unwrap();
        assert_eq!(bob.load_revocations(&f).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── DID mode ────────────────────────────────────────────────────────────────────────────────────────

    fn did_node(name: &str, seed: u8, host: &str) -> Trust {
        node(name, seed).with_did(host, None, None).unwrap()
    }
    /// alice and bob trust each other's DIDs.
    fn did_pair() -> (Trust, Trust) {
        let (alice, bob) = (did_node("alice", 1, "a.example.com"), did_node("bob", 2, "b.example.com"));
        alice.trust_did(bob.did().unwrap()).unwrap();
        bob.trust_did(alice.did().unwrap()).unwrap();
        (alice, bob)
    }

    #[test]
    fn did_mode_accepts_a_document_from_a_trusted_did_without_any_lookup() {
        let (alice, bob) = did_pair();
        assert_eq!(bob.mode(), "did");
        assert!(bob.did().unwrap().starts_with("did:wba:b.example.com:agents:bob:e1_"));
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Ok("alice".into()));
        let mut back = command("bob", "alice");
        bob.sign(Coll::Inbox, "send::t2", &mut back);
        assert_eq!(alice.verify(Coll::Inbox, "send::t2", &back), Ok("bob".into()));
    }

    #[test]
    fn did_mode_refuses_a_did_nobody_pinned() {
        let (_, bob) = did_pair();
        let mallory = did_node("mallory", 9, "evil.example.com");
        let mut d = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(m)) if m.contains("not a trusted identity")));
    }

    #[test]
    fn did_mode_a_forged_document_naming_a_trusted_host_is_still_refused() {
        // Anyone can mint a self-signed DID document that says it lives on a.example.com. Only pinning the DID counts.
        let (_, bob) = did_pair();
        let mallory = did_node("alice", 9, "a.example.com");
        let mut d = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(_))));
    }

    #[test]
    fn did_mode_replaying_alices_document_with_another_key_fails_the_signature() {
        // The DID document is public (it replicates). Mallory attaches Alice's genuine DID and document to her own
        // signature, hoping that is enough to pass as Alice.
        let (alice, bob) = did_pair();
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut d = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        d["trust"]["did"] = json!(alice.did().unwrap());
        d["trust"]["didDoc"] = alice.did_document().unwrap();
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadSignature));
    }

    #[test]
    fn did_mode_the_name_is_part_of_the_identity() {
        let (alice, bob) = did_pair();
        bob.trust_did(alice.did().unwrap()).unwrap();
        // alice's real DID and key, but she signs as 'bob'
        let mut d = json!({ "nodeId": "bob", "ts": 1 });
        let imposter = Trust { node_id: "bob".into(), ..did_node("bob", 1, "a.example.com") };
        imposter.sign(Coll::Agents, "bob", &mut d);
        d["trust"]["did"] = json!(alice.did().unwrap());
        d["trust"]["didDoc"] = alice.did_document().unwrap();
        // verified by a third node that trusts alice's DID
        let carol = did_node("carol", 3, "c.example.com");
        carol.trust_did(alice.did().unwrap()).unwrap();
        assert!(matches!(carol.verify(Coll::Agents, "bob", &d), Err(Reject::BadCredential(m)) if m.contains("not the identity of 'bob'")));
    }

    #[test]
    fn did_mode_a_tampered_did_document_is_refused() {
        let (alice, bob) = did_pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        d["trust"]["didDoc"]["service"] = json!([{ "id": "x", "type": "AgentDescription", "serviceEndpoint": "https://evil.example.com" }]);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(_))));
        let mut e = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t2", &mut e);
        e["trust"].as_object_mut().unwrap().remove("didDoc");
        assert!(matches!(bob.verify(Coll::Inbox, "send::t2", &e), Err(Reject::NoCredential(_))));
    }

    #[test]
    fn did_mode_admission_proves_possession_of_the_key() {
        let (alice, bob) = did_pair();
        let (user, pass) = alice.credential().unwrap();
        assert!(bob.admit(&user, &pass), "a trusted DID's fresh assertion is admitted");
        assert!(!bob.admit("mallory", &pass), "the assertion is bound to the name");
        assert!(!bob.admit(&user, "garbage"));
        // not pinned
        let stranger = did_node("stranger", 7, "s.example.com");
        let (u2, p2) = stranger.credential().unwrap();
        assert!(!bob.admit(&u2, &p2));
        // a stale assertion (clocks, or a captured one)
        let d = alice.did.as_ref().unwrap();
        let ts = now_ms() - 3_600_000;
        let sig = alice.key.sign(admit_message("alice", &d.did, ts).as_bytes());
        let stale = B64.encode(json!({ "did": d.did, "doc": d.doc, "ts": ts, "sig": B64.encode(sig.to_bytes()) }).to_string());
        assert!(!bob.admit("alice", &stale));
        // Alice's public DID and document without her key
        let forged = B64.encode(json!({ "did": d.did, "doc": d.doc, "ts": now_ms(), "sig": B64.encode([0u8; 64]) }).to_string());
        assert!(!bob.admit("alice", &forged));
        assert!(bob.rejections().iter().any(|r| r.collection == "connection" && r.reason.contains("stale")));
    }

    #[test]
    fn did_mode_after_biscuit_is_refused_and_pinning_needs_did_mode() {
        let auth = Authority::generate();
        let t = token_node(&auth, "alice", 1, &["*"]);
        assert!(t.with_did("a.example.com", None, None).is_err());
        assert!(node("alice", 1).trust_did("did:wba:a.example.com").is_err(), "needs DID mode");
    }

    // ── DID + Biscuit ───────────────────────────────────────────────────────────────────────────────────

    /// A node that proves a DID and holds a token from `auth` bound to that DID. Returns the node and its token.
    fn hybrid(auth: &Authority, name: &str, seed: u8, host: &str, targets: &[&str]) -> (Trust, String) {
        let t = node(name, seed).with_did(host, None, None).unwrap();
        let mut g = grant_for(&t, targets);
        g.did = t.did().map(str::to_string);
        let token = auth.issue(&g).unwrap();
        (t.with_biscuit(&auth.public_b64(), &token).unwrap(), token)
    }

    #[test]
    fn hybrid_trusts_a_did_the_authority_vouches_for_without_any_pin() {
        let auth = Authority::generate();
        let ((alice, _), (bob, _)) = (hybrid(&auth, "alice", 1, "a.example.com", &["bob"]), hybrid(&auth, "bob", 2, "b.example.com", &["alice"]));
        assert_eq!(bob.mode(), "did+biscuit");
        assert!(bob.has_biscuit() && bob.admits());
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Ok("alice".into()), "no trust_did call was needed");
        let mut card = json!({ "nodeId": "alice", "ts": 1 });
        alice.sign(Coll::Agents, "alice", &mut card);
        assert_eq!(bob.verify(Coll::Agents, "alice", &card), Ok("alice".into()));
    }

    #[test]
    fn hybrid_keeps_the_tokens_scoping() {
        let auth = Authority::generate();
        let ((alice, _), (bob, _)) = (hybrid(&auth, "alice", 1, "a.example.com", &["bob"]), hybrid(&auth, "bob", 2, "b.example.com", &["alice"]));
        let mut ok = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut ok);
        assert!(bob.verify(Coll::Inbox, "send::t1", &ok).is_ok());
        let mut no = command("alice", "carol");
        alice.sign(Coll::Inbox, "send::t2", &mut no);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t2", &no), Err(Reject::BadCredential(_))), "alice's token only lets her message bob");
    }

    #[test]
    fn hybrid_refuses_a_did_the_authority_did_not_vouch_for() {
        let auth = Authority::generate();
        let (bob, _) = hybrid(&auth, "bob", 2, "b.example.com", &["*"]);
        // a perfectly valid DID with a token from some other authority
        let (mallory, _) = hybrid(&Authority::generate(), "mallory", 9, "evil.example.com", &["*"]);
        let mut d = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(_))));
        // and a pin does not substitute for a token
        bob.trust_did(mallory.did().unwrap()).unwrap();
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(_))), "the authority decides, not a pin");
    }

    #[test]
    fn hybrid_a_token_not_bound_to_the_did_is_refused_at_startup() {
        let auth = Authority::generate();
        let t = node("alice", 1).with_did("a.example.com", None, None).unwrap();
        let unbound = auth.issue(&grant_for(&t, &["*"])).unwrap(); // no DID in the grant
        assert!(t.with_biscuit(&auth.public_b64(), &unbound).is_err());
        let t = node("alice", 1).with_did("a.example.com", None, None).unwrap();
        let other = {
            let mut g = grant_for(&t, &["*"]);
            g.did = Some("did:wba:a.example.com:agents:alice:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
            auth.issue(&g).unwrap()
        };
        assert!(t.with_biscuit(&auth.public_b64(), &other).is_err(), "a token for a different DID");
        // order matters: a DID-bound token cannot be validated before the DID exists
        let (_, bound) = hybrid(&auth, "alice", 1, "a.example.com", &["*"]);
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &bound).is_err());
        let wrong_order = node("zed", 5).with_biscuit(&auth.public_b64(), &auth.issue(&grant_for(&node("zed", 5), &["*"])).unwrap()).unwrap();
        assert!(wrong_order.with_did("z.example.com", None, None).is_err(), "call with_did first");
    }

    #[test]
    fn hybrid_a_stolen_token_or_document_does_not_make_an_impersonator() {
        let auth = Authority::generate();
        let ((alice, _), (bob, bob_tok)) = (hybrid(&auth, "alice", 1, "a.example.com", &["bob"]), hybrid(&auth, "bob", 2, "b.example.com", &["alice"]));
        // Mallory signs with her own key but attaches Alice's public DID document and token
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut d = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        let mut genuine = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t0", &mut genuine);
        d["trust"]["did"] = genuine["trust"]["did"].clone();
        d["trust"]["didDoc"] = genuine["trust"]["didDoc"].clone();
        d["trust"]["token"] = genuine["trust"]["token"].clone();
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadSignature));
        // Alice's real signature, but someone swaps in Bob's token
        let mut swapped = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t2", &mut swapped);
        swapped["trust"]["token"] = json!(bob_tok);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t2", &swapped), Err(Reject::BadCredential(_))));
        // no token at all
        let mut bare = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t3", &mut bare);
        bare["trust"].as_object_mut().unwrap().remove("token");
        assert!(matches!(bob.verify(Coll::Inbox, "send::t3", &bare), Err(Reject::NoCredential(_))));
    }

    #[test]
    fn hybrid_revocation_cuts_a_did_off_and_closes_the_door() {
        let auth = Authority::generate();
        let ((alice, alice_tok), (bob, _)) = (hybrid(&auth, "alice", 1, "a.example.com", &["bob"]), hybrid(&auth, "bob", 2, "b.example.com", &["alice"]));
        let (user, pass) = alice.credential().unwrap();
        assert!(bob.admit(&user, &pass), "a vouched DID with its token is admitted");
        assert!(!bob.admit("mallory", &pass), "bound to the name");
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(bob.verify(Coll::Inbox, "send::t1", &d).is_ok());

        bob.accept_revocation(&auth.revoke(&alice_tok, "tablet lost").unwrap()).unwrap();
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadCredential(m)) if m.contains("revoked")));
        assert!(!bob.admit(&user, &pass), "the door is closed too");
        assert!(bob.rejections().iter().any(|r| r.collection == "connection" && r.reason.contains("revoked")));
    }

    #[test]
    fn hybrid_admission_needs_the_token_and_the_dids_signature() {
        let auth = Authority::generate();
        let ((alice, _), (bob, _)) = (hybrid(&auth, "alice", 1, "a.example.com", &["bob"]), hybrid(&auth, "bob", 2, "b.example.com", &["alice"]));
        // a valid DID assertion with no token
        let d = alice.did.as_ref().unwrap();
        let ts = now_ms();
        let sig = alice.key.sign(admit_message("alice", &d.did, ts).as_bytes());
        let no_token = B64.encode(json!({ "did": d.did, "doc": d.doc, "ts": ts, "sig": B64.encode(sig.to_bytes()) }).to_string());
        assert!(!bob.admit("alice", &no_token));
        // a stranger under another authority
        let (mal, _) = hybrid(&Authority::generate(), "mallory", 9, "evil.example.com", &["*"]);
        let (u, p) = mal.credential().unwrap();
        assert!(!bob.admit(&u, &p));
    }

    #[test]
    fn a_did_node_publishes_a_signed_agent_description_its_did_document_points_to() {
        let alice = node("alice", 1).with_did("alice.example.com", Some(8800), None).unwrap();
        let did_doc = anp_did::verify_document(&alice.did_document().unwrap(), alice.did()).unwrap();
        let endpoint = did_doc.service_endpoint("AgentDescription").unwrap();
        assert_eq!(endpoint, "https://alice.example.com:8800/agents/alice/ad.json");
        let card = json!({ "name": "alice", "description": "Reviews reports", "version": "1.0", "skills": [{ "id": "review", "name": "Review", "description": "d" }] });
        let ad = alice.agent_description(&card).unwrap();
        assert_eq!(ad["url"], endpoint.as_str(), "the document says where it lives, and that is where the DID points");
        anp_ad::verify(&ad, &did_doc, Some("alice.example.com:8800")).unwrap();
        assert!(anp_ad::verify(&ad, &did_doc, Some("elsewhere.example.com")).is_err());
        let again = alice.agent_description(&card).unwrap();
        assert_ne!(ad["proof"]["challenge"], again["proof"]["challenge"], "a fresh challenge each time");
        assert!(node("bob", 2).agent_description(&card).is_err(), "only in DID mode");
    }

    // ── end-to-end encryption ───────────────────────────────────────────────────────────────────────────

    fn e2ee_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("anp-e2ee-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn e2ee_node(name: &str, seed: u8, dir: &std::path::Path) -> Trust {
        node(name, seed).with_did(&format!("{name}.example.com"), None, None).unwrap().with_e2ee(dir).unwrap()
    }
    /// Make `a` and `b` trust each other's DIDs and learn each other's keys, as replicated agent cards would.
    fn befriend(a: &Trust, b: &Trust) {
        a.trust_did(b.did().unwrap()).unwrap();
        b.trust_did(a.did().unwrap()).unwrap();
        for (x, y) in [(a, b), (b, a)] {
            let mut card = json!({ "nodeId": x.node_id(), "ts": 1, "e2eeBundle": x.e2ee_bundle().unwrap() });
            x.sign(Coll::Agents, x.node_id(), &mut card);
            y.learn_peer(&card);
        }
    }
    fn secret_command(from: &str, to: &str) -> Value {
        json!({ "kind": "send", "taskId": "t1", "contextId": "c1", "to": to, "from": from, "ts": 5,
                "message": { "role": "ROLE_USER", "parts": [{ "text": "TOP-SECRET-MARKER" }] } })
    }

    #[test]
    fn a_command_is_readable_by_its_recipient_and_its_author_only() {
        let (da, db, dc) = (e2ee_dir("a1"), e2ee_dir("b1"), e2ee_dir("c1"));
        let (alice, bob, carol) = (e2ee_node("alice", 1, &da), e2ee_node("bob", 2, &db), e2ee_node("carol", 3, &dc));
        befriend(&alice, &bob);
        befriend(&alice, &carol);
        befriend(&bob, &carol);
        let original = secret_command("alice", "bob");
        let mut doc = original.clone();
        alice.seal_doc(Coll::Inbox, "send::t1", &mut doc).unwrap();
        assert!(doc.get("message").is_none() && doc.get("enc").is_some());
        alice.sign(Coll::Inbox, "send::t1", &mut doc);
        assert!(!doc.to_string().contains("TOP-SECRET-MARKER"), "the stored document holds no plaintext");
        assert_eq!(doc["to"], "bob", "routing metadata stays readable");

        // every node can verify the document (it is signed), only the right ones can open it
        for n in [&alice, &bob, &carol] {
            assert!(n.verify(Coll::Inbox, "send::t1", &doc).is_ok());
        }
        let mut for_bob = doc.clone();
        assert_eq!(bob.open_doc(Coll::Inbox, "send::t1", &mut for_bob), Opened::Decrypted);
        assert_eq!(for_bob["message"], original["message"]);
        let mut for_alice = doc.clone();
        assert_eq!(alice.open_doc(Coll::Inbox, "send::t1", &mut for_alice), Opened::Decrypted, "the author keeps access");
        let mut for_carol = doc.clone();
        assert_eq!(carol.open_doc(Coll::Inbox, "send::t1", &mut for_carol), Opened::NotForUs, "a relay cannot read it");
        assert!(for_carol.get("message").is_none());
    }

    #[test]
    fn a_task_goes_back_to_the_node_that_asked_for_it() {
        let (da, db) = (e2ee_dir("a2"), e2ee_dir("b2"));
        let (alice, bob) = (e2ee_node("alice", 1, &da), e2ee_node("bob", 2, &db));
        befriend(&alice, &bob);
        // bob executed alice's command and writes the task: origin alice, owner bob
        let task = json!({ "task": { "id": "t1", "artifacts": [{ "parts": [{ "text": "TOP-SECRET-MARKER" }] }] }, "owner": "bob", "origin": "alice", "ts": 7 });
        let mut doc = task.clone();
        bob.seal_doc(Coll::Tasks, "t1", &mut doc).unwrap();
        bob.sign(Coll::Tasks, "t1", &mut doc);
        assert!(!doc.to_string().contains("TOP-SECRET-MARKER"));
        let mut at_alice = doc.clone();
        assert_eq!(alice.open_doc(Coll::Tasks, "t1", &mut at_alice), Opened::Decrypted);
        assert_eq!(at_alice["task"], task["task"]);
        let mut at_bob = doc.clone();
        assert_eq!(bob.open_doc(Coll::Tasks, "t1", &mut at_bob), Opened::Decrypted, "the executor reads its own task back");
        // a task that stays on one node is sealed to that node alone
        let mut local = json!({ "task": { "id": "t2" }, "owner": "bob", "origin": "bob", "ts": 1 });
        bob.seal_doc(Coll::Tasks, "t2", &mut local).unwrap();
        assert_eq!(local["enc"]["recipients"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sealing_fails_closed_without_the_recipients_keys() {
        let (da, db) = (e2ee_dir("a3"), e2ee_dir("b3"));
        let (alice, bob) = (e2ee_node("alice", 1, &da), e2ee_node("bob", 2, &db));
        let mut doc = secret_command("alice", "bob");
        assert_eq!(alice.seal_doc(Coll::Inbox, "send::t1", &mut doc), Err(SealError::NeedPeer("bob".into())));
        assert!(doc.get("message").is_some(), "nothing was changed, and nothing was sent in the clear");
        // a bundle that has expired is not used either
        befriend(&alice, &bob);
        alice.e2ee.as_ref().unwrap().peers.lock().unwrap().get_mut("bob").unwrap().expires_at = "2020-01-01T00:00:00Z".into();
        assert_eq!(alice.seal_doc(Coll::Inbox, "send::t1", &mut doc), Err(SealError::NeedPeer("bob".into())));
        // documents that carry no payload need no keys
        let mut card = json!({ "nodeId": "alice", "ts": 1 });
        assert!(alice.seal_doc(Coll::Agents, "alice", &mut card).is_ok() && card.get("enc").is_none());
    }

    #[test]
    fn plaintext_from_a_peer_is_refused_when_encryption_is_on() {
        let (da, db, dc) = (e2ee_dir("a4"), e2ee_dir("b4"), e2ee_dir("c4"));
        let (bob, carol) = (e2ee_node("bob", 2, &db), e2ee_node("carol", 3, &dc));
        let alice = node("alice", 1).with_did("alice.example.com", None, None).unwrap(); // no encryption
        let _ = da;
        alice.trust_did(bob.did().unwrap()).unwrap();
        bob.trust_did(alice.did().unwrap()).unwrap();
        let mut plain = secret_command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut plain);
        assert!(bob.verify(Coll::Inbox, "send::t1", &plain).is_ok(), "the signature is fine");
        assert!(matches!(bob.open_doc(Coll::Inbox, "send::t1", &mut plain), Opened::Refused(m) if m.contains("plaintext")), "but it must not be accepted as is");
        // our own plaintext (written before encryption was switched on) is not a downgrade
        let mut mine = secret_command("bob", "carol");
        bob.sign(Coll::Inbox, "send::t2", &mut mine);
        assert_eq!(bob.open_doc(Coll::Inbox, "send::t2", &mut mine), Opened::Plain);
        let _ = carol;
    }

    #[test]
    fn a_sealed_payload_cannot_be_moved_to_another_document_or_field() {
        let (da, db) = (e2ee_dir("a5"), e2ee_dir("b5"));
        let (alice, bob) = (e2ee_node("alice", 1, &da), e2ee_node("bob", 2, &db));
        befriend(&alice, &bob);
        let mut doc = secret_command("alice", "bob");
        alice.seal_doc(Coll::Inbox, "send::t1", &mut doc).unwrap();
        alice.sign(Coll::Inbox, "send::t1", &mut doc);
        let mut moved = doc.clone();
        assert!(matches!(bob.open_doc(Coll::Inbox, "send::OTHER", &mut moved), Opened::Refused(_)), "another document id");
        let mut renamed = doc.clone();
        renamed["enc"]["field"] = json!("task");
        assert!(matches!(bob.open_doc(Coll::Inbox, "send::t1", &mut renamed), Opened::Refused(_)), "another field");
        let mut both = doc.clone();
        both["message"] = json!({ "plaintext": "injected" });
        assert!(matches!(bob.open_doc(Coll::Inbox, "send::t1", &mut both), Opened::Refused(_)), "a payload next to the ciphertext");
    }

    #[test]
    fn prekeys_persist_rotate_and_are_deleted() {
        let (da, db) = (e2ee_dir("a6"), e2ee_dir("b6"));
        let alice = e2ee_node("alice", 1, &da);
        let bob = e2ee_node("bob", 2, &db);
        befriend(&alice, &bob);
        let mut doc = secret_command("alice", "bob");
        alice.seal_doc(Coll::Inbox, "send::t1", &mut doc).unwrap();
        alice.sign(Coll::Inbox, "send::t1", &mut doc);

        // bob restarts: same prekeys come back from disk, the message still opens
        let bob2 = e2ee_node("bob", 2, &db);
        bob2.trust_did(alice.did().unwrap()).unwrap();
        let mut d1 = doc.clone();
        assert_eq!(bob2.open_doc(Coll::Inbox, "send::t1", &mut d1), Opened::Decrypted);
        assert_eq!(bob2.e2ee.as_ref().unwrap().prekeys.lock().unwrap().len(), 1, "no rotation yet");

        // an old prekey is rotated, the old one stays for opening
        bob2.e2ee.as_ref().unwrap().prekeys.lock().unwrap()[0].created_ms -= SPK_ROTATE_MS + 1;
        let new_bundle = bob2.e2ee_bundle().unwrap();
        assert_eq!(bob2.e2ee.as_ref().unwrap().prekeys.lock().unwrap().len(), 2);
        assert_ne!(new_bundle["signed_prekey"]["key_id"], doc["enc"]["recipients"][0]["init"]["recipient_signed_prekey_id"]);
        let mut d2 = doc.clone();
        assert_eq!(bob2.open_doc(Coll::Inbox, "send::t1", &mut d2), Opened::Decrypted, "messages to the previous prekey still open");

        // past the keep time the old prekey is deleted, and the message can never be opened again
        bob2.e2ee.as_ref().unwrap().prekeys.lock().unwrap()[0].created_ms -= SPK_KEEP_MS;
        bob2.rotate_prekeys().unwrap();
        assert_eq!(bob2.e2ee.as_ref().unwrap().prekeys.lock().unwrap().len(), 1);
        let bob3 = e2ee_node("bob", 2, &db); // and it is gone from disk too
        let mut d3 = doc.clone();
        assert!(matches!(bob3.open_doc(Coll::Inbox, "send::t1", &mut d3), Opened::Refused(m) if m.contains("deleted")));
    }

    #[test]
    fn encryption_needs_did_mode_and_the_key_is_published_either_way() {
        let d = e2ee_dir("a7");
        assert!(node("x", 1).with_e2ee(&d).is_err());
        let plain = node("alice", 1).with_did("alice.example.com", None, None).unwrap();
        let v = anp_did::verify_document(&plain.did_document().unwrap(), plain.did()).unwrap();
        assert!(v.key_agreement().is_some(), "every DID-mode node advertises a key-agreement key");
        let on = e2ee_node("alice", 1, &d);
        assert!(on.e2ee_enabled() && !plain.e2ee_enabled());
        assert!(plain.e2ee_bundle().is_none());
        // the same node always has the same key-agreement key (it comes from the seed)
        assert_eq!(v.key_agreement(), anp_did::verify_document(&on.did_document().unwrap(), on.did()).unwrap().key_agreement());
    }

    #[test]
    fn one_time_prekeys_are_handed_out_once_used_once_and_kept_across_restarts() {
        let d = e2ee_dir("opk1");
        let n = e2ee_node("alice", 1, &d);
        let a = n.direct_issue_one_time_prekey().expect("one is ready");
        let b = n.direct_issue_one_time_prekey().unwrap();
        assert_ne!(a["key_id"], b["key_id"], "never the same key twice");
        let id = a["key_id"].as_str().unwrap().to_string();
        // the public half the SDK would use, and the secret we keep
        let secret = n.direct_consume_one_time_prekey(&id).expect("an issued key can be used");
        assert_eq!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(anp_e2ee::public_of(&secret)), a["public_key_b64u"].as_str().unwrap());
        assert!(n.direct_consume_one_time_prekey(&id).is_none(), "and only once");
        assert!(n.direct_consume_one_time_prekey("opk-never-issued").is_none(), "a key that was never handed out cannot be used");
        // a restart: b is still issued and usable, a is still used up, and the pool is topped up
        let m = e2ee_node("alice", 1, &d);
        assert!(m.direct_consume_one_time_prekey(&id).is_none());
        let bid = b["key_id"].as_str().unwrap();
        assert!(m.direct_consume_one_time_prekey(bid).is_some(), "an issued, unused key survives a restart");
        // the pool is never empty for long: 10 ready after every start, and each issue refills
        for _ in 0..25 {
            assert!(m.direct_issue_one_time_prekey().is_some());
        }
        // the identity and the signed prekey a bundle names are available for accepting inits
        let (did, device, ka_id, _ka) = m.direct_identity().unwrap();
        assert!(did.starts_with("did:wba:alice.example.com:agents:alice:e1_") && device == "dev-alice" && ka_id.ends_with("#key-agreement-1"));
        let bundle = m.e2ee_bundle().unwrap();
        let (spk_id, _) = m.direct_prekey_for_bundle(bundle["bundle_id"].as_str().unwrap()).expect("the prekey of the published bundle");
        assert_eq!(bundle["signed_prekey"]["key_id"], spk_id.as_str());
        assert!(m.direct_prekey_for_bundle("bundle-unknown").is_none());
        assert!(node("x", 9).direct_issue_one_time_prekey().is_none() && node("x", 9).direct_identity().is_none(), "nothing without end-to-end encryption");
    }

    #[test]
    fn a_did_document_can_advertise_a_message_service() {
        let t = node("alice", 1)
            .with_did_services("alice.example.com", Some(8800), None, vec![serde_json::json!({ "id": "#message", "type": "ANPMessageService", "serviceEndpoint": "https://alice.example.com:8800/anp/direct" })])
            .unwrap();
        let v = anp_did::verify_document(&t.did_document().unwrap(), t.did()).unwrap();
        assert_eq!(v.service_endpoint("ANPMessageService").as_deref(), Some("https://alice.example.com:8800/anp/direct"));
        let svc = v.services().into_iter().find(|s| s["type"] == "ANPMessageService").unwrap();
        assert!(svc["id"].as_str().unwrap().ends_with("#message") && svc["id"].as_str().unwrap().starts_with("did:wba:"), "a relative id becomes a DID URL");
        assert!(v.service_endpoint("AgentDescription").is_some(), "the agent description service stays");
    }
}