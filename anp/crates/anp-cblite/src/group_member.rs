//! The node as a **member** of end-to-end encrypted groups (ANP-09 "P6", `--group-member <host URL>`), next to its role as a host
//! (`group_host`). The node is one MLS device: its DID, its device id, a leaf whose key is bound to the DID by a signed binding.
//!
//! * It publishes a key package to the host (at start, and again each time one is used up by a welcome), so a controller can add it.
//! * As a **controller** it creates a group (the host provisions the group DID), adds and removes members: each change is an MLS
//!   commit whose authenticated data is the submission binding, with an origin proof by the node's key.
//! * As a **member** it collects its mailbox from the host (a long poll), and for each notification: joins from a welcome, processes
//!   another member's commit (checking it carries the binding the notice says), learns it was removed, or verifies (origin proof against
//!   the sender's DID document, receipt by the group's key) and decrypts a message.
//! * It sends to a group it belongs to. Everything sent and received is in a log per group, announced to [`GroupMember::subscribe`]rs.
//!
//! State (the MLS state, which holds secrets; the groups with their version and epoch; the log) is kept in the data folder, so a
//! restart picks up where it was. The host never sees a group secret: it relays ciphertext and orders changes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anp_group::{aad, binding, origin, wire, *};
use anp_group_mls::Member;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};

use crate::direct_messaging::post_signed;
use crate::httpauth::DomainTrust;
use crate::trust::Trust;

/// The profiles a group member's device lists in its DID document (call `Trust::with_device_profiles` with them before `with_did`).
pub const GROUP_PROFILES: [&str; 4] = binding::P6_PROFILES;

/// How many messages the log keeps per group.
const LOG_PER_GROUP: usize = 500;
/// How long one collection of the mailbox may wait for a delivery (the host's long poll).
const PULL_WAIT_MS: u64 = 20_000;
/// How long a key package and its binding are valid.
const PACKAGE_DAYS: i64 = 30;

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}
fn ts(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn b64(b: &[u8]) -> String {
    B64U.encode(b)
}
fn unb64(v: &Value, what: &str) -> Result<Vec<u8>, String> {
    B64U.decode(v.as_str().unwrap_or("")).map_err(|_| format!("{what} is not base64url"))
}
fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}
fn op_id(kind: &str) -> String {
    format!("op-{kind}-{}", uuid::Uuid::new_v4())
}

/// What this node knows of a group it belongs to.
#[derive(Clone, Debug)]
struct GroupRec {
    /// The MLS group id, base64url.
    gid: String,
    /// The group state version the host is at (as far as we have seen).
    version: u64,
    /// `controller` (we created it) or `member`.
    role: String,
    /// `active`, or `removed` once we were removed.
    status: String,
    /// The group's DID document (its key signs the receipts), when the host serves it.
    doc: Option<Value>,
}

impl GroupRec {
    fn to_json(&self) -> Value {
        json!({ "gid": self.gid, "version": self.version, "role": self.role, "status": self.status, "doc": self.doc })
    }
    fn from_json(v: &Value) -> Option<GroupRec> {
        Some(GroupRec {
            gid: v["gid"].as_str()?.to_string(),
            version: v["version"].as_u64()?,
            role: v["role"].as_str()?.to_string(),
            status: v["status"].as_str()?.to_string(),
            doc: v.get("doc").filter(|d| d.is_object()).cloned(),
        })
    }
}

pub struct GroupMember {
    trust: Arc<Trust>,
    /// The host's base URL (`http://host:port`): JSON-RPC at `/anp/groups`, provisioning at `/anp/groups/provision`.
    host: String,
    docs: HashMap<String, Value>,
    domains: Option<Arc<DomainTrust>>,
    member: Mutex<Member>,
    member_file: PathBuf,
    groups: Mutex<HashMap<String, GroupRec>>,
    groups_file: PathBuf,
    log: Mutex<HashMap<String, Vec<Value>>>,
    log_file: PathBuf,
    events: tokio::sync::broadcast::Sender<Value>,
    /// One group operation at a time (an MLS commit is pending between proposing it and the host's answer).
    busy: tokio::sync::Mutex<()>,
    /// Notifications handled and not yet acknowledged to the host.
    acks: Mutex<Vec<String>>,
}

fn write_private(file: &Path, v: &Value) {
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

fn load(file: &Path) -> Result<Option<Value>, String> {
    match std::fs::read_to_string(file) {
        Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| format!("{}: {e}", file.display())),
        Err(_) => Ok(None),
    }
}

impl GroupMember {
    /// `host` is the group host's base URL; `docs` the DID documents the node was given (`--allow-caller`), with which senders'
    /// origin proofs are checked and members' devices found; `dir` the data folder.
    pub fn new(trust: Arc<Trust>, host: &str, dir: &Path, docs: Vec<Value>, domains: Option<Arc<DomainTrust>>) -> Result<GroupMember, String> {
        let did = trust.did().ok_or("group membership needs DID mode (--did-host)")?.to_string();
        let device = trust.own_device_id();
        let member_file = dir.join("group-member-mls.json");
        let member = match load(&member_file)? {
            Some(v) => Member::import_state(&v).map_err(|e| format!("{}: {e}", member_file.display()))?,
            None => Member::new(&did, &device).map_err(|e| e.to_string())?,
        };
        let groups_file = dir.join("group-member-groups.json");
        let groups = load(&groups_file)?.and_then(|v| v.as_object().cloned()).map(|o| o.iter().filter_map(|(k, v)| GroupRec::from_json(v).map(|g| (k.clone(), g))).collect()).unwrap_or_default();
        let log_file = dir.join("group-member-log.json");
        let log = load(&log_file)?.and_then(|v| v.as_object().cloned()).map(|o| o.into_iter().map(|(k, v)| (k, v.as_array().cloned().unwrap_or_default())).collect()).unwrap_or_default();
        let docs = docs.into_iter().filter_map(|d| d["id"].as_str().map(|id| (id.to_string(), d.clone()))).collect();
        let me = GroupMember {
            trust,
            host: host.trim_end_matches('/').to_string(),
            docs,
            domains,
            member: Mutex::new(member),
            member_file,
            groups: Mutex::new(groups),
            groups_file,
            log: Mutex::new(log),
            log_file,
            events: tokio::sync::broadcast::channel(256).0,
            busy: tokio::sync::Mutex::new(()),
            acks: Mutex::new(vec![]),
        };
        me.save_member();
        Ok(me)
    }

    /// Publish a key package, then keep collecting the mailbox.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            // the host may not be up yet: keep trying to publish
            let mut delay = 1;
            while let Err(e) = me.publish_key_package().await {
                log::warn!("group member: could not publish a key package to {}: {e}", me.host);
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(30);
            }
            loop {
                if let Err(e) = me.collect().await {
                    log::warn!("group member: collecting the mailbox: {e}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });
    }

    // ── identity ───────────────────────────────────────────────────────────────────────────────────────────

    fn me(&self) -> (String, String, String) {
        (self.trust.did().unwrap_or_default().to_string(), self.trust.own_device_id(), self.trust.signing_method().unwrap_or_default())
    }

    fn binding(&self, member: &Member) -> Result<Value, String> {
        let (did, device, vm) = self.me();
        let t = now();
        let u = binding::unsigned_binding(&did, &device, &vm, &member.leaf_signature_key_b64u(), &ts(t), &ts(t + chrono::Duration::days(PACKAGE_DAYS))).map_err(|e| e.0)?;
        binding::sign(&u, self.trust.signing_key(), &ts(t)).map_err(|e| e.0)
    }

    fn key_package(&self, member: &mut Member) -> Result<Value, String> {
        let (did, device, _) = self.me();
        let b = self.binding(member)?;
        let bytes = member.key_package(&b).map_err(|e| e.0)?;
        Ok(json!({ "key_package_id": format!("kp-{}", uuid::Uuid::new_v4()), "owner_did": did, "owner_device_id": device, "suite": MTI_SUITE,
                   "mls_key_package_b64u": b64(&bytes), "did_wba_binding": b, "expires_at": ts(now() + chrono::Duration::days(PACKAGE_DAYS)) }))
    }

    fn service_meta(&self, op: &str) -> Value {
        let (did, device, _) = self.me();
        json!({ "profile": PROFILE, "security_profile": TRANSPORT_PROFILE, "sender_did": did, "sender_device_id": device, "target": { "kind": "service", "did": did }, "operation_id": op })
    }

    fn group_meta(&self, group_did: &str, op: &str) -> Value {
        let (did, device, _) = self.me();
        json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": did, "sender_device_id": device, "target": { "kind": "group", "did": group_did }, "operation_id": op })
    }

    fn origin_auth(&self, method: &str, meta: &Value, body: &Value) -> Result<Value, String> {
        let (_, _, vm) = self.me();
        let proof = origin::generate(method, meta, body, self.trust.signing_key(), &vm, now().timestamp(), None, &uuid::Uuid::new_v4().to_string()).map_err(|e| e.0)?;
        Ok(json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": proof }))
    }

    // ── persistence and the log ────────────────────────────────────────────────────────────────────────────

    fn save_member(&self) {
        let state = self.member.lock().unwrap().export_state();
        write_private(&self.member_file, &state);
    }

    fn save_groups(&self, g: &HashMap<String, GroupRec>) {
        write_private(&self.groups_file, &Value::Object(g.iter().map(|(k, v)| (k.clone(), v.to_json())).collect()));
    }

    fn update_group(&self, group_did: &str, f: impl FnOnce(&mut GroupRec)) {
        let mut g = self.groups.lock().unwrap();
        if let Some(rec) = g.get_mut(group_did) {
            f(rec);
        }
        self.save_groups(&g);
    }

    fn group(&self, group_did: &str) -> Result<GroupRec, String> {
        self.groups.lock().unwrap().get(group_did).cloned().ok_or_else(|| format!("this node is not in {group_did}"))
    }

    fn record(&self, group_did: &str, entry: Value) {
        let mut entry = entry;
        entry["group"] = json!(group_did);
        entry["at"] = json!(ts(now()));
        {
            let mut log = self.log.lock().unwrap();
            let msgs = log.entry(group_did.to_string()).or_default();
            msgs.push(entry.clone());
            if msgs.len() > LOG_PER_GROUP {
                let extra = msgs.len() - LOG_PER_GROUP;
                msgs.drain(..extra);
            }
            write_private(&self.log_file, &json!(*log));
        }
        let _ = self.events.send(entry);
    }

    /// Each logged event as it happens: `{group, kind: "message"|"membership", direction, ...}`.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Value> {
        self.events.subscribe()
    }

    /// The events of one group, oldest first.
    pub fn messages(&self, group_did: &str) -> Vec<Value> {
        self.log.lock().unwrap().get(group_did).cloned().unwrap_or_default()
    }

    /// The groups this node is in (or was removed from).
    pub fn groups(&self) -> Vec<Value> {
        let g = self.groups.lock().unwrap();
        let m = self.member.lock().unwrap();
        let mut out: Vec<Value> = g
            .iter()
            .map(|(did, r)| {
                let gid = B64U.decode(&r.gid).unwrap_or_default();
                let members: Vec<Value> = m.leaves(&gid).unwrap_or_default().iter().filter_map(|l| l.binding()).map(|b| json!({ "did": b["agent_did"], "device_id": b["device_id"] })).collect();
                json!({ "group_did": did, "role": r.role, "status": r.status, "version": r.version, "epoch": m.epoch(&gid), "members": if r.status == "active" { json!(members) } else { Value::Null } })
            })
            .collect();
        out.sort_by(|a, b| a["group_did"].as_str().cmp(&b["group_did"].as_str()));
        out
    }

    // ── talking to the host ────────────────────────────────────────────────────────────────────────────────

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let (trust, url, text) = (self.trust.clone(), format!("{}{path}", self.host), body.to_string());
        let (status, answer) = tokio::task::spawn_blocking(move || post_signed(&trust, &url, &text)).await.map_err(|e| e.to_string())??;
        let v: Value = serde_json::from_str(&answer).map_err(|_| format!("the host answered HTTP {status}: {}", answer.trim()))?;
        if status != 200 {
            return Err(format!("the host answered HTTP {status}: {v}"));
        }
        Ok(v)
    }

    /// One JSON-RPC call; the result, or the host's error as text.
    async fn rpc(&self, method: &str, meta: &Value, body: &Value, auth: Option<&Value>) -> Result<Value, String> {
        let req = wire::request(method, meta, body, auth).map_err(|e| format!("{method}: {}", e.0))?;
        let v = self.post("/anp/groups", json!({ "jsonrpc": "2.0", "id": op_id("rpc"), "method": req["method"], "params": req["params"] })).await?;
        match v.get("error") {
            Some(e) => Err(format!("{method} refused: {} {}", e["code"], e["message"].as_str().or(e["data"]["detail"].as_str()).unwrap_or(""))),
            None => Ok(v["result"].clone()),
        }
    }

    /// Publish a fresh key package (each one can be used by one welcome).
    pub async fn publish_key_package(&self) -> Result<(), String> {
        let kp = {
            let mut m = self.member.lock().unwrap();
            self.key_package(&mut m)?
        };
        self.save_member();
        let r = self.rpc(METHOD_PUBLISH_KEY_PACKAGE, &self.service_meta(&op_id("publish")), &json!({ "group_key_package": kp }), None).await?;
        wire::check_publish_key_package_result(&r).map_err(|e| e.0)?;
        log::info!("group member: published key package {}", kp["key_package_id"]);
        Ok(())
    }

    /// The group's DID document, from the host (it serves it at the path the DID names), checked.
    async fn fetch_group_doc(&self, group_did: &str) -> Option<Value> {
        let path = format!("/{}/did.json", group_did.split(':').skip(3).collect::<Vec<_>>().join("/"));
        let url = format!("{}{path}", self.host);
        let text = tokio::task::spawn_blocking(move || ureq::get(&url).timeout(Duration::from_secs(10)).call().ok().and_then(|r| r.into_string().ok())).await.ok()??;
        let doc: Value = serde_json::from_str(&text).ok()?;
        anp_did::verify_document(&doc, Some(group_did)).ok()?;
        Some(doc)
    }

    fn check_receipt(&self, group_did: &str, receipt: &Value) -> Result<(), String> {
        let doc = self.groups.lock().unwrap().get(group_did).and_then(|g| g.doc.clone());
        match doc {
            Some(d) => {
                let key = anp_group_host::receipt_key(&d).ok_or("the group's document has no receipt key")?;
                anp_did::verify_proof(receipt, &key).map_err(|e| format!("the host's receipt does not verify: {e}"))
            }
            None => Ok(()), // the host did not serve the group's document: nothing to check the receipt against
        }
    }

    /// A DID document: one the node was given, or one fetched from a trusted domain.
    async fn document(&self, did: &str) -> Option<Value> {
        if let Some(d) = self.docs.get(did) {
            return Some(d.clone());
        }
        let d = self.domains.as_ref()?;
        if !d.allows(did) {
            return None;
        }
        d.resolve(did).await.ok().map(|r| r.document)
    }

    /// The device of `did` that can be in a group: the first one its document lists with the group profile.
    async fn group_device(&self, did: &str) -> Option<String> {
        let doc = self.document(did).await?;
        let devices = doc.pointer("/deviceManifest/devices")?.as_array()?.clone();
        devices.iter().find(|d| d["profiles"].as_array().map_or(false, |p| p.iter().any(|x| x == binding::PROFILE_GROUP_E2EE_V2))).and_then(|d| d["device_id"].as_str()).map(str::to_string)
    }

    // ── what a controller does ─────────────────────────────────────────────────────────────────────────────

    /// Create a group named `name` on the host, with this node as its controller and only member. Returns the group DID.
    pub async fn create(&self, name: &str, max_members: Option<u64>) -> Result<String, String> {
        let _busy = self.busy.lock().await;
        let mut req = json!({ "name": name });
        if let Some(m) = max_members {
            req["max_members"] = json!(m);
        }
        let provisioned = self.post("/anp/groups/provision", req).await?;
        let group_did = provisioned["group_did"].as_str().ok_or("the host did not provision a group DID")?.to_string();
        let (kp, gid) = {
            let mut m = self.member.lock().unwrap();
            let kp = self.key_package(&mut m)?;
            let b = self.binding(&m)?;
            let gid = m.create_group(&b).map_err(|e| e.0)?;
            (kp, gid)
        };
        self.save_member();
        let meta = { let mut m = self.service_meta(&op_id("create")); m["security_profile"] = json!(SECURITY_PROFILE); m };
        let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE,
                           "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
        let auth = self.origin_auth(METHOD_CREATE, &meta, &body)?;
        let r = self.rpc(METHOD_CREATE, &meta, &body, Some(&auth)).await?;
        wire::check_create_result(&r).map_err(|e| e.0)?;
        let doc = match provisioned.get("document").filter(|d| d.is_object()) {
            Some(d) => anp_did::verify_document(d, Some(&group_did)).ok().map(|_| d.clone()),
            None => self.fetch_group_doc(&group_did).await,
        };
        {
            let mut g = self.groups.lock().unwrap();
            g.insert(group_did.clone(), GroupRec { gid: b64(&gid), version: 1, role: "controller".into(), status: "active".into(), doc });
            self.save_groups(&g);
        }
        self.record(&group_did, json!({ "kind": "membership", "event": "created", "by": self.me().0 }));
        log::info!("group member: created {group_did}");
        Ok(group_did)
    }

    /// Add `member_did` (its group device, from its DID document, unless `device_id` names one) to a group this node controls.
    pub async fn add(&self, group_did: &str, member_did: &str, device_id: Option<&str>) -> Result<(), String> {
        let _busy = self.busy.lock().await;
        let rec = self.group(group_did)?;
        let device = match device_id {
            Some(d) => d.to_string(),
            None => self.group_device(member_did).await.ok_or_else(|| format!("no group device known for {member_did} (give its DID document, or the device id)"))?,
        };
        let kp = self.rpc(METHOD_GET_KEY_PACKAGE, &self.service_meta(&op_id("get")), &json!({ "target_did": member_did, "target_device_id": device }), None).await?["group_key_package"].clone();
        if !kp.is_object() {
            return Err(format!("the host has no key package for {member_did}"));
        }
        let gid = B64U.decode(&rec.gid).map_err(|e| e.to_string())?;
        let meta = self.group_meta(group_did, &op_id("add"));
        let state = json!({ "group_did": group_did, "group_state_version": (rec.version + 1).to_string() });
        let (body, next) = {
            let mut m = self.member.lock().unwrap();
            let next = (m.epoch(&gid).ok_or("no MLS state for that group")? + 1).to_string();
            let ad = aad::add_submission_binding_for(&meta, member_did, &device, &state, &rec.gid, &next).map_err(|e| e.0)?;
            let out = m.add_member(&gid, &unb64(&kp["mls_key_package_b64u"], "the key package")?, &ad).map_err(|e| e.0)?;
            let body = json!({ "member_did": member_did, "member_device_id": device, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": rec.gid,
                               "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
            (body, next)
        };
        let r = match self.origin_auth(METHOD_ADD, &meta, &body) {
            Ok(auth) => self.rpc(METHOD_ADD, &meta, &body, Some(&auth)).await,
            Err(e) => Err(e),
        };
        self.settle_commit(&gid, group_did, r, "added", member_did, &device, &next).await
    }

    /// Remove `member_did` from a group this node controls.
    pub async fn remove(&self, group_did: &str, member_did: &str, device_id: Option<&str>) -> Result<(), String> {
        let _busy = self.busy.lock().await;
        let rec = self.group(group_did)?;
        let device = match device_id {
            Some(d) => d.to_string(),
            None => self.group_device(member_did).await.ok_or_else(|| format!("no group device known for {member_did}"))?,
        };
        let gid = B64U.decode(&rec.gid).map_err(|e| e.to_string())?;
        let meta = self.group_meta(group_did, &op_id("remove"));
        let state = json!({ "group_did": group_did, "group_state_version": (rec.version + 1).to_string() });
        let (body, next) = {
            let mut m = self.member.lock().unwrap();
            let next = (m.epoch(&gid).ok_or("no MLS state for that group")? + 1).to_string();
            let ad = aad::remove_submission_binding_for(&meta, member_did, &device, &state, &rec.gid, &next).map_err(|e| e.0)?;
            let commit = m.remove_member(&gid, member_did, &device, &ad).map_err(|e| e.0)?;
            (json!({ "member_did": member_did, "member_device_id": device, "group_state_ref": state, "crypto_group_id_b64u": rec.gid, "epoch": next, "commit_b64u": b64(&commit) }), next)
        };
        let r = match self.origin_auth(METHOD_REMOVE, &meta, &body) {
            Ok(auth) => self.rpc(METHOD_REMOVE, &meta, &body, Some(&auth)).await,
            Err(e) => Err(e),
        };
        self.settle_commit(&gid, group_did, r, "removed", member_did, &device, &next).await
    }

    /// The host's answer to a membership change: merge the pending commit, or throw it away.
    async fn settle_commit(&self, gid: &[u8], group_did: &str, r: Result<Value, String>, event: &str, who: &str, device: &str, epoch: &str) -> Result<(), String> {
        let outcome = r.and_then(|v| wire::check_membership_result(&v).map(|_| v).map_err(|e| e.0));
        match outcome {
            Ok(v) => {
                self.member.lock().unwrap().finalize_commit(gid).map_err(|e| e.0)?;
                self.save_member();
                let version = v["group_state_ref"]["group_state_version"].as_str().and_then(|x| x.parse().ok());
                self.update_group(group_did, |g| g.version = version.unwrap_or(g.version + 1));
                self.record(group_did, json!({ "kind": "membership", "event": event, "member": who, "device_id": device, "epoch": epoch, "by": self.me().0 }));
                Ok(())
            }
            Err(e) => {
                let _ = self.member.lock().unwrap().abort_commit(gid);
                self.save_member();
                Err(e)
            }
        }
    }

    // ── sending ────────────────────────────────────────────────────────────────────────────────────────────

    /// Send `plaintext` (`{application_content_type, text}` or a payload) to a group this node is an active member of.
    pub async fn send(&self, group_did: &str, plaintext: &Value) -> Result<String, String> {
        let _busy = self.busy.lock().await;
        let rec = self.group(group_did)?;
        if rec.status != "active" {
            return Err(format!("this node was removed from {group_did}"));
        }
        let gid = B64U.decode(&rec.gid).map_err(|e| e.to_string())?;
        let message_id = format!("msg-{}", uuid::Uuid::new_v4());
        let mut meta = self.group_meta(group_did, &op_id("send"));
        meta["message_id"] = json!(message_id);
        meta["content_type"] = json!(CIPHER_CONTENT_TYPE);
        let plain = aad::canonical_application_plaintext(plaintext).map_err(|e| e.0)?;
        let cipher = {
            let mut m = self.member.lock().unwrap();
            let epoch = m.epoch(&gid).ok_or("no MLS state for that group")?;
            let mut cipher = json!({ "crypto_group_id_b64u": rec.gid, "epoch": epoch.to_string(), "private_message_b64u": "AA", "group_state_ref": { "group_did": group_did, "group_state_version": rec.version.to_string() } });
            let ad = aad::send_authenticated_data(&meta, &cipher).map_err(|e| e.0)?;
            cipher["private_message_b64u"] = json!(b64(&m.encrypt(&gid, &plain, &ad).map_err(|e| e.0)?));
            cipher
        };
        self.save_member();
        let auth = self.origin_auth(METHOD_SEND, &meta, &cipher)?;
        let r = self.rpc(METHOD_SEND, &meta, &cipher, Some(&auth)).await?;
        wire::check_send_result(&r).map_err(|e| e.0)?;
        self.check_receipt(group_did, &r["group_receipt"])?;
        self.record(group_did, json!({ "kind": "message", "direction": "out", "message_id": message_id, "from": self.me().0, "plaintext": plaintext, "seq": r["group_event_seq"] }));
        Ok(message_id)
    }

    // ── the mailbox ────────────────────────────────────────────────────────────────────────────────────────

    /// Collect the mailbox once (waiting up to [`PULL_WAIT_MS`] for something), handle what came, acknowledge it next time.
    pub async fn collect(&self) -> Result<usize, String> {
        let (did, device, _) = self.me();
        let ack: Vec<String> = std::mem::take(&mut *self.acks.lock().unwrap());
        let v = self.post("/anp/groups", json!({ "jsonrpc": "2.0", "id": op_id("pull"), "method": "group.e2ee.pull",
                                                 "params": { "meta": { "sender_did": did, "sender_device_id": device }, "ack": ack, "wait_ms": PULL_WAIT_MS } })).await;
        let v = match v {
            Ok(v) => v,
            Err(e) => {
                self.acks.lock().unwrap().extend(ack); // not acknowledged: send them again next time
                return Err(e);
            }
        };
        if let Some(e) = v.get("error") {
            self.acks.lock().unwrap().extend(ack);
            return Err(format!("the host refused the pull: {e}"));
        }
        let notes = v["result"]["notifications"].as_array().cloned().unwrap_or_default();
        let n = notes.len();
        for note in notes {
            let id = s(&note["id"]);
            let _busy = self.busy.lock().await;
            if let Err(e) = self.handle(&note["notification"]).await {
                log::warn!("group member: notification {id}: {e}");
                if let Some(g) = note["notification"]["params"]["body"]["group_did"].as_str() {
                    self.record(g, json!({ "kind": "error", "notification": id, "error": e }));
                }
            }
            self.acks.lock().unwrap().push(id); // handled (or not handleable): either way, not again
        }
        Ok(n)
    }

    async fn handle(&self, n: &Value) -> Result<(), String> {
        match n["method"].as_str().unwrap_or("") {
            METHOD_NOTICE => {
                let (nmeta, body, _) = wire::parse_request(METHOD_NOTICE, n).map_err(|e| e.0)?;
                match body["notice_type"].as_str().unwrap_or("") {
                    "welcome-delivery" => self.on_welcome(&body).await,
                    "commit-delivery" => self.on_commit(&nmeta, &body).await,
                    other => Err(format!("unknown notice type {other}")),
                }
            }
            METHOD_INCOMING => self.on_message(n).await,
            other => Err(format!("unknown notification {other}")),
        }
    }

    async fn on_welcome(&self, body: &Value) -> Result<(), String> {
        let group_did = s(&body["group_did"]);
        let (gid, epoch) = {
            let mut m = self.member.lock().unwrap();
            m.join(&unb64(&body["welcome_b64u"], "the welcome")?, &unb64(&body["ratchet_tree_b64u"], "the ratchet tree")?).map_err(|e| e.0)?
        };
        self.save_member();
        if b64(&gid) != s(&body["crypto_group_id_b64u"]) {
            return Err("the welcome is for another crypto group than the notice says".into());
        }
        let version = body["group_state_ref"]["group_state_version"].as_str().and_then(|v| v.parse().ok()).unwrap_or(1);
        let doc = self.fetch_group_doc(&group_did).await;
        {
            let mut g = self.groups.lock().unwrap();
            g.insert(group_did.clone(), GroupRec { gid: b64(&gid), version, role: "member".into(), status: "active".into(), doc });
            self.save_groups(&g);
        }
        self.check_receipt(&group_did, &body["group_receipt"])?;
        self.record(&group_did, json!({ "kind": "membership", "event": "joined", "member": self.me().0, "epoch": epoch }));
        log::info!("group member: joined {group_did}");
        // that key package is used up: offer another
        if let Err(e) = self.publish_key_package().await {
            log::warn!("group member: could not publish a new key package: {e}");
        }
        Ok(())
    }

    async fn on_commit(&self, nmeta: &Value, body: &Value) -> Result<(), String> {
        let group_did = s(&body["group_did"]);
        let rec = self.group(&group_did)?;
        self.check_receipt(&group_did, &body["group_receipt"])?;
        let (me, my_device, _) = self.me();
        let (subject, subject_device, status) = (s(&body["subject_did"]), s(&body["subject_device_id"]), s(&body["subject_status"]));
        if subject == me && subject_device == my_device && status == "removed" {
            self.update_group(&group_did, |g| g.status = "removed".into());
            self.record(&group_did, json!({ "kind": "membership", "event": "removed", "member": me }));
            log::info!("group member: removed from {group_did}");
            return Ok(());
        }
        let gid = B64U.decode(&rec.gid).map_err(|e| e.to_string())?;
        let commit = unb64(&body["commit_b64u"], "the commit")?;
        let epoch = {
            let mut m = self.member.lock().unwrap();
            // the commit says which leaf made it; that leaf's binding says which device: the meta it signed the submission with
            let info = anp_group_mls::inspect_commit(&commit).map_err(|e| e.0)?;
            let committer = m.leaves(&gid).map_err(|e| e.0)?.into_iter().find(|l| l.leaf_index == info.sender_leaf).and_then(|l| l.binding()).ok_or("the commit's sender is not a leaf of the group")?;
            let bmeta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": committer["agent_did"], "sender_device_id": committer["device_id"],
                                "target": { "kind": "group", "did": group_did }, "operation_id": nmeta["operation_id"] });
            let f = if status == "removed" { aad::remove_submission_binding_for } else { aad::add_submission_binding_for };
            let expected = f(&bmeta, &subject, &subject_device, &body["group_state_ref"], &rec.gid, body["epoch"].as_str().unwrap_or("")).map_err(|e| e.0)?;
            m.process_commit(&gid, &commit, &expected).map_err(|e| e.0)?
        };
        self.save_member();
        let version = body["group_state_ref"]["group_state_version"].as_str().and_then(|v| v.parse().ok());
        self.update_group(&group_did, |g| g.version = version.unwrap_or(g.version + 1));
        let event = if status == "removed" { "removed" } else { "added" };
        self.record(&group_did, json!({ "kind": "membership", "event": event, "member": subject, "device_id": subject_device, "epoch": epoch }));
        Ok(())
    }

    async fn on_message(&self, n: &Value) -> Result<(), String> {
        let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, n).map_err(|e| e.0)?;
        let auth = auth.ok_or("a message without its origin proof")?;
        let group_did = s(&body["group_did"]);
        let rec = self.group(&group_did)?;
        let sender = s(&meta["sender_did"]);
        let sender_doc = self.document(&sender).await.ok_or_else(|| format!("no DID document for the sender {sender}"))?;
        origin::verify_incoming(&meta, &body, &auth, &sender_doc, Some(&sender)).map_err(|e| format!("the origin proof: {}", e.0))?;
        self.check_receipt(&group_did, &body["group_receipt"])?;
        let original = origin::reconstruct_send_request(&meta, &body, &auth).map_err(|e| e.0)?;
        let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).map_err(|e| e.0)?;
        let gid = B64U.decode(&rec.gid).map_err(|e| e.to_string())?;
        let (plain, leaf) = {
            let mut m = self.member.lock().unwrap();
            m.decrypt(&gid, &unb64(&body["group_cipher_object"]["private_message_b64u"], "the message")?, &ad).map_err(|e| e.0)?
        };
        self.save_member();
        // the MLS sender must be the device that signed the origin proof
        if leaf.binding().map_or(true, |b| b["agent_did"] != json!(sender)) {
            return Err("the message was encrypted by another member than the one who signed it".into());
        }
        let plaintext = aad::parse_application_plaintext(&plain).map_err(|e| e.0)?;
        if let Some(v) = body["group_state_version"].as_str().and_then(|v| v.parse().ok()) {
            self.update_group(&group_did, |g| g.version = v);
        }
        self.record(&group_did, json!({ "kind": "message", "direction": "in", "message_id": original["meta"]["message_id"], "from": sender, "plaintext": plaintext, "seq": body["group_event_seq"] }));
        Ok(())
    }
}
