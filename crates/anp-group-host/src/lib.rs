//! The P6 **group host**: the service in the middle of a group. It is not a member and holds no group secret; what it does is
//! **order** and **relay** and **vouch**:
//!
//! * a **key service** for devices (`publish_key_package`, `get_key_package`): a package is checked when it is published (the binding
//!   against the device's DID document and against the MLS leaf inside the package) and used once;
//! * **groups**: `create` (the host provisioned the group DID and holds its key), `add` and `remove` (only the group's controller, the
//!   creator; the commit must carry the submission binding as its authenticated data and be framed in the current epoch; the group
//!   state version it names must be the next one, the version it creates), `send` (only members, in the current epoch);
//! * every submission carries the sender's **origin proof**, verified here against the sender's DID document;
//! * **delivery**: each accepted change or message becomes a notification in the mailbox of every device that must see it
//!   (`group.e2ee.notice` with a welcome or a commit, `group.incoming` with the ciphertext and the preserved proof), and a device
//!   collects its mailbox with `group.e2ee.pull` (this project's way of pushing: the spec leaves the transport open);
//! * **receipts**: an object proof by the *group's* DID key over what was accepted (`group_receipt`), which is why the host holds the
//!   group DID's key: it provisions group DIDs (`group.e2ee.provision`, also this project's own method) and serves their documents.
//!
//! The host decides nothing about MLS content: it cannot read a message and does not process a commit. It checks what it can see
//! (framing, authenticated data, bindings, proofs, ordering) and refuses what cannot be right.

use anp_did::{SigningKey, VerifyingKey};
use anp_group::binding::{self, LeafEvidence};
use anp_group::{aad, origin, rpc_error, state, wire, *};

/// This project's method: a member asks for the group's current state, signed by the group's key (roster, policy, hashes).
pub const METHOD_STATE: &str = "group.e2ee.state";
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Where the host finds DID documents (those it was given, and those fetched from trusted domains).
pub trait Docs: Send + Sync {
    fn document(&self, did: &str) -> Option<Value>;
}

/// A fixed set of documents (tests, and nodes started with `--allow-caller`).
#[derive(Default, Clone)]
pub struct StaticDocs(pub HashMap<String, Value>);

impl Docs for StaticDocs {
    fn document(&self, did: &str) -> Option<Value> {
        self.0.get(did).cloned()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Package {
    value: Value,
    consumed: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct Member {
    did: String,
    device: String,
    leaf_key: String,
}

#[derive(Debug, Clone, PartialEq)]
struct Group {
    crypto_group_id: String,
    epoch: u64,
    version: u64,
    seq: u64,
    controller: (String, String),
    members: Vec<Member>,
}

struct Identity {
    key: SigningKey,
    document: Value,
    /// The group's policy (see `anp_group::state`): at most this many members, when set.
    max_members: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
struct Delivery {
    id: String,
    did: String,
    device: String,
    notification: Value,
}

pub struct Host {
    docs: Arc<dyn Docs>,
    now: Box<dyn Fn() -> String + Send + Sync>,
    /// DID `host` part groups are provisioned under (`host[:port]`), and where documents are served.
    authority: String,
    identities: HashMap<String, Identity>,
    groups: HashMap<String, Group>,
    /// Key packages by `(did, device)`.
    packages: HashMap<(String, String), Vec<Package>>,
    mailboxes: Vec<Delivery>,
    counter: u64,
}

type Fail = (i32, String);

fn fail<T>(code: i32, detail: impl Into<String>) -> Result<T, Fail> {
    Err((code, detail.into()))
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl Host {
    pub fn new(authority: &str, docs: Arc<dyn Docs>, now: Box<dyn Fn() -> String + Send + Sync>) -> Host {
        Host { docs, now, authority: authority.to_ascii_lowercase(), identities: HashMap::new(), groups: HashMap::new(), packages: HashMap::new(), mailboxes: vec![], counter: 0 }
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// The DID document of a group DID this host provisioned.
    pub fn group_document(&self, did: &str) -> Option<Value> {
        self.identities.get(did).map(|i| i.document.clone())
    }

    /// Pending notifications for a device.
    pub fn pending(&self, did: &str, device: &str) -> usize {
        self.mailboxes.iter().filter(|d| d.did == did && d.device == device).count()
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("{prefix}-{}", self.counter)
    }

    /// Make a group DID: a key the host keeps, a DID document it serves.
    pub fn provision(&mut self, name: &str, seed: [u8; 32]) -> Result<Value, String> {
        self.provision_with(name, seed, None)
    }

    /// Like [`Host::provision`], with a policy: the group never has more than `max_members` members.
    pub fn provision_with(&mut self, name: &str, seed: [u8; 32], max_members: Option<u64>) -> Result<Value, String> {
        if max_members == Some(0) {
            return Err("max_members must be at least 1".into());
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err("a group name is lowercase letters, digits and hyphens".into());
        }
        let key = SigningKey::from_bytes(&seed);
        let (host, port) = match self.authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
            None => (self.authority.clone(), None),
        };
        let did = anp_did::did_for_key(&host, port, &["groups", name], &key.verifying_key().to_bytes());
        if self.identities.contains_key(&did) {
            return Err("that group DID exists".into());
        }
        let doc = anp_did::build_document(&did, &key, &[], &(self.now)()).map_err(|e| e.to_string())?;
        self.identities.insert(did.clone(), Identity { key, document: doc, max_members });
        Ok(json!({ "group_did": did, "policy_hash": state::policy_hash(max_members) }))
    }

    // ── the JSON-RPC surface ──────────────────────────────────────────────────────────────────────────────

    /// Handle one request (a JSON-RPC envelope, or just `{method, params}`): the response object.
    pub fn handle(&mut self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let call = json!({ "method": request["method"], "params": request["params"] });
        let method = s(&request["method"]);
        let result = match method.as_str() {
            METHOD_PUBLISH_KEY_PACKAGE => self.publish(&call),
            METHOD_GET_KEY_PACKAGE => self.get_package(&call),
            METHOD_CREATE => self.create(&call),
            METHOD_ADD => self.membership(&call, true),
            METHOD_REMOVE => self.membership(&call, false),
            METHOD_SEND => self.send(&call),
            "group.e2ee.pull" => self.pull(&call),
            METHOD_STATE => self.state(&call),
            m => fail(-32601, format!("method not found: {m}")),
        };
        match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": if code <= -32000 { json!({ "code": code, "message": msg }) } else { rpc_error(code, &msg) } }),
        }
    }

    fn doc_of(&self, did: &str) -> Result<Value, Fail> {
        self.docs.document(did).ok_or_else(|| (5002, format!("no DID document for {did}")))
    }

    fn parse(&self, method: &str, call: &Value) -> Result<(Value, Value, Option<Value>), Fail> {
        wire::parse_request(method, call).map_err(|e| (-32602, e.0))
    }

    /// The origin proof of a submission, against the sender's document.
    fn check_origin(&self, method: &str, meta: &Value, body: &Value, auth: &Option<Value>) -> Result<Value, Fail> {
        let sender = s(&meta["sender_did"]);
        let doc = self.doc_of(&sender)?;
        let auth = auth.as_ref().ok_or((-32602, "auth is required".to_string()))?;
        origin::verify(&auth["origin_proof"], method, meta, body, &doc, Some(&sender)).map_err(|e| (5002, format!("the origin proof does not verify: {}", e.0)))?;
        Ok(doc)
    }

    /// A key package object checked against its owner's document and the MLS leaf inside it.
    fn check_package(&self, kp: &Value) -> Result<LeafEvidence, Fail> {
        let owner = s(&kp["owner_did"]);
        let doc = self.doc_of(&owner)?;
        let bytes = B64U.decode(s(&kp["mls_key_package_b64u"])).map_err(|_| (5001, "the key package is not base64url".to_string()))?;
        let ev = anp_group_mls::inspect_key_package(&bytes).map_err(|e| (5001, format!("the MLS key package is not valid: {e}")))?;
        binding::verify(&kp["did_wba_binding"], &doc, &ev, &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT], &(self.now)(), true).map_err(|e| (5002, e.0))?;
        Ok(ev)
    }

    fn publish(&mut self, call: &Value) -> Result<Value, Fail> {
        let (meta, body, _) = self.parse(METHOD_PUBLISH_KEY_PACKAGE, call)?;
        let kp = body["group_key_package"].clone();
        self.check_package(&kp)?;
        let key = (s(&meta["sender_did"]), s(&meta["sender_device_id"]));
        let list = self.packages.entry(key.clone()).or_default();
        if list.iter().any(|p| p.value["key_package_id"] == kp["key_package_id"]) {
            return fail(5012, "that key package id is already published");
        }
        list.push(Package { value: kp.clone(), consumed: false });
        Ok(json!({ "published": true, "owner_did": key.0, "owner_device_id": key.1, "key_package_id": kp["key_package_id"], "published_at": (self.now)() }))
    }

    fn get_package(&mut self, call: &Value) -> Result<Value, Fail> {
        let (_, body, _) = self.parse(METHOD_GET_KEY_PACKAGE, call)?;
        let key = (s(&body["target_did"]), s(&body["target_device_id"]));
        let p = self.packages.get(&key).and_then(|l| l.iter().find(|p| !p.consumed)).ok_or((5000, "no unused key package for that device".to_string()))?;
        Ok(json!({ "target_did": key.0, "target_device_id": key.1, "group_key_package": p.value }))
    }

    fn create(&mut self, call: &Value) -> Result<Value, Fail> {
        let (meta, body, auth) = self.parse(METHOD_CREATE, call)?;
        let group_did = s(&body["group_did"]);
        if !self.identities.contains_key(&group_did) {
            return fail(5004, "this host did not provision that group DID");
        }
        if self.groups.contains_key(&group_did) {
            return fail(5004, "that group already exists");
        }
        self.check_origin(METHOD_CREATE, &meta, &body, &auth)?;
        let ev = self.check_package(&body["creator_key_package"])?;
        let creator = (s(&meta["sender_did"]), s(&meta["sender_device_id"]));
        let group = Group {
            crypto_group_id: s(&body["crypto_group_id_b64u"]),
            epoch: 0,
            version: 1,
            seq: 0,
            controller: creator.clone(),
            members: vec![Member { did: creator.0, device: creator.1, leaf_key: ev.leaf_signature_key_b64u }],
        };
        let sref = state_ref(&group_did, group.version);
        let result = json!({ "created": true, "group_did": group_did, "group_state_ref": sref, "crypto_group_id_b64u": group.crypto_group_id, "epoch": "0", "accepted_at": (self.now)() });
        self.groups.insert(group_did, group);
        Ok(result)
    }

    fn membership(&mut self, call: &Value, adding: bool) -> Result<Value, Fail> {
        let method = if adding { METHOD_ADD } else { METHOD_REMOVE };
        let (meta, body, auth) = self.parse(method, call)?;
        let group_did = s(&meta["target"]["did"]);
        let group = self.groups.get(&group_did).cloned().ok_or((5004, "no such group here".to_string()))?;
        let sender = (s(&meta["sender_did"]), s(&meta["sender_device_id"]));
        if sender != group.controller {
            return fail(5003, "only the group's controller changes its membership");
        }
        let max_members = self.identities.get(&group_did).and_then(|i| i.max_members);
        self.check_origin(method, &meta, &body, &auth)?;
        if s(&body["crypto_group_id_b64u"]) != group.crypto_group_id {
            return fail(5006, "that is not this group's crypto group id");
        }
        // the submission names the state it creates (the version after this change): the commit's authenticated data binds it, and the
        // notices and the receipt carry the same reference
        if body["group_state_ref"]["group_state_version"] != (group.version + 1).to_string() {
            return fail(5005, format!("the group state is at version {}; a membership change creates version {}", group.version, group.version + 1));
        }
        let new_epoch = group.epoch + 1;
        if body["epoch"] != new_epoch.to_string() {
            return fail(5005, format!("the next epoch is {new_epoch}"));
        }
        let member = (s(&body["member_did"]), s(&body["member_device_id"]));
        // the commit: a public message in the current epoch, by a member, carrying the submission binding
        let expected = if adding { aad::add_submission_binding(&meta, &body) } else { aad::remove_submission_binding(&meta, &body) }.map_err(|e| (5008, e.0))?;
        let commit_bytes = B64U.decode(s(&body["commit_b64u"])).map_err(|_| (5008, "the commit is not base64url".to_string()))?;
        let info = anp_group_mls::inspect_commit(&commit_bytes).map_err(|e| (5008, e.0))?;
        if !info.is_commit {
            return fail(5008, "that is not a commit");
        }
        if B64U.encode(&info.group_id) != group.crypto_group_id {
            return fail(5006, "the commit is for another crypto group");
        }
        if info.epoch != group.epoch {
            return fail(5005, format!("the commit is framed in epoch {}, the group is in {}", info.epoch, group.epoch));
        }
        if info.authenticated_data != expected {
            return fail(5008, "the commit's authenticated data is not the submission binding");
        }
        let mut group = group;
        let mut new_member_package = None;
        if adding {
            if group.members.iter().any(|m| (m.did.clone(), m.device.clone()) == member) {
                return fail(5013, "that device is already a member");
            }
            let kp = body["group_key_package"].clone();
            let published = self.packages.get(&member).and_then(|l| l.iter().find(|p| p.value["key_package_id"] == kp["key_package_id"])).ok_or((5000, "that key package was not published here".to_string()))?;
            if published.consumed {
                return fail(5012, "that key package was already used");
            }
            if published.value["mls_key_package_b64u"] != kp["mls_key_package_b64u"] {
                return fail(5001, "that is not the key package that was published under that id");
            }
            let ev = self.check_package(&kp)?;
            if group.members.iter().any(|m| m.leaf_key == ev.leaf_signature_key_b64u) {
                return fail(5013, "that leaf key is already in the group");
            }
            for b in [&body["welcome_b64u"], &body["ratchet_tree_b64u"]] {
                if B64U.decode(s(b)).map_or(true, |x| x.is_empty()) {
                    return fail(5009, "the welcome and the ratchet tree must be base64url");
                }
            }
            if let Some(max) = max_members {
                if group.members.len() as u64 >= max {
                    return fail(-32010, format!("group policy: this group has at most {max} members"));
                }
            }
            group.members.push(Member { did: member.0.clone(), device: member.1.clone(), leaf_key: ev.leaf_signature_key_b64u });
            new_member_package = Some(kp["key_package_id"].clone());
        } else {
            let before = group.members.len();
            group.members.retain(|m| (m.did.clone(), m.device.clone()) != member);
            if group.members.len() == before {
                return fail(5013, "that device is not a member");
            }
            if member == group.controller {
                return fail(5003, "the controller cannot remove itself");
            }
        }
        // a state reference that carries the hashes names the roster after this change and this group's policy: it must be right
        state::check_hashes(&body["group_state_ref"], max_members, &entries(&group)).map_err(|e| (5005, e))?;
        group.epoch = new_epoch;
        group.version += 1;
        // the reference goes out as the controller wrote it (the commit's authenticated data binds it, and a recipient compares it with the notice)
        let sref = body["group_state_ref"].clone();
        let accepted_at = (self.now)();
        let receipt = self.receipt(&group_did, group.version, method, &s(&meta["operation_id"]), &sender.0, &accepted_at, &s(&auth.as_ref().unwrap()["origin_proof"]["contentDigest"]), None)?;
        // delivery: the new member gets the welcome; the others (not the committer) get the commit
        let recipients: Vec<(String, String)> = group.members.iter().map(|m| (m.did.clone(), m.device.clone())).filter(|r| *r != sender).collect();
        let mut out = Vec::new();
        for r in recipients {
            let welcome = adding && r == member;
            let mut notice = json!({
                "notice_id": self.next_id("notice"), "notice_type": if welcome { "welcome-delivery" } else { "commit-delivery" },
                "group_did": group_did, "group_state_ref": sref, "crypto_group_id_b64u": group.crypto_group_id, "epoch": new_epoch.to_string(),
                "subject_did": member.0, "subject_device_id": member.1, "subject_status": if adding { "active" } else { "removed" }, "group_receipt": receipt,
            });
            if welcome {
                notice["welcome_b64u"] = body["welcome_b64u"].clone();
                notice["ratchet_tree_b64u"] = body["ratchet_tree_b64u"].clone();
            } else {
                notice["commit_b64u"] = body["commit_b64u"].clone();
            }
            out.push((r, notice));
        }
        if !adding {
            // the removed device learns it was removed (it was a member of the epoch the commit is framed in)
            out.push((member.clone(), json!({
                "notice_id": self.next_id("notice"), "notice_type": "commit-delivery", "group_did": group_did, "group_state_ref": sref,
                "crypto_group_id_b64u": group.crypto_group_id, "epoch": new_epoch.to_string(), "subject_did": member.0, "subject_device_id": member.1,
                "subject_status": "removed", "commit_b64u": body["commit_b64u"], "group_receipt": receipt,
            })));
        }
        for (r, notice) in out {
            let nmeta = json!({ "anp_version": "2.0", "profile": PROFILE, "security_profile": TRANSPORT_PROFILE, "sender_did": group_did, "target": { "kind": "agent", "did": r.0 }, "recipient_device_id": r.1, "operation_id": meta["operation_id"], "created_at": accepted_at });
            let n = wire::request(METHOD_NOTICE, &nmeta, &notice, None).map_err(|e| (5011, format!("the host built an invalid notice: {}", e.0)))?;
            let id = self.next_id("d");
            self.mailboxes.push(Delivery { id, did: r.0, device: r.1, notification: n });
        }
        if let Some(id) = new_member_package {
            if let Some(p) = self.packages.get_mut(&member).and_then(|l| l.iter_mut().find(|p| p.value["key_package_id"] == id)) {
                p.consumed = true;
            }
        }
        let result = json!({ "accepted": true, "group_did": group_did, "member_did": member.0, "member_device_id": member.1, "group_state_ref": sref, "crypto_group_id_b64u": group.crypto_group_id, "epoch": new_epoch.to_string(), "accepted_at": accepted_at });
        self.groups.insert(group_did, group);
        Ok(result)
    }

    fn send(&mut self, call: &Value) -> Result<Value, Fail> {
        let (meta, body, auth) = self.parse(METHOD_SEND, call)?;
        let group_did = s(&meta["target"]["did"]);
        let group = self.groups.get(&group_did).cloned().ok_or((5004, "no such group here".to_string()))?;
        let sender = (s(&meta["sender_did"]), s(&meta["sender_device_id"]));
        if !group.members.iter().any(|m| (m.did.clone(), m.device.clone()) == sender) {
            return fail(5013, "the sender is not a current member of the group");
        }
        self.check_origin(METHOD_SEND, &meta, &body, &auth)?;
        if s(&body["crypto_group_id_b64u"]) != group.crypto_group_id {
            return fail(5006, "that is not this group's crypto group id");
        }
        if body["epoch"] != group.epoch.to_string() {
            return fail(5005, format!("the group is in epoch {}", group.epoch));
        }
        if body["group_state_ref"]["group_state_version"] != group.version.to_string() {
            return fail(5005, format!("the group state is at version {}", group.version));
        }
        let max_members = self.identities.get(&group_did).and_then(|i| i.max_members);
        state::check_hashes(&body["group_state_ref"], max_members, &entries(&group)).map_err(|e| (5005, e))?;
        let mut group = group;
        group.seq += 1;
        let accepted_at = (self.now)();
        let receipt = self.receipt(&group_did, group.version, METHOD_SEND, &s(&meta["operation_id"]), &sender.0, &accepted_at, &s(&auth.as_ref().unwrap()["origin_proof"]["contentDigest"]), Some(group.seq))?;
        // what the recipients need to rebuild the original submission: the target and the timestamp are rewritten by delivery
        let mut extra = Map::new();
        if let Some(v) = meta.get("anp_version") {
            extra.insert("anp_version".into(), v.clone());
        }
        let mut context = Map::new();
        if let Some(c) = meta.get("created_at") {
            context.insert("created_at".into(), c.clone());
        }
        if !extra.is_empty() {
            context.insert("extra_meta".into(), Value::Object(extra));
        }
        let recipients: Vec<(String, String)> = group.members.iter().map(|m| (m.did.clone(), m.device.clone())).filter(|r| *r != sender).collect();
        for r in recipients {
            let mut imeta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": sender.0, "sender_device_id": sender.1, "target": { "kind": "agent", "did": r.0 }, "recipient_device_id": r.1, "operation_id": meta["operation_id"], "message_id": meta["message_id"], "content_type": CIPHER_CONTENT_TYPE, "created_at": accepted_at });
            if let Some(v) = meta.get("anp_version") {
                imeta["anp_version"] = v.clone();
            }
            let ibody = json!({ "group_did": group_did, "group_state_version": group.version.to_string(), "group_event_seq": group.seq.to_string(), "accepted_at": accepted_at, "group_receipt": receipt, "group_cipher_object": body });
            let iauth = json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": auth.as_ref().unwrap()["origin_proof"], "origin_context": Value::Object(context.clone()) });
            let n = wire::request(METHOD_INCOMING, &imeta, &ibody, Some(&iauth)).map_err(|e| (5011, format!("the host built an invalid delivery: {}", e.0)))?;
            let id = self.next_id("d");
            self.mailboxes.push(Delivery { id, did: r.0, device: r.1, notification: n });
        }
        let result = json!({ "accepted": true, "group_did": group_did, "message_id": meta["message_id"], "operation_id": meta["operation_id"], "group_event_seq": group.seq.to_string(), "group_state_version": group.version.to_string(), "accepted_at": accepted_at, "epoch": group.epoch.to_string(), "group_receipt": receipt });
        self.groups.insert(group_did, group);
        Ok(result)
    }

    /// The group's receipt for something it accepted: an object proof by the group DID's key.
    #[allow(clippy::too_many_arguments)]
    fn receipt(&self, group_did: &str, version: u64, method: &str, operation_id: &str, actor: &str, accepted_at: &str, payload_digest: &str, seq: Option<u64>) -> Result<Value, Fail> {
        let mut r = json!({ "receipt_type": "group.e2ee.accepted", "group_did": group_did, "group_state_version": version.to_string(), "subject_method": method, "operation_id": operation_id, "actor_did": actor, "accepted_at": accepted_at, "payload_digest": payload_digest });
        if let Some(n) = seq {
            r["group_event_seq"] = json!(n.to_string());
        }
        self.sign_as_group(group_did, r, accepted_at)
    }

    /// An object proof by the group DID's key.
    fn sign_as_group(&self, group_did: &str, mut obj: Value, at: &str) -> Result<Value, Fail> {
        let id = self.identities.get(group_did).ok_or((5004, "no group identity".to_string()))?;
        let vm = format!("{group_did}#{}", anp_did::thumbprint(&id.key.verifying_key().to_bytes()));
        anp_did::add_proof(&mut obj, &id.key, &vm, "assertionMethod", at, &Map::new()).map_err(|e| (5011, e.to_string()))?;
        Ok(obj)
    }

    /// `group.e2ee.state` (this project's method): the group's state as the host sees it, signed by the group's key: version, epoch, last
    /// event number, controller, policy, roster and the two hashes (`anp_group::state`). A member asks, with `params.meta` naming itself
    /// and `params.group_did`; a device that is not a member is refused (5013). The node requires the HTTP caller to be that DID.
    fn state(&self, call: &Value) -> Result<Value, Fail> {
        let p = &call["params"];
        let (did, device) = (s(&p["meta"]["sender_did"]), s(&p["meta"]["sender_device_id"]));
        let group_did = s(&p["group_did"]);
        let group = self.groups.get(&group_did).ok_or((5004, "no such group here".to_string()))?;
        if !group.members.iter().any(|m| m.did == did && m.device == device) {
            return fail(5013, "only a current member of the group may ask for its state");
        }
        let max = self.identities.get(&group_did).and_then(|i| i.max_members);
        let e = entries(group);
        let now = (self.now)();
        let obj = json!({
            "receipt_type": "group.e2ee.state", "group_did": group_did, "group_state_version": group.version.to_string(), "epoch": group.epoch.to_string(),
            "group_event_seq": group.seq.to_string(), "controller": { "did": group.controller.0, "device_id": group.controller.1 },
            "max_members": max, "policy_hash": state::policy_hash(max), "roster_hash": state::roster_hash(&e),
            "members": group.members.iter().map(|m| json!({ "did": m.did, "device_id": m.device, "leaf_key": m.leaf_key })).collect::<Vec<_>>(),
            "accepted_at": now,
        });
        self.sign_as_group(&group_did, obj, &now)
    }

    /// Notifications waiting for a device, without touching them (the WebSocket push reads them this way and acknowledges separately).
    pub fn waiting(&self, did: &str, device: &str) -> Vec<(String, Value)> {
        self.mailboxes.iter().filter(|d| d.did == did && d.device == device).map(|d| (d.id.clone(), d.notification.clone())).collect()
    }

    /// Drop the notifications a device has acknowledged.
    pub fn acknowledge(&mut self, did: &str, device: &str, ids: &[String]) {
        self.mailboxes.retain(|d| !(d.did == did && d.device == device && ids.contains(&d.id)));
    }

    /// `group.e2ee.pull` (this project's method): the notifications waiting for a device, after dropping those it acknowledges.
    /// Params: `meta: {sender_did, sender_device_id}`, `ack: [ids]` (optional).
    fn pull(&mut self, call: &Value) -> Result<Value, Fail> {
        let p = &call["params"];
        let (did, device) = (s(&p["meta"]["sender_did"]), s(&p["meta"]["sender_device_id"]));
        if did.is_empty() || device.is_empty() {
            return fail(-32602, "meta.sender_did and meta.sender_device_id are required");
        }
        let acks: Vec<String> = p["ack"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
        self.mailboxes.retain(|d| !(d.did == did && d.device == device && acks.contains(&d.id)));
        let notes: Vec<Value> = self.mailboxes.iter().filter(|d| d.did == did && d.device == device).map(|d| json!({ "id": d.id, "notification": d.notification })).collect();
        Ok(json!({ "notifications": notes }))
    }

    // ── keeping state ─────────────────────────────────────────────────────────────────────────────────────

    pub fn to_json(&self) -> Value {
        let groups: Map<String, Value> = self.groups.iter().map(|(k, g)| (k.clone(), json!({ "crypto_group_id": g.crypto_group_id, "epoch": g.epoch, "version": g.version, "seq": g.seq, "controller": [g.controller.0, g.controller.1], "members": g.members.iter().map(|m| json!([m.did, m.device, m.leaf_key])).collect::<Vec<_>>() }))).collect();
        let ids: Map<String, Value> = self.identities.iter().map(|(k, i)| (k.clone(), json!({ "seed": B64U.encode(i.key.to_bytes()), "document": i.document, "max_members": i.max_members }))).collect();
        let pk: Vec<Value> = self.packages.iter().map(|((d, v), l)| json!({ "did": d, "device": v, "packages": l.iter().map(|p| json!({ "value": p.value, "consumed": p.consumed })).collect::<Vec<_>>() })).collect();
        let mail: Vec<Value> = self.mailboxes.iter().map(|d| json!({ "id": d.id, "did": d.did, "device": d.device, "notification": d.notification })).collect();
        json!({ "counter": self.counter, "groups": groups, "identities": ids, "packages": pk, "mailboxes": mail })
    }

    pub fn load(&mut self, v: &Value) -> Result<(), String> {
        self.counter = v["counter"].as_u64().unwrap_or(0);
        for (k, g) in v["groups"].as_object().into_iter().flatten() {
            let members = g["members"].as_array().into_iter().flatten().map(|m| Member { did: s(&m[0]), device: s(&m[1]), leaf_key: s(&m[2]) }).collect();
            self.groups.insert(k.clone(), Group { crypto_group_id: s(&g["crypto_group_id"]), epoch: g["epoch"].as_u64().unwrap_or(0), version: g["version"].as_u64().unwrap_or(1), seq: g["seq"].as_u64().unwrap_or(0), controller: (s(&g["controller"][0]), s(&g["controller"][1])), members });
        }
        for (k, i) in v["identities"].as_object().into_iter().flatten() {
            let seed: [u8; 32] = B64U.decode(s(&i["seed"])).map_err(|e| e.to_string())?.try_into().map_err(|_| "a stored group key must be 32 bytes".to_string())?;
            self.identities.insert(k.clone(), Identity { key: SigningKey::from_bytes(&seed), document: i["document"].clone(), max_members: i["max_members"].as_u64() });
        }
        for e in v["packages"].as_array().into_iter().flatten() {
            let list = e["packages"].as_array().into_iter().flatten().map(|p| Package { value: p["value"].clone(), consumed: p["consumed"].as_bool().unwrap_or(false) }).collect();
            self.packages.insert((s(&e["did"]), s(&e["device"])), list);
        }
        for d in v["mailboxes"].as_array().into_iter().flatten() {
            self.mailboxes.push(Delivery { id: s(&d["id"]), did: s(&d["did"]), device: s(&d["device"]), notification: d["notification"].clone() });
        }
        Ok(())
    }
}

/// A group's roster as `anp_group::state` hashes it.
fn entries(g: &Group) -> Vec<state::Entry> {
    g.members.iter().map(|m| (m.did.clone(), m.device.clone(), m.leaf_key.clone())).collect()
}

fn state_ref(group_did: &str, version: u64) -> Value {
    json!({ "group_did": group_did, "group_state_version": version.to_string() })
}

/// The verifying key of a group's receipts, for a client that has the group's document (convenience for tests and tools).
pub fn receipt_key(group_document: &Value) -> Option<VerifyingKey> {
    let id = group_document["assertionMethod"][0].as_str()?;
    anp_did::authentication_key(group_document, id).or_else(|| {
        let m = group_document["verificationMethod"].as_array()?.iter().find(|m| m["id"].as_str() == Some(id))?;
        VerifyingKey::from_bytes(&anp_did::decode_multibase(m["publicKeyMultibase"].as_str()?).ok()?).ok()
    })
}