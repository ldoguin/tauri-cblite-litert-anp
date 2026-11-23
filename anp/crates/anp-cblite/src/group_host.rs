//! The node as a group host for end-to-end encrypted groups (ANP-09 "P6", `--group-host`): `anp-group-host` behind HTTP, with the node's DID documents as its address book.
//!
//! * `POST /anp/groups` (also the old `/anp/p6`): JSON-RPC for `group.e2ee.publish_key_package`, `get_key_package`, `create`, `add`, `remove`, `send` and this project's
//!   `group.e2ee.pull` (a device collects its notifications and acknowledges the ones it has; with `wait_ms` (at most 30000) the request is held until
//!   something is delivered, which is this host's push).
//! * `POST /anp/groups/provision` `{"name": "blue"}`: make a group DID on this node's domain; the node keeps its key (it signs the group's
//!   receipts). The group's DID document is served at the usual path (`/groups/<name>/<e1_fingerprint>/did.json`).
//! * State (groups, key packages, mailboxes, group keys) is kept in `<data>/p6-host.json`.
//!
//! Who is who: a submission proves its sender with its own origin proof (checked against the sender's DID document), so the HTTP
//! layer does not have to. A mailbox is another matter: `pull` hands out notifications, so with `--require-auth` the HTTP caller
//! must be the device's DID, and the node refuses to run a P6 host without `--require-auth` unless started with `--group-open-mailboxes`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anp_group_host::{Docs, Host};
use serde_json::{json, Value};

use crate::httpauth::DomainTrust;

/// The node's address book: documents it was given, and those fetched from trusted domains.
pub struct NodeDocs {
    pub fixed: std::collections::HashMap<String, Value>,
    pub domains: Option<Arc<DomainTrust>>,
}

impl Docs for NodeDocs {
    fn document(&self, did: &str) -> Option<Value> {
        self.fixed.get(did).cloned().or_else(|| self.domains.as_ref().and_then(|d| d.cached(did)).map(|r| r.document))
    }
}

pub struct GroupHostService {
    host: Mutex<Host>,
    file: PathBuf,
    domains: Option<Arc<DomainTrust>>,
    fixed: std::collections::HashSet<String>,
    /// Woken after every accepted change, so a pull that asked to wait (`wait_ms`) returns as soon as something is delivered.
    delivered: tokio::sync::Notify,
}

fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

impl GroupHostService {
    /// `authority` is `host[:port]` of this node's DID; `docs` the documents it was given.
    pub fn new(authority: &str, dir: &std::path::Path, docs: Vec<Value>, domains: Option<Arc<DomainTrust>>) -> Result<GroupHostService, String> {
        let mut fixed = std::collections::HashMap::new();
        for d in docs {
            if let Some(id) = d["id"].as_str() {
                fixed.insert(id.to_string(), d.clone());
            }
        }
        let known: std::collections::HashSet<String> = fixed.keys().cloned().collect();
        let mut host = Host::new(authority, Arc::new(NodeDocs { fixed, domains: domains.clone() }), Box::new(now));
        crate::adopt_renamed_file(dir, "p6-host.json", "group-host.json");
        let file = dir.join("group-host.json");
        if let Ok(text) = std::fs::read_to_string(&file) {
            host.load(&serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?)?;
        }
        Ok(GroupHostService { host: Mutex::new(host), file, domains, fixed: known, delivered: tokio::sync::Notify::new() })
    }

    pub fn group_count(&self) -> usize {
        self.host.lock().unwrap().group_count()
    }

    fn save(&self, h: &Host) {
        let tmp = self.file.with_extension("tmp");
        let r = std::fs::write(&tmp, h.to_json().to_string()).and_then(|_| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&tmp, &self.file)
        });
        if let Err(e) = r {
            log::warn!("could not save the group host state: {e}");
        }
    }

    /// Every DID a request names, so that those on trusted domains can be fetched before the (synchronous) host looks at it.
    fn dids_in(req: &Value) -> Vec<String> {
        let p = &req["params"];
        let mut v = vec![];
        for x in [&p["meta"]["sender_did"], &p["body"]["member_did"], &p["body"]["target_did"], &p["body"]["creator_key_package"]["owner_did"], &p["body"]["group_key_package"]["owner_did"]] {
            if let Some(s) = x.as_str() {
                v.push(s.to_string());
            }
        }
        v
    }

    /// Handle one JSON-RPC request. `caller` is the DID that signed the HTTP request, when the node requires that.
    pub async fn handle(&self, req: Value, caller: Option<String>, require_caller: bool) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        if let Some(d) = &self.domains {
            for did in Self::dids_in(&req) {
                if !self.fixed.contains(&did) && d.allows(&did) {
                    if let Err(e) = d.resolve(&did).await {
                        log::warn!("group host: could not resolve {did}: {e}");
                    }
                }
            }
        }
        if (req["method"] == "group.e2ee.pull" || req["method"] == anp_group_host::METHOD_STATE) && require_caller && caller.as_deref() != req["params"]["meta"]["sender_did"].as_str() {
            return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": "a mailbox (and the group state) is read by the device's own DID (sign the request)" } });
        }
        let wait = if req["method"] == "group.e2ee.pull" { req["params"]["wait_ms"].as_u64().unwrap_or(0).min(30_000) } else { 0 };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait);
        loop {
            // register for the wake-up before looking, so a delivery in between is not missed
            let wake = self.delivered.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let resp = {
                let mut h = self.host.lock().unwrap();
                let resp = h.handle(&req);
                self.save(&h);
                resp
            };
            let empty = resp["result"]["notifications"].as_array().map_or(false, |a| a.is_empty());
            if wait == 0 || !empty || tokio::time::Instant::now() >= deadline {
                if req["method"] != "group.e2ee.pull" {
                    self.delivered.notify_waiters();
                }
                return resp;
            }
            let _ = tokio::time::timeout_at(deadline, wake).await;
        }
    }

    /// Make a group DID. Returns `{group_did}` and the document.
    pub fn provision(&self, name: &str, max_members: Option<u64>) -> Result<Value, String> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
        let mut h = self.host.lock().unwrap();
        let mut out = h.provision_with(name, seed, max_members)?;
        out["document"] = h.group_document(out["group_did"].as_str().unwrap_or("")).unwrap_or(Value::Null);
        self.save(&h);
        Ok(out)
    }

    pub fn group_document(&self, did: &str) -> Option<Value> {
        self.host.lock().unwrap().group_document(did)
    }

    // ── the WebSocket push channel (`GET /anp/groups/ws`) ───────────────────────────────────────────────────

    /// A wake-up for the next delivery. Call `.enable()` on it (pinned) *before* reading the mailbox, so a delivery in between is not missed.
    pub fn delivery_wake(&self) -> tokio::sync::futures::Notified<'_> {
        self.delivered.notified()
    }

    /// What waits for a device (id and notification), untouched.
    pub fn waiting(&self, did: &str, device: &str) -> Vec<(String, Value)> {
        self.host.lock().unwrap().waiting(did, device)
    }

    /// The device acknowledges what it has: those notifications are dropped.
    pub fn acknowledge(&self, did: &str, device: &str, ids: &[String]) {
        let mut h = self.host.lock().unwrap();
        h.acknowledge(did, device, ids);
        self.save(&h);
    }
}