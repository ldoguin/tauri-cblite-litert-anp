//! Who is asking: ANP-02 (RFC 9421) signed JSON-RPC requests, for a search agent that only takes registrations from the agent itself.
//!
//! With `--require-signed-registration` the methods that make the agent fetch (`register`, `crawl`, `refresh`) must come in a request signed
//! by a DID whose document the agent can fetch and verify (self-certifying, over the guarded resolver); `search`, `list` and `search_handle`
//! stay open. The signature covers the method, the exact public URL and the body, is fresh for a few minutes and is accepted once.
//! What the signer may do is decided by [`crate::Service`]: a description is registered or refreshed only by the DID it names, and a domain
//! is crawled only by a DID that lives on it.

use crate::Service;
use anp_httpauth::{Policy, ReplayCache, Request};

pub struct Authenticator {
    /// How callers address this agent (`https://host[:port]`, no trailing slash): what a signature has to name.
    origin: String,
    policy: Policy,
    replay: ReplayCache,
}

impl Authenticator {
    pub fn new(public_origin: &str) -> Authenticator {
        let policy = Policy::default();
        Authenticator { origin: public_origin.trim_end_matches('/').to_string(), replay: ReplayCache::new(&policy), policy }
    }

    /// The DID that signed a `POST /` with these `headers` and `body`, or why none did. Blocking: it may fetch the caller's DID document.
    pub fn caller(&self, service: &Service, headers: &[(String, String)], body: &[u8], now: i64) -> Result<String, String> {
        let signature_input = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("signature-input")).map(|(_, v)| v.as_str()).ok_or("this request is not signed (ANP-02 Signature-Input missing)")?;
        let key_id = anp_httpauth::key_id_of(signature_input).ok_or("the signature names no keyid")?;
        let did = key_id.split('#').next().unwrap_or_default().to_string();
        let doc = service.did_document(&did).map_err(|e| format!("cannot resolve {did}: {e}"))?;
        let url = format!("{}/", self.origin);
        let req = Request { method: "POST", url: &url, headers, body };
        let verified = anp_httpauth::verify(&req, &|k| anp_did::authentication_key(&doc.document, k), &self.policy, now).map_err(|e| e.0)?;
        if verified.did != did {
            return Err("the key id and the signer disagree".into());
        }
        if !self.replay.accept(&verified, now) {
            return Err("this signed request was already used".into());
        }
        Ok(verified.did)
    }
}
