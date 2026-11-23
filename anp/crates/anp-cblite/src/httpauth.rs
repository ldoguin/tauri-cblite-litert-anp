//! ANP-02 for the node's own HTTP API: when switched on, every request except the public documents must carry an HTTP
//! Message Signature (RFC 9421) from a DID that this node has been told to accept.
//!
//! Public, always: the DID document, the agent description, the agent card, the discovery listing and the demo pages.
//! Everything else (the JSON-RPC endpoint, the mesh directory, the security status, the link control, revocations) is
//! protected. The caller is whoever signed: a request is accepted only if the DID document this node holds for the
//! signing DID lists the key under `authentication`, the signature covers the method, the exact public URL and the
//! body, it is fresh, and it has not been seen before.

use std::collections::HashMap;
use std::sync::Arc;

use anp_httpauth::{anp_did, Policy, ReplayCache, Request as AuthRequest};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::hub::Hub;

/// Largest request body that is buffered to check its digest.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Which domains are believed, and the resolver that fetches their DIDs' documents over HTTPS. A DID whose domain is
/// listed is accepted as a caller or a P5 peer once its document has been fetched from that domain over TLS and verified:
/// what vouches for it is the domain, not a list of DIDs. Everything else about a DID on another domain stays refused.
pub struct DomainTrust {
    resolver: anp_resolve::Resolver,
    domains: std::collections::HashSet<String>,
}

impl DomainTrust {
    /// `domains` are authorities (`host` or `host:port`). `extra_roots` are DER certificates of a private CA to trust in
    /// addition to the web's; `allow_private` lets documents live on private addresses (a closed network, or tests).
    pub fn new(domains: Vec<String>, extra_roots: Vec<Vec<u8>>, allow_private: bool) -> Result<DomainTrust, String> {
        let cfg = anp_resolve::Config { allow_private, extra_roots, ..anp_resolve::Config::default() };
        Ok(DomainTrust { resolver: anp_resolve::Resolver::new(cfg)?, domains: domains.into_iter().map(|d| d.to_ascii_lowercase()).collect() })
    }

    pub fn domains(&self) -> Vec<String> {
        let mut v: Vec<String> = self.domains.iter().cloned().collect();
        v.sort();
        v
    }

    /// Is this DID on a trusted domain?
    pub fn allows(&self, did: &str) -> bool {
        anp_resolve::domain_of(did).map_or(false, |d| self.domains.contains(&d))
    }

    /// A fresh resolution already held, for a DID on a trusted domain.
    pub fn cached(&self, did: &str) -> Option<anp_resolve::Resolved> {
        if self.allows(did) { self.resolver.cached(did) } else { None }
    }

    /// Fetch (or reuse) the document of a DID on a trusted domain, off the async runtime.
    pub async fn resolve(self: &Arc<Self>, did: &str) -> Result<anp_resolve::Resolved, anp_resolve::ResolveError> {
        if !self.allows(did) {
            return Err(anp_resolve::ResolveError::Refused("that domain is not trusted".into()));
        }
        let (me, did) = (self.clone(), did.to_string());
        tokio::task::spawn_blocking(move || me.resolver.resolve(&did)).await.map_err(|e| anp_resolve::ResolveError::Fetch(e.to_string()))?
    }
}

/// Certificates from PEM text, as DER (for ``DomainTrust::new``).
pub fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    anp_resolve::pem_certificates(pem)
}

pub struct HttpAuth {
    /// How callers address this node: `https://host[:port]`. Behind a TLS-terminating proxy this is the proxy's URL;
    /// the signature covers it, so it is configured rather than read from the `Host` header.
    pub origin: String,
    /// Verified DID documents of the callers this node accepts, by DID.
    callers: HashMap<String, Value>,
    policy: Policy,
    replay: ReplayCache,
    /// Callers on trusted domains are resolved over HTTPS instead of being listed.
    domains: Option<Arc<DomainTrust>>,
    /// The older `Authorization: DIDWba` header and the Bearer token it returns (off unless asked for).
    legacy: Option<Legacy>,
}

struct Legacy {
    nonces: anp_httpauth::legacy::NonceCache,
    tokens: anp_httpauth::legacy::Tokens,
}

impl HttpAuth {
    /// `callers` are DID documents; each must verify (be self-certifying) or the node does not start with it.
    pub fn new(origin: &str, callers: Vec<Value>) -> Result<HttpAuth, String> {
        if anp_httpauth_origin_ok(origin).is_none() {
            return Err(format!("--public-origin must be http(s)://host[:port], got {origin}"));
        }
        let mut map = HashMap::new();
        for doc in callers {
            let v = anp_did::verify_document(&doc, None).map_err(|e| format!("caller DID document: {e}"))?;
            map.insert(v.did_string.clone(), doc);
        }
        let policy = Policy::default();
        Ok(HttpAuth { origin: origin.trim_end_matches('/').to_string(), callers: map, replay: ReplayCache::new(&policy), policy, domains: None, legacy: None })
    }

    /// Also accept callers whose DID is on a trusted domain.
    pub fn with_domain_trust(mut self, d: Arc<DomainTrust>) -> HttpAuth {
        self.domains = Some(d);
        self
    }

    /// Also accept the older `Authorization: DIDWba` scheme, and answer it with a Bearer token. It does not cover the method,
    /// the path or the body, and a token can be replayed until it expires, so it is something to switch on knowingly.
    pub fn with_legacy(mut self) -> HttpAuth {
        self.legacy = Some(Legacy { nonces: Default::default(), tokens: anp_httpauth::legacy::Tokens::new() });
        self
    }

    pub fn legacy_enabled(&self) -> bool {
        self.legacy.is_some()
    }

    /// The server name the legacy header is signed for: the host of the public origin, without a port.
    fn legacy_domain(&self) -> String {
        let rest = self.origin.split("://").nth(1).unwrap_or(&self.origin);
        let hostport = rest.split('/').next().unwrap_or(rest);
        if hostport.starts_with('[') {
            return hostport.split(']').next().unwrap_or(hostport).trim_start_matches('[').to_string();
        }
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h).to_string()
    }

    /// Is this DID one the node accepts (listed, or on a trusted domain)?
    fn accepts(&self, did: &str) -> bool {
        self.callers.contains_key(did) || self.domains.as_ref().map_or(false, |d| d.allows(did))
    }

    pub fn callers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.callers.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn trusted_domains(&self) -> Vec<String> {
        self.domains.as_ref().map(|d| d.domains()).unwrap_or_default()
    }

    fn key_for(&self, key_id: &str) -> Option<anp_did::VerifyingKey> {
        let did = key_id.split('#').next()?;
        if let Some(doc) = self.callers.get(did) {
            return anp_did::authentication_key(doc, key_id);
        }
        // a DID on a trusted domain: its document, as fetched (and verified) by the resolver
        let r = self.domains.as_ref()?.cached(did)?;
        anp_did::authentication_key(&r.document, key_id)
    }
}

fn anp_httpauth_origin_ok(o: &str) -> Option<()> {
    let rest = o.strip_prefix("https://").or_else(|| o.strip_prefix("http://"))?;
    let host = rest.trim_end_matches('/');
    (!host.is_empty() && !host.contains('/') && !host.contains('@')).then_some(())
}

/// Paths served without authentication: the documents that exist to be found.
pub fn is_public(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || path.starts_with("/demo")
        || path.ends_with("/ad.json")
        || path.ends_with("/openrpc.json")
        || path.ends_with("/did.json")
        || path.ends_with("/agent-card.json")
}

/// The node operator's own controls: no peer ever signs for them, so they are not ANP-02 calls; the handler answers
/// only callers on this machine (see `server::local_caller`).
pub fn is_local_control(path: &str) -> bool {
    path == "/anp/direct/conversations"
        || path == "/anp/groups/member"
        || path.starts_with("/anp/groups/member/")
        || path == "/store/sim"
        || path.starts_with("/store/sim/")
        || path == "/telemetry"
}

fn unauthorized(origin: &str, why: &str) -> Response {
    let realm = origin.split("://").nth(1).unwrap_or(origin);
    let mut r = (StatusCode::UNAUTHORIZED, format!("unauthorized: {why}\n")).into_response();
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("DIDWba realm=\"{realm}\", error=\"invalid_request\"")) {
        h.insert(header::WWW_AUTHENTICATE, v);
    }
    h.insert("accept-signature", HeaderValue::from_static("sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created;expires;nonce;keyid"));
    r
}

/// The caller's DID, added to the request once it has authenticated.
#[derive(Clone, Debug)]
pub struct Caller(pub String);

pub async fn middleware(State(hub): State<Arc<Hub>>, req: Request<Body>, next: Next) -> Response {
    let Some(auth) = hub.http_auth() else { return next.run(req).await };
    if is_public(req.uri().path()) || is_local_control(req.uri().path()) {
        return next.run(req).await;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let authorization = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_string);
    // the older scheme: a Bearer token this node issued, or a DIDWba header (which earns a token)
    if let (Some(legacy), Some(az)) = (&auth.legacy, authorization.as_deref()) {
        if az.len() > 7 && az[..7].eq_ignore_ascii_case("bearer ") {
            return match legacy.tokens.verify(az[7..].trim(), now) {
                Ok(did) if auth.accepts(&did) => {
                    let mut req = req;
                    req.extensions_mut().insert(Caller(did));
                    next.run(req).await
                }
                Ok(did) => {
                    hub.note_http_refusal(&format!("bearer token for {did}, which is no longer accepted"));
                    unauthorized(&auth.origin, "this caller is not accepted")
                }
                Err(e) => {
                    hub.note_http_refusal(&e.0);
                    unauthorized(&auth.origin, &e.0)
                }
            };
        }
        if az.len() >= 6 && az[..6].eq_ignore_ascii_case("didwba") {
            let parts = match anp_httpauth::legacy::parse(az) {
                Ok(p) => p,
                Err(e) => {
                    hub.note_http_refusal(&e.0);
                    return unauthorized(&auth.origin, &e.0);
                }
            };
            if let Some(d) = &auth.domains {
                if !auth.callers.contains_key(&parts.did) && d.allows(&parts.did) {
                    if let Err(e) = d.resolve(&parts.did).await {
                        log::warn!("ANP-02: could not resolve {}: {e}", parts.did);
                        hub.note_http_refusal(&format!("could not resolve {}: {e}", parts.did));
                    }
                }
            }
            let checked = match auth.key_for(&parts.key_id()) {
                None => Err(format!("no acceptable key for {}", parts.key_id())),
                Some(key) => anp_httpauth::legacy::verify(&parts, &key, &auth.legacy_domain(), now).map_err(|e| e.0),
            };
            if let Err(why) = checked {
                hub.note_http_refusal(&why);
                return unauthorized(&auth.origin, &why);
            }
            if !legacy.nonces.accept(&parts.did, &parts.nonce, now) {
                hub.note_http_refusal("replayed DIDWba header");
                return unauthorized(&auth.origin, "this DIDWba header was already used");
            }
            let token = legacy.tokens.issue(&parts.did, now);
            let mut req = req;
            req.extensions_mut().insert(Caller(parts.did.clone()));
            let mut resp = next.run(req).await;
            let h = resp.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&format!("access_token=\"{token}\", token_type=\"Bearer\", expires_in={}", anp_httpauth::legacy::TOKEN_LIFETIME)) {
                h.insert("authentication-info", v);
            }
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                h.insert(header::AUTHORIZATION, v); // the SDK's clients also look here
            }
            return resp;
        }
    }
    // a caller we were not given a document for, on a domain we trust: fetch its document first
    if let Some(d) = &auth.domains {
        let claimed = req.headers().get("signature-input").and_then(|v| v.to_str().ok()).and_then(anp_httpauth::key_id_of);
        if let Some(did) = claimed.as_deref().and_then(|k| k.split('#').next()) {
            if !auth.callers.contains_key(did) && d.allows(did) {
                if let Err(e) = d.resolve(did).await {
                    log::warn!("ANP-02: could not resolve {did}: {e}");
                    hub.note_http_refusal(&format!("could not resolve {did}: {e}"));
                }
            }
        }
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large\n").into_response();
    };
    let headers: Vec<(String, String)> = parts.headers.iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string()))).collect();
    let url = format!("{}{}", auth.origin, parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
    let areq = AuthRequest { method: parts.method.as_str(), url: &url, headers: &headers, body: &bytes };
    let verified = match anp_httpauth::verify(&areq, &|k| auth.key_for(k), &auth.policy, now) {
        Ok(v) => v,
        Err(e) => {
            hub.note_http_refusal(&e.0);
            return unauthorized(&auth.origin, &e.0);
        }
    };
    if !auth.replay.accept(&verified, now) {
        hub.note_http_refusal("replayed request");
        return unauthorized(&auth.origin, "this signed request was already used");
    }
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(Caller(verified.did));
    next.run(req).await
}
