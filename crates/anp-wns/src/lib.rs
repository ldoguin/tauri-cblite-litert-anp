//! ANP-04 WNS (WBA Name Space): a **handle** such as `alice.example.com` (or `wba://alice.example.com`) names an agent in a
//! form people can say, and resolves to its DID.
//!
//! * The handle's provider is the domain: `GET https://<domain>/.well-known/handle/<local-part>` returns a *handle resolution
//!   document* (`handle`, `did`, `status`, `binding_generation`, optional `ttl`, `updated`, `versionId` and a display-only `profile`).
//!   404 means no such handle, 410 that it was revoked for good, 301 that it moved.
//! * A handle is only believed if the binding holds **both ways** (forward: the provider says this handle is that DID and it is
//!   active; reverse: that DID's own document carries an `ANPHandleService` entry whose HTTPS endpoint is on the provider's domain).
//!   For `did:wba` the DID must also live on the handle's domain; a `did:web` identity may live elsewhere but must still declare
//!   the provider in its document.
//! * The `profile` is for showing, never for routing, authentication or key binding. It is dropped when it does not describe the
//!   same DID and handle as the outer document.
//! * `binding_generation` is a positive decimal string (no sign, no leading zero, any length) that a provider raises when the
//!   binding changes; clients compare them as strings of digits, never as machine integers.
//!
//! This crate has the rules (no network) and a client that resolves and verifies through the guarded `anp-resolve` fetcher.

use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::fmt;

pub const HANDLE_SERVICE_TYPE: &str = "ANPHandleService";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WnsError {
    /// Not a valid handle or `wba://` URI.
    Invalid(String),
    /// 404.
    NotFound(String),
    /// 410: revoked for good.
    Gone(String),
    /// A redirect: the handle moved (redirects are not followed).
    Moved(String),
    /// Network, protocol or document errors.
    Resolution(String),
    /// The binding does not hold in both directions.
    Binding(String),
}

impl fmt::Display for WnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WnsError::Invalid(s) => write!(f, "invalid handle: {s}"),
            WnsError::NotFound(s) => write!(f, "no such handle: {s}"),
            WnsError::Gone(s) => write!(f, "handle revoked: {s}"),
            WnsError::Moved(s) => write!(f, "handle moved: {s}"),
            WnsError::Resolution(s) => write!(f, "could not resolve: {s}"),
            WnsError::Binding(s) => write!(f, "binding not verified: {s}"),
        }
    }
}
impl std::error::Error for WnsError {}

// ── handles ─────────────────────────────────────────────────────────────────────────────────────────────

/// A normalised (lowercase) handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    pub local: String,
    pub domain: String,
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.local, self.domain)
    }
}

impl Handle {
    /// `https://<domain>/.well-known/handle/<local-part>`
    pub fn resolution_url(&self) -> String {
        format!("https://{}/.well-known/handle/{}", self.domain, self.local)
    }
    /// `wba://<local-part>.<domain>`
    pub fn uri(&self) -> String {
        format!("wba://{self}")
    }
}

/// 1 to 63 characters of `a-z`, `0-9` and `-`; starts and ends with a letter or digit; no two hyphens in a row.
pub fn valid_local_part(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && !s.contains("--")
}

fn valid_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            (1..=63).contains(&b.len()) && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') && b[0] != b'-' && b[b.len() - 1] != b'-'
        })
}

/// Validate a handle (case does not matter; it is lowercased). The local part is everything before the first dot.
pub fn validate_handle(input: &str) -> Result<Handle, WnsError> {
    let s = input.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err(WnsError::Invalid("a handle must not be empty".into()));
    }
    let (local, domain) = s.split_once('.').ok_or_else(|| WnsError::Invalid(format!("a handle needs at least one dot: '{input}'")))?;
    if local.is_empty() || domain.is_empty() {
        return Err(WnsError::Invalid(format!("the local part and the domain must not be empty: '{input}'")));
    }
    if !valid_local_part(local) {
        return Err(WnsError::Invalid(format!("local part '{local}' must be 1-63 characters of a-z, 0-9 and hyphen, start and end with a letter or digit, and have no double hyphen")));
    }
    if !valid_domain(domain) {
        return Err(WnsError::Invalid(format!("'{domain}' is not a domain name")));
    }
    Ok(Handle { local: local.to_string(), domain: domain.to_string() })
}

/// `wba://alice.example.com` to its handle.
pub fn parse_wba_uri(uri: &str) -> Result<Handle, WnsError> {
    let rest = uri.strip_prefix("wba://").ok_or_else(|| WnsError::Invalid(format!("a URI must start with wba://: '{uri}'")))?;
    if rest.is_empty() {
        return Err(WnsError::Invalid("no handle after wba://".into()));
    }
    validate_handle(rest)
}

/// A bare handle or a `wba://` URI.
pub fn parse(input: &str) -> Result<Handle, WnsError> {
    validate_handle(input.strip_prefix("wba://").unwrap_or(input))
}

// ── binding generations ─────────────────────────────────────────────────────────────────────────────────

/// A canonical binding generation: ASCII digits only, positive, no leading zero, any length.
pub fn check_generation(s: &str) -> Result<(), WnsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WnsError::Resolution("binding_generation must contain only ASCII decimal digits".into()));
    }
    if s.starts_with('0') {
        return Err(WnsError::Resolution("binding_generation must be positive and have no leading zero".into()));
    }
    Ok(())
}

/// Compare two canonical generations as numbers of any size.
pub fn compare_generations(a: &str, b: &str) -> Result<Ordering, WnsError> {
    check_generation(a)?;
    check_generation(b)?;
    Ok(a.len().cmp(&b.len()).then_with(|| a.cmp(b)))
}

// ── the resolution document ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
    Revoked,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Suspended => "suspended",
            Status::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    pub handle: Handle,
    pub did: String,
    pub status: Status,
    pub binding_generation: String,
    pub updated: Option<String>,
    pub version_id: Option<String>,
    pub ttl: Option<u64>,
    /// For display only; `None` when absent or when it does not describe the same DID and handle.
    pub profile: Option<Value>,
}

/// Read a handle resolution document, checking it is the one asked for.
pub fn parse_resolution(v: &Value, requested: &Handle) -> Result<Resolution, WnsError> {
    let bad = |m: &str| WnsError::Resolution(m.to_string());
    let s = |k: &str| v[k].as_str();
    let handle = validate_handle(s("handle").ok_or_else(|| bad("the document has no handle"))?).map_err(|e| WnsError::Resolution(e.to_string()))?;
    if &handle != requested {
        return Err(WnsError::Resolution(format!("handle mismatch: asked for {requested}, got {handle}")));
    }
    let did = s("did").filter(|d| d.starts_with("did:")).ok_or_else(|| bad("the document has no DID"))?.to_string();
    let status = match s("status") {
        Some("active") => Status::Active,
        Some("suspended") => Status::Suspended,
        Some("revoked") => Status::Revoked,
        other => return Err(WnsError::Resolution(format!("unknown status {other:?}"))),
    };
    let generation = s("binding_generation").ok_or_else(|| bad("binding_generation must be a decimal string"))?;
    check_generation(generation)?;
    let profile = v.get("profile").filter(|p| p.is_object()).filter(|p| p["subject_did"].as_str() == Some(did.as_str()) && p["handle"].as_str().map_or(true, |h| h == handle.to_string())).cloned();
    Ok(Resolution {
        handle,
        did,
        status,
        binding_generation: generation.to_string(),
        updated: s("updated").map(str::to_string),
        version_id: s("versionId").map(str::to_string),
        ttl: v["ttl"].as_u64(),
        profile,
    })
}

/// What a provider serves for one of its handles.
pub fn resolution_document(handle: &Handle, did: &str, status: Status, generation: &str, updated: &str, ttl: u64, profile: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("handle".into(), json!(handle.to_string()));
    m.insert("did".into(), json!(did));
    m.insert("status".into(), json!(status.as_str()));
    m.insert("binding_generation".into(), json!(generation));
    m.insert("updated".into(), json!(updated));
    m.insert("ttl".into(), json!(ttl));
    if let Some(p) = profile {
        m.insert("profile".into(), p);
    }
    Value::Object(m)
}

/// The display profile of an agent (`DIDSubjectProfile`).
pub fn profile(did: &str, handle: &Handle, subject_type: &str, display_name: &str, description: Option<&str>, updated: &str) -> Value {
    let mut p = json!({ "type": "DIDSubjectProfile", "subject_did": did, "subject_type": subject_type, "handle": handle.to_string(), "display_name": display_name, "updated": updated });
    if let Some(d) = description {
        p["description"] = json!(d);
    }
    p
}

/// The service entry a DID document carries so that the binding can be checked from the DID's side.
pub fn handle_service_entry(did: &str, handle: &Handle) -> Value {
    json!({ "id": format!("{did}#handle"), "type": HANDLE_SERVICE_TYPE, "serviceEndpoint": handle.resolution_url() })
}

fn https_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("HTTPS://"))?;
    let auth = rest.split(['/', '?', '#']).next()?;
    if auth.contains('@') {
        return None;
    }
    let host = if auth.starts_with('[') { auth.split(']').next()?.trim_start_matches('[') } else { auth.rsplit_once(':').map_or(auth, |(h, _)| h) };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Does a DID document declare `domain` as its handle provider (an `ANPHandleService` with an https endpoint on that host)?
pub fn declares_provider(did_document: &Value, domain: &str) -> bool {
    did_document["service"].as_array().into_iter().flatten().filter(|s| s["type"] == HANDLE_SERVICE_TYPE).any(|s| s["serviceEndpoint"].as_str().and_then(https_host).as_deref() == Some(domain))
}

/// The domain of a `did:wba` or `did:web` DID (percent-decoded colon kept as `host:port`).
fn did_domain(did: &str) -> Option<String> {
    anp_resolve::domain_of(did)
}

/// The outcome of a verified binding.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub handle: Handle,
    pub did: String,
    pub binding_generation: String,
    pub profile: Option<Value>,
}

/// Check the rules of the binding given the forward resolution and the DID's document (no network).
pub fn check_binding(res: &Resolution, did_document: &Value) -> Result<Verified, WnsError> {
    let bind = |m: String| WnsError::Binding(m);
    if res.status != Status::Active {
        return Err(bind(format!("handle status is '{}', expected 'active'", res.status.as_str())));
    }
    let is_web = res.did.starts_with("did:web:");
    if !is_web && !res.did.starts_with("did:wba:") {
        return Err(bind(format!("{} is neither did:wba nor did:web", res.did)));
    }
    if !is_web {
        let dd = did_domain(&res.did).ok_or_else(|| bind(format!("{} is not a valid did:wba", res.did)))?;
        let host = dd.rsplit_once(':').map_or(dd.as_str(), |(h, _)| h);
        if host != res.handle.domain {
            return Err(bind(format!("domain mismatch: the handle is on {} but the DID is on {dd}", res.handle.domain)));
        }
    }
    if did_document["id"].as_str() != Some(res.did.as_str()) {
        return Err(bind("the DID document is for another DID".into()));
    }
    if !declares_provider(did_document, &res.handle.domain) {
        return Err(bind(format!("the DID document has no ANPHandleService entry whose https endpoint is on {}", res.handle.domain)));
    }
    Ok(Verified { handle: res.handle.clone(), did: res.did.clone(), binding_generation: res.binding_generation.clone(), profile: res.profile.clone() })
}

// ── the client ──────────────────────────────────────────────────────────────────────────────────────────

pub struct Client {
    resolver: anp_resolve::Resolver,
    /// Fetch handle documents from `<base>/.well-known/handle/<local>` instead of `https://<domain>/...` (a gateway, or tests
    /// that cannot use port 443). The handle in the document is still checked against the one asked for.
    base: Option<String>,
}

impl Client {
    pub fn new(cfg: anp_resolve::Config) -> Result<Client, String> {
        Ok(Client { resolver: anp_resolve::Resolver::new(cfg)?, base: None })
    }

    pub fn with_base(mut self, base: &str) -> Client {
        self.base = Some(base.trim_end_matches('/').to_string());
        self
    }

    /// Forward resolution: the provider's document for a handle (guarded HTTPS: no internal addresses, no redirects).
    pub fn resolve(&self, handle: &Handle) -> Result<Resolution, WnsError> {
        let url = match &self.base {
            Some(b) => format!("{b}/.well-known/handle/{}", handle.local),
            None => handle.resolution_url(),
        };
        let doc = self.resolver.get_json(&url, "application/json").map_err(|e| match e {
            anp_resolve::ResolveError::Status(404) => WnsError::NotFound(handle.to_string()),
            anp_resolve::ResolveError::Status(410) => WnsError::Gone(handle.to_string()),
            anp_resolve::ResolveError::Refused(m) if m.contains("redirect") => WnsError::Moved(format!("{handle} answered with a redirect")),
            e => WnsError::Resolution(e.to_string()),
        })?;
        parse_resolution(&doc, handle)
    }

    /// Forward and reverse. `did_document` is the DID's document if the caller already has it; otherwise it is resolved.
    pub fn verify(&self, handle: &Handle, did_document: Option<&Value>) -> Result<Verified, WnsError> {
        let res = self.resolve(handle)?;
        self.verify_resolution(&res, did_document)
    }

    /// The reverse half of [`Client::verify`] for a resolution already fetched.
    pub fn verify_resolution(&self, res: &Resolution, did_document: Option<&Value>) -> Result<Verified, WnsError> {
        if res.status != Status::Active {
            return check_binding(res, &Value::Null);
        }
        let fetched;
        let doc = match did_document {
            Some(d) => d,
            None => {
                fetched = self.resolver.resolve(&res.did).map_err(|e| WnsError::Binding(format!("could not resolve {}: {e}", res.did)))?.document;
                &fetched
            }
        };
        check_binding(res, doc)
    }
}

// ── caching and rotation ────────────────────────────────────────────────────────────────────────────────

/// What a client keeps about handles it has verified: the answer for as long as the provider's `ttl` allows, and, for as long as the
/// process lives, the **highest binding generation seen** for each handle, so that an older document (a replayed or stale mirror) is
/// refused after a newer one was accepted. A handle moving to another DID (a **rotation**) is only believed with a *higher* generation.
#[derive(Debug, Default)]
pub struct Cache {
    entries: std::collections::HashMap<Handle, (Verified, u64)>,
    seen: std::collections::HashMap<Handle, (String, String)>,
}

/// Cache time limits: a missing `ttl` counts as this many seconds, and no `ttl` counts for more than a day.
pub const DEFAULT_TTL: u64 = 300;
pub const MAX_TTL: u64 = 86_400;

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    /// A verified answer that is still fresh at `now` (seconds).
    pub fn fresh(&self, handle: &Handle, now: u64) -> Option<&Verified> {
        self.entries.get(handle).filter(|(_, until)| now < *until).map(|(v, _)| v)
    }

    /// Check a resolution against what was seen before: a lower generation is a rollback; the same generation must name the same DID.
    pub fn admit(&self, res: &Resolution) -> Result<(), WnsError> {
        if let Some((gen, did)) = self.seen.get(&res.handle) {
            match compare_generations(&res.binding_generation, gen)? {
                Ordering::Less => return Err(WnsError::Binding(format!("{} answered with binding_generation {} after {gen} was seen: refused (rollback)", res.handle, res.binding_generation))),
                Ordering::Equal if &res.did != did => return Err(WnsError::Binding(format!("{} names another DID at the same binding_generation {gen}", res.handle))),
                _ => {}
            }
        }
        Ok(())
    }

    /// Remember a verified binding (after `admit`) for its `ttl` from `now`.
    pub fn store(&mut self, v: &Verified, ttl: Option<u64>, now: u64) {
        self.seen.insert(v.handle.clone(), (v.binding_generation.clone(), v.did.clone()));
        let ttl = ttl.unwrap_or(DEFAULT_TTL).min(MAX_TTL);
        if ttl > 0 {
            self.entries.insert(v.handle.clone(), (v.clone(), now + ttl));
        } else {
            self.entries.remove(&v.handle);
        }
    }

    /// The provider said the handle is gone, suspended or revoked: nothing is kept for it (the generation stays, so a revival needs a higher one).
    pub fn forget(&mut self, handle: &Handle) {
        self.entries.remove(handle);
    }
}

/// A [`Client`] with a [`Cache`]: `verify` answers from the cache while the `ttl` lasts, and otherwise resolves, checks the generation
/// against the highest seen, verifies both directions and remembers the result.
pub struct CachingClient {
    pub client: Client,
    cache: std::sync::Mutex<Cache>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl CachingClient {
    pub fn new(client: Client) -> CachingClient {
        CachingClient { client, cache: std::sync::Mutex::new(Cache::new()), clock: Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())) }
    }

    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> CachingClient {
        self.clock = Box::new(clock);
        self
    }

    pub fn verify(&self, handle: &Handle) -> Result<Verified, WnsError> {
        let now = (self.clock)();
        if let Some(v) = self.cache.lock().unwrap().fresh(handle, now) {
            return Ok(v.clone());
        }
        let res = match self.client.resolve(handle) {
            Ok(r) => r,
            Err(e @ (WnsError::NotFound(_) | WnsError::Gone(_))) => {
                self.cache.lock().unwrap().forget(handle);
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        self.cache.lock().unwrap().admit(&res)?;
        let verified = self.client.verify_resolution(&res, None);
        let mut cache = self.cache.lock().unwrap();
        match verified {
            Ok(v) => {
                cache.store(&v, res.ttl, now);
                Ok(v)
            }
            Err(e) => {
                cache.forget(handle);
                Err(e)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Handle {
        validate_handle(s).unwrap()
    }
    const DID: &str = "did:wba:example.com:agents:alice:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn handles_follow_the_syntax_rules() {
        assert_eq!(h("Alice.Example.COM").to_string(), "alice.example.com", "case is folded");
        assert_eq!(h("  a.b.example.com ").local, "a");
        assert_eq!(h("a.b.example.com").domain, "b.example.com", "the local part ends at the first dot");
        assert_eq!(h("x-y.example.com").local, "x-y");
        for bad in ["", "alice", "alice.", ".example.com", "-a.example.com", "a-.example.com", "a--b.example.com", "a_b.example.com", "alice.example", "alice.-example.com", "alice.example..com", "alice.ex ample.com"] {
            if bad == "alice.example" {
                continue; // two labels is a valid domain: "example"? no: the domain here is the single label "example"
            }
            assert!(validate_handle(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_handle(&format!("{}.example.com", "a".repeat(63))).is_ok());
        assert!(validate_handle(&format!("{}.example.com", "a".repeat(64))).is_err());
        assert!(validate_handle("alice.example").is_err(), "a domain needs two labels");
    }

    #[test]
    fn uris_and_urls() {
        let a = parse_wba_uri("wba://alice.example.com").unwrap();
        assert_eq!(a, h("alice.example.com"));
        assert_eq!(a.uri(), "wba://alice.example.com");
        assert_eq!(a.resolution_url(), "https://example.com/.well-known/handle/alice");
        assert!(parse_wba_uri("alice.example.com").is_err());
        assert!(parse_wba_uri("wba://").is_err());
        assert_eq!(parse("wba://alice.example.com").unwrap(), parse("alice.example.com").unwrap());
    }

    #[test]
    fn generations_are_canonical_decimal_strings_of_any_length() {
        for ok in ["1", "7", "10", "123456789012345678901234567890"] {
            assert!(check_generation(ok).is_ok(), "{ok}");
        }
        for bad in ["", "0", "01", "-1", "+1", "1.0", " 1", "1 ", "１２", "abc"] {
            assert!(check_generation(bad).is_err(), "{bad:?}");
        }
        assert_eq!(compare_generations("9", "10").unwrap(), Ordering::Less, "numbers, not text");
        assert_eq!(compare_generations("123456789012345678901234567891", "123456789012345678901234567890").unwrap(), Ordering::Greater);
        assert_eq!(compare_generations("5", "5").unwrap(), Ordering::Equal);
        assert!(compare_generations("5", "05").is_err());
    }

    fn doc(extra: Value) -> Value {
        let mut d = resolution_document(&h("alice.example.com"), DID, Status::Active, "3", "2026-11-15T10:00:00Z", 300, None);
        for (k, v) in extra.as_object().unwrap() {
            d[k] = v.clone();
        }
        d
    }

    #[test]
    fn a_resolution_document_is_checked_against_the_handle_asked_for() {
        let r = parse_resolution(&doc(json!({})), &h("alice.example.com")).unwrap();
        assert_eq!((r.did.as_str(), r.status, r.binding_generation.as_str(), r.ttl), (DID, Status::Active, "3", Some(300)));
        assert!(parse_resolution(&doc(json!({})), &h("bob.example.com")).is_err(), "another handle");
        assert!(parse_resolution(&doc(json!({ "binding_generation": 3 })), &h("alice.example.com")).is_err(), "a number is not a string");
        assert!(parse_resolution(&doc(json!({ "binding_generation": "03" })), &h("alice.example.com")).is_err());
        assert!(parse_resolution(&doc(json!({ "status": "gone" })), &h("alice.example.com")).is_err());
        assert!(parse_resolution(&doc(json!({ "did": "alice" })), &h("alice.example.com")).is_err());
        let mut no_gen = doc(json!({}));
        no_gen.as_object_mut().unwrap().remove("binding_generation");
        assert!(parse_resolution(&no_gen, &h("alice.example.com")).is_err());
        assert_eq!(parse_resolution(&doc(json!({ "handle": "ALICE.example.com" })), &h("alice.example.com")).unwrap().handle, h("alice.example.com"), "case is folded");
    }

    #[test]
    fn a_profile_that_describes_someone_else_is_dropped() {
        let a = h("alice.example.com");
        let good = profile(DID, &a, "agent", "Alice", Some("Books rooms"), "2026-11-15T10:00:00Z");
        assert!(parse_resolution(&doc(json!({ "profile": good.clone() })), &a).unwrap().profile.is_some());
        let mut other_did = good.clone();
        other_did["subject_did"] = json!("did:wba:evil.example.com:agents:x:e1_B");
        assert!(parse_resolution(&doc(json!({ "profile": other_did })), &a).unwrap().profile.is_none());
        let mut other_handle = good;
        other_handle["handle"] = json!("mallory.example.com");
        assert!(parse_resolution(&doc(json!({ "profile": other_handle })), &a).unwrap().profile.is_none());
        assert!(parse_resolution(&doc(json!({ "profile": "text" })), &a).unwrap().profile.is_none(), "not an object");
    }

    fn did_doc_with(service: Value) -> Value {
        json!({ "id": DID, "service": [service] })
    }

    #[test]
    fn the_binding_must_hold_both_ways() {
        let a = h("alice.example.com");
        let res = parse_resolution(&doc(json!({})), &a).unwrap();
        let ok = did_doc_with(handle_service_entry(DID, &a));
        let v = check_binding(&res, &ok).unwrap();
        assert_eq!((v.did.as_str(), v.binding_generation.as_str()), (DID, "3"));
        // the DID's document does not mention the provider
        assert!(check_binding(&res, &json!({ "id": DID, "service": [] })).unwrap_err().to_string().contains("ANPHandleService"));
        // it names another provider
        let other = did_doc_with(handle_service_entry(DID, &h("alice.evil.com")));
        assert!(check_binding(&res, &other).is_err());
        // plain http does not count, nor does a host that only contains the domain
        let plain = did_doc_with(json!({ "id": format!("{DID}#handle"), "type": HANDLE_SERVICE_TYPE, "serviceEndpoint": "http://example.com/.well-known/handle/alice" }));
        assert!(check_binding(&res, &plain).is_err());
        let sneaky = did_doc_with(json!({ "id": format!("{DID}#handle"), "type": HANDLE_SERVICE_TYPE, "serviceEndpoint": "https://example.com.evil.net/.well-known/handle/alice" }));
        assert!(check_binding(&res, &sneaky).is_err());
        let userinfo = did_doc_with(json!({ "id": format!("{DID}#handle"), "type": HANDLE_SERVICE_TYPE, "serviceEndpoint": "https://example.com@evil.net/x" }));
        assert!(check_binding(&res, &userinfo).is_err());
        // a document for another DID
        assert!(check_binding(&res, &json!({ "id": "did:wba:example.com:agents:bob:e1_C", "service": [handle_service_entry(DID, &a)] })).is_err());
    }

    #[test]
    fn a_wba_did_must_live_on_the_handles_domain_but_a_web_did_may_not() {
        let res_for = |did: &str| {
            let mut d = doc(json!({}));
            d["did"] = json!(did);
            parse_resolution(&d, &h("alice.example.com")).unwrap()
        };
        let foreign = "did:wba:other.net:agents:alice:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let doc_foreign = json!({ "id": foreign, "service": [handle_service_entry(foreign, &h("alice.example.com"))] });
        assert!(check_binding(&res_for(foreign), &doc_foreign).unwrap_err().to_string().contains("domain mismatch"));
        let web = "did:web:identity.other.net:alice";
        let doc_web = json!({ "id": web, "service": [handle_service_entry(web, &h("alice.example.com"))] });
        assert!(check_binding(&res_for(web), &doc_web).is_ok(), "did:web declares its provider instead");
        // a did:wba with a port on the same host is the same domain
        let ported = "did:wba:example.com%3A8443:agents:alice:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let doc_ported = json!({ "id": ported, "service": [handle_service_entry(ported, &h("alice.example.com"))] });
        assert!(check_binding(&res_for(ported), &doc_ported).is_ok());
        assert!(check_binding(&res_for("did:key:z6Mk"), &json!({ "id": "did:key:z6Mk" })).is_err(), "other methods");
    }

    #[test]
    fn a_handle_that_is_not_active_never_verifies() {
        for s in [Status::Suspended, Status::Revoked] {
            let mut d = doc(json!({}));
            d["status"] = json!(s.as_str());
            let res = parse_resolution(&d, &h("alice.example.com")).unwrap();
            let ok = did_doc_with(handle_service_entry(DID, &h("alice.example.com")));
            assert!(check_binding(&res, &ok).unwrap_err().to_string().contains("expected 'active'"));
        }
    }

    #[test]
    fn the_cache_keeps_an_answer_for_its_ttl_and_refuses_a_rollback() {
        let a = h("alice.example.com");
        let ok = did_doc_with(handle_service_entry(DID, &a));
        let res3 = parse_resolution(&doc(json!({})), &a).unwrap();
        let v3 = check_binding(&res3, &ok).unwrap();
        let mut c = Cache::new();
        assert!(c.fresh(&a, 1000).is_none());
        c.admit(&res3).unwrap();
        c.store(&v3, Some(60), 1000);
        assert!(c.fresh(&a, 1059).is_some(), "fresh within the ttl");
        assert!(c.fresh(&a, 1060).is_none(), "stale at the ttl");
        // an older generation after a newer one is a rollback, even once the entry has expired
        let res2 = parse_resolution(&doc(json!({ "binding_generation": "2" })), &a).unwrap();
        assert!(c.admit(&res2).is_err());
        // the same generation but another DID is inconsistent
        let other = parse_resolution(&doc(json!({ "did": "did:wba:example.com:agents:alice2:e1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" })), &a).unwrap();
        assert!(c.admit(&other).is_err());
        // a rotation to another DID needs a higher generation
        let mut rotated = other.clone();
        rotated.binding_generation = "4".into();
        c.admit(&rotated).unwrap();
        // ttl 0 means do not cache; a missing ttl is the default; a huge one is capped
        c.store(&v3, Some(0), 2000);
        assert!(c.fresh(&a, 2000).is_none());
        c.store(&v3, None, 2000);
        assert!(c.fresh(&a, 2000 + DEFAULT_TTL - 1).is_some() && c.fresh(&a, 2000 + DEFAULT_TTL).is_none());
        c.store(&v3, Some(10_000_000), 2000);
        assert!(c.fresh(&a, 2000 + MAX_TTL).is_none());
        // gone or revoked: nothing kept
        c.store(&v3, Some(60), 3000);
        c.forget(&a);
        assert!(c.fresh(&a, 3001).is_none());
    }}
