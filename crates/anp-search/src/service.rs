//! Registration, crawling and the JSON-RPC methods, over a `Fetcher` (the network side, so that tests need none).

use crate::index::{Entry, Index};
use crate::store::{JsonFile, Store};
use anp_did::Verified;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// What the service needs from the network.
pub trait Fetcher: Send + Sync {
    /// The JSON document at an https URL.
    fn get_json(&self, url: &str) -> Result<Value, FetchError>;
    /// The verified (self-certifying) DID document of a `did:wba` e1 DID, fetched from its own domain.
    fn did_document(&self, did: &str) -> Result<Verified, String>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchError {
    /// The server says it is not there (404 or 410).
    Gone,
    Other(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Gone => write!(f, "the server says it is gone"),
            FetchError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Resolves a WNS handle (`alice.example.com`) to the DID its provider and the DID itself agree on (both directions checked).
pub trait HandleResolver: Send + Sync {
    fn did_for(&self, handle: &str) -> Result<String, String>;
}

/// The real network: guarded HTTPS and the DID resolver.
pub struct NetFetcher(pub anp_resolve::Resolver);

impl Fetcher for NetFetcher {
    fn get_json(&self, url: &str) -> Result<Value, FetchError> {
        self.0.get_json(url, "application/json, application/ld+json").map_err(|e| match e {
            anp_resolve::ResolveError::Status(404) | anp_resolve::ResolveError::Status(410) => FetchError::Gone,
            e => FetchError::Other(e.to_string()),
        })
    }
    fn did_document(&self, did: &str) -> Result<Verified, String> {
        let r = self.0.resolve(did).map_err(|e| e.to_string())?;
        r.verified.ok_or_else(|| "only did:wba e1 DIDs can describe themselves here".to_string())
    }
}

/// Why a description could not be taken: `Transient` failures say nothing about the description (the network, a resolver), while
/// `Invalid` ones say it does not stand up.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    Transient(String),
    Invalid(String),
}

impl Failure {
    fn message(self) -> String {
        match self {
            Failure::Transient(s) | Failure::Invalid(s) => s,
        }
    }
}

/// A registration that is not refreshed is dropped when it has gone this many refresh intervals without verifying.
pub const STALE_AFTER_INTERVALS: i64 = 7;

/// How much one `crawl` may do: pages of a listing, and descriptions taken from it.
pub const CRAWL_PAGES: usize = 10;
pub const CRAWL_ENTRIES: usize = 50;

pub struct Service {
    fetcher: Arc<dyn Fetcher>,
    index: Mutex<Index>,
    /// Where each change is kept (one entry at a time); `None` keeps nothing between runs.
    store: Option<Arc<dyn Store>>,
    /// Registrations, crawls and refreshes need a signed request, and what the signer may do is limited (see `auth`).
    signed_only: bool,
    /// When set, only these domains (`host[:port]`) are registered from or crawled.
    allowed: Option<Vec<String>>,
    /// Looks handles up (ANP-04), when the agent was given a resolver for them.
    handles: Option<Arc<dyn HandleResolver>>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `host[:port]` of an https URL, lowercase.
pub fn authority(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let a = rest.split(['/', '?', '#']).next()?;
    (!a.is_empty() && !a.contains('@')).then(|| a.to_ascii_lowercase())
}

impl Service {
    /// A service that keeps its index in one JSON file (or nowhere); see [`Service::with_store`] for a database.
    pub fn new(fetcher: Arc<dyn Fetcher>, file: Option<PathBuf>) -> Result<Service, String> {
        let store: Option<Arc<dyn Store>> = match file {
            Some(f) => Some(Arc::new(JsonFile::open(&f)?)),
            None => None,
        };
        Service::with_store(fetcher, store)
    }

    /// A service that keeps its index in `store`, and starts from what the store holds.
    pub fn with_store(fetcher: Arc<dyn Fetcher>, store: Option<Arc<dyn Store>>) -> Result<Service, String> {
        let mut index = Index::default();
        if let Some(s) = &store {
            for e in s.load()? {
                index.put(e).ok();
            }
        }
        Ok(Service { fetcher, index: Mutex::new(index), store, signed_only: false, allowed: None, handles: None })
    }

    /// Take `register`, `crawl` and `refresh` only from signed requests, and only from the agent they concern.
    pub fn require_signed_registration(mut self) -> Service {
        self.signed_only = true;
        self
    }

    /// Does this method need the caller to have signed the request (so that the HTTP layer must check the signature)?
    pub fn needs_signature(&self, method: &str) -> bool {
        self.signed_only && matches!(method, "register" | "crawl" | "refresh")
    }

    /// The verified DID document of a `did:wba` e1 DID, fetched from its own domain (to check the signer of a request).
    pub fn did_document(&self, did: &str) -> Result<Verified, String> {
        self.fetcher.did_document(did)
    }

    /// Serve only these domains.
    pub fn restrict_to(mut self, domains: Vec<String>) -> Service {
        self.allowed = Some(domains.into_iter().map(|d| d.to_ascii_lowercase()).collect());
        self
    }

    fn permitted(&self, domain: &str) -> Result<(), String> {
        match &self.allowed {
            Some(a) if !a.iter().any(|d| d == domain) => Err(format!("this search agent does not take descriptions from {domain}")),
            _ => Ok(()),
        }
    }

    pub fn len(&self) -> usize {
        self.index.lock().unwrap().len()
    }

    /// Make an entry durable.
    fn keep(&self, e: &Entry) {
        if let Some(s) = &self.store {
            if let Err(err) = s.put(e) {
                log::warn!("could not keep {} in the index store: {err}", e.url);
            }
        }
    }

    /// Make a removal durable.
    fn forget(&self, url: &str) {
        if let Some(s) = &self.store {
            if let Err(err) = s.remove(url) {
                log::warn!("could not remove {url} from the index store: {err}");
            }
        }
    }

    /// Fetch the description at `url`, check everything (see the crate docs) and index it.
    pub fn register(&self, url: &str) -> Result<Entry, String> {
        self.register_as(url, None)
    }

    /// Like [`Service::register`], for a request signed by `caller` (when there is one): a description is registered by the DID it names.
    pub fn register_as(&self, url: &str, caller: Option<&str>) -> Result<Entry, String> {
        let entry = self.check(url).map_err(Failure::message)?;
        if let Some(c) = caller {
            if entry.did != c {
                return Err(format!("not permitted: {c} cannot register a description of {}; an agent registers its own", entry.did));
            }
        }
        let mut i = self.index.lock().unwrap();
        i.put(entry.clone())?;
        self.keep(&entry);
        Ok(entry)
    }

    fn check(&self, url: &str) -> Result<Entry, Failure> {
        use Failure::{Invalid, Transient};
        let from = authority(url).ok_or_else(|| Invalid("the URL must be https://host[:port]/...".to_string()))?;
        self.permitted(&from).map_err(Invalid)?;
        let ad = self.fetcher.get_json(url).map_err(|e| Transient(format!("fetching the description: {e}")))?;
        anp_ad::validate(&ad).map_err(|e| Invalid(format!("not a valid agent description: {}", e.0)))?;
        if ad["url"].as_str() != Some(url) {
            return Err(Invalid(format!("the description says it is at {}, not at {url}", ad["url"])));
        }
        let did = ad["did"].as_str().ok_or_else(|| Invalid("a description must name its DID".to_string()))?;
        if anp_resolve::domain_of(did).as_deref() != Some(from.as_str()) {
            return Err(Invalid(format!("{did} does not live on {from}: an agent describes itself on its own domain")));
        }
        let doc = self.fetcher.did_document(did).map_err(|e| Transient(format!("resolving {did}: {e}")))?;
        anp_ad::verify(&ad, &doc, Some(&from)).map_err(|e| Invalid(format!("the description does not verify: {}", e.0)))?;
        Ok(Entry::from_ad(url, &ad, now()))
    }

    /// Re-check what has not been verified for `max_age` seconds, oldest first, at most `limit` of them. A description that
    /// still verifies is updated; one whose server says it is gone, or that no longer verifies, is dropped (the index holds
    /// only what verifies); one that could not be reached is kept until it has gone `STALE_AFTER_INTERVALS` intervals unseen.
    pub fn refresh_due(&self, max_age: i64, limit: usize) -> Value {
        let cutoff = now() - max_age;
        let mut due: Vec<(i64, String)> = self.index.lock().unwrap().list().iter().filter(|e| e.verified_at <= cutoff).map(|e| (e.verified_at, e.url.clone())).collect();
        due.sort();
        due.truncate(limit);
        let (mut updated, mut removed, mut kept) = (0, vec![], 0);
        for (verified_at, url) in due {
            let outcome = match self.fetcher.get_json(&url) {
                Err(FetchError::Gone) => Err(Failure::Invalid("its server says it is gone".into())),
                _ => self.check(&url),
            };
            let mut i = self.index.lock().unwrap();
            match outcome {
                Ok(e) => {
                    if i.put(e.clone()).is_ok() {
                        self.keep(&e);
                        updated += 1;
                    }
                }
                Err(Failure::Invalid(why)) => {
                    i.remove(&url);
                    self.forget(&url);
                    removed.push(json!({ "url": url, "reason": why }));
                }
                Err(Failure::Transient(why)) if now() - verified_at > STALE_AFTER_INTERVALS * max_age => {
                    i.remove(&url);
                    self.forget(&url);
                    removed.push(json!({ "url": url, "reason": format!("unreachable for too long: {why}") }));
                }
                Err(Failure::Transient(_)) => kept += 1,
            }
        }
        json!({ "updated": updated, "removed": removed, "keptUnreachable": kept })
    }

    /// Re-check a registered description: updated if it still verifies, dropped if its server says it is gone, left alone
    /// (with the reason) if it could not be fetched or no longer verifies.
    pub fn refresh(&self, url: &str) -> Result<&'static str, String> {
        self.refresh_as(url, None)
    }

    /// Like [`Service::refresh`], for a request signed by `caller` (when there is one): an entry is refreshed (or withdrawn) by its own DID.
    pub fn refresh_as(&self, url: &str, caller: Option<&str>) -> Result<&'static str, String> {
        match (self.index.lock().unwrap().get(url), caller) {
            (None, _) => return Err("not registered".into()),
            (Some(e), Some(c)) if e.did != c => return Err(format!("not permitted: {c} cannot refresh {url}; it belongs to {}", e.did)),
            _ => {}
        }
        let gone = matches!(self.fetcher.get_json(url), Err(FetchError::Gone));
        if gone {
            let mut i = self.index.lock().unwrap();
            i.remove(url);
            self.forget(url);
            return Ok("removed");
        }
        self.register_as(url, caller).map(|_| "updated")
    }

    /// Active discovery of a domain (ANP-08): crawl its `/.well-known/agent-descriptions`, register what verifies. Only
    /// descriptions on that same origin are taken, and only the first `CRAWL_ENTRIES`.
    pub fn crawl(&self, domain: &str) -> Result<Value, String> {
        self.crawl_as(domain, None)
    }

    /// Like [`Service::crawl`], for a request signed by `caller` (when there is one): a domain is crawled on the word of a DID that lives on it.
    pub fn crawl_as(&self, domain: &str, caller: Option<&str>) -> Result<Value, String> {
        let domain = domain.to_ascii_lowercase();
        if domain.is_empty() || domain.contains(['/', '@', '?', '#', ' ']) {
            return Err("give a domain as host or host:port".into());
        }
        if let Some(c) = caller {
            if anp_resolve::domain_of(c).as_deref() != Some(domain.as_str()) {
                return Err(format!("not permitted: {c} does not live on {domain}; a domain is crawled on the word of one of its own agents"));
            }
        }
        self.permitted(&domain)?;
        let start = format!("https://{domain}/.well-known/agent-descriptions");
        let mut fetch = |u: &str| self.fetcher.get_json(u).map_err(|e| e.to_string());
        let items = anp_ad::discovery::crawl(&start, CRAWL_PAGES, &mut fetch).map_err(|e| e.0)?;
        let (mut added, mut failed, mut skipped) = (0, vec![], 0);
        for item in items.iter().take(CRAWL_ENTRIES) {
            if authority(&item.id).as_deref() != Some(domain.as_str()) {
                skipped += 1;
                continue;
            }
            match self.register(&item.id) {
                Ok(_) => added += 1,
                Err(e) => failed.push(json!({ "url": item.id, "reason": e })),
            }
        }
        Ok(json!({ "listed": items.len(), "registered": added, "refused": failed, "otherOrigin": skipped, "beyondLimit": items.len().saturating_sub(CRAWL_ENTRIES) }))
    }

    /// Give the service a resolver for WNS handles: a query that is a handle then finds the agents of the DID it names.
    pub fn with_handles(mut self, r: Arc<dyn HandleResolver>) -> Service {
        self.handles = Some(r);
        self
    }

    /// The agents of the DID a handle resolves to (the binding is verified both ways by the resolver; a handle that does not
    /// verify finds nothing, and says why).
    pub fn search_handle(&self, handle: &str, limit: usize) -> Result<Value, String> {
        let r = self.handles.as_ref().ok_or("this search agent has no handle resolver")?;
        let did = r.did_for(handle)?;
        let i = self.index.lock().unwrap();
        let found: Vec<Value> = i.by_did(&did).into_iter().take(limit.clamp(1, 100)).map(|e| e.to_json()).collect();
        Ok(json!({ "handle": handle, "did": did, "results": found }))
    }

    pub fn search(&self, query: &str, protocol: Option<&str>, limit: usize) -> Value {
        let i = self.index.lock().unwrap();
        json!({ "query": query, "results": i.search(query, protocol, limit.clamp(1, 100)).iter().map(|m| m.to_json()).collect::<Vec<_>>() })
    }

    pub fn list(&self, offset: usize, limit: usize) -> Value {
        let i = self.index.lock().unwrap();
        let all = i.list();
        let page: Vec<Value> = all.iter().skip(offset).take(limit.clamp(1, 100)).map(|e| e.to_json()).collect();
        json!({ "total": all.len(), "entries": page })
    }

    /// One JSON-RPC 2.0 request (parameters by name). Blocking: it may fetch.
    pub fn rpc(&self, req: &Value) -> Value {
        self.rpc_as(req, None)
    }

    /// Like [`Service::rpc`]; `caller` is the DID that signed the request, when it was checked (see `auth`). A service that requires signed
    /// registration refuses `register`, `crawl` and `refresh` without one (-32030), and one for a DID that is not the agent concerned (-32031).
    pub fn rpc_as(&self, req: &Value, caller: Option<&str>) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let err = |code: i32, m: String| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": m } });
        let Some(method) = req["method"].as_str() else { return err(-32600, "missing method".into()) };
        let p = &req["params"];
        let str_param = |k: &str| p[k].as_str().filter(|s| !s.is_empty());
        if self.needs_signature(method) && caller.is_none() {
            return err(-32030, "this search agent takes registrations only in signed requests (ANP-02, RFC 9421): sign the request with your DID".into());
        }
        // a code of its own for "you may not do that" (the signer is known, but it is not the agent concerned)
        let denied = |e: String| (if e.starts_with("not permitted:") { -32031 } else { -32010 }, e);
        let result = match method {
            "register" => match str_param("url") {
                Some(u) => self.register_as(u, caller).map(|e| e.to_json()).map_err(denied),
                None => Err((-32602, "url required".into())),
            },
            "refresh" => match str_param("url") {
                Some(u) => self.refresh_as(u, caller).map(|s| json!({ "result": s })).map_err(denied),
                None => Err((-32602, "url required".into())),
            },
            "crawl" => match str_param("domain") {
                Some(d) => self.crawl_as(d, caller).map_err(denied),
                None => Err((-32602, "domain required".into())),
            },
            "search" => match str_param("query") {
                Some(q) => Ok(self.search(q, str_param("protocol"), p["limit"].as_u64().unwrap_or(10) as usize)),
                None => Err((-32602, "query required".into())),
            },
            "search_handle" => match str_param("handle") {
                Some(h) => self.search_handle(h, p["limit"].as_u64().unwrap_or(10) as usize).map_err(|e| (-32011, e)),
                None => Err((-32602, "handle required".into())),
            },
            "list" => Ok(self.list(p["offset"].as_u64().unwrap_or(0) as usize, p["limit"].as_u64().unwrap_or(50) as usize)),
            m => Err((-32601, format!("method not found: {m}"))),
        };
        match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((c, m)) => err(c, m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp_ad::{Info, Interface, Spec};
    use anp_did::SigningKey;
    use std::collections::HashMap;

    /// A pretend network: URLs to documents, DIDs to their documents.
    #[derive(Default)]
    struct Fake {
        docs: Mutex<HashMap<String, Value>>,
        dids: Mutex<HashMap<String, Verified>>,
    }
    impl Fetcher for Fake {
        fn get_json(&self, url: &str) -> Result<Value, FetchError> {
            self.docs.lock().unwrap().get(url).cloned().ok_or(FetchError::Gone)
        }
        fn did_document(&self, did: &str) -> Result<Verified, String> {
            self.dids.lock().unwrap().get(did).cloned().ok_or_else(|| "no such DID".to_string())
        }
    }

    struct Agent {
        sk: SigningKey,
        did: String,
        verified: Verified,
        domain: String,
    }
    fn agent(seed: u8, name: &str, domain: &str) -> Agent {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let (host, port) = match domain.split_once(':') {
            Some((h, p)) => (h, p.parse().ok()),
            None => (domain, None),
        };
        let did = anp_did::did_for_key(host, port, &["agents", name], &sk.verifying_key().to_bytes());
        let doc = anp_did::build_document(&did, &sk, &[], "2026-11-14T10:00:00Z").unwrap();
        let verified = anp_did::verify_document(&doc, Some(&did)).unwrap();
        Agent { sk, did, verified, domain: domain.into() }
    }
    fn ad_url(a: &Agent, name: &str) -> String {
        format!("https://{}/agents/{name}/ad.json", a.domain)
    }
    fn signed_ad(a: &Agent, name: &str, desc: &str) -> Value {
        let mut ad = anp_ad::build(&Spec {
            name: name.into(),
            did: a.did.clone(),
            url: ad_url(a, name),
            description: Some(desc.into()),
            owner: None,
            created: "2026-11-14T10:00:00Z".into(),
            informations: vec![Info { ty: "Information".into(), description: "Room policies".into(), url: None }],
            interfaces: vec![Interface { ty: "StructuredInterface".into(), protocol: "A2A".into(), version: None, url: format!("https://{}/.well-known/agent-card.json", a.domain), description: Some("Tasks".into()), human_authorization: None }],
        });
        anp_ad::sign(&mut ad, &a.sk, &a.did, "2026-11-14T10:00:00Z", Some((&a.domain, "n-1"))).unwrap();
        ad
    }
    fn world(agents: &[(&Agent, &str, &str)]) -> (Arc<Fake>, Service) {
        let f = Arc::new(Fake::default());
        for (a, name, desc) in agents {
            f.docs.lock().unwrap().insert(ad_url(a, name), signed_ad(a, name, desc));
            f.dids.lock().unwrap().insert(a.did.clone(), a.verified.clone());
        }
        let s = Service::new(f.clone(), None).unwrap();
        (f, s)
    }

    #[test]
    fn a_description_that_verifies_is_indexed_and_found() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (_, s) = world(&[(&a, "concierge", "Books rooms for guests")]);
        let e = s.register(&ad_url(&a, "concierge")).unwrap();
        assert_eq!((e.name.as_str(), e.did.as_str(), e.protocols.as_slice()), ("concierge", a.did.as_str(), ["A2A".to_string()].as_slice()));
        let r = s.search("rooms", None, 5);
        assert_eq!(r["results"][0]["did"], json!(a.did));
    }

    #[test]
    fn a_handle_finds_the_agents_of_the_did_it_names_and_only_when_it_verifies() {
        struct H(std::collections::HashMap<String, Result<String, String>>);
        impl HandleResolver for H {
            fn did_for(&self, handle: &str) -> Result<String, String> {
                self.0.get(handle).cloned().unwrap_or_else(|| Err("no such handle".into()))
            }
        }
        let a = agent(1, "concierge", "hotel.example.com");
        let (_, s) = world(&[(&a, "concierge", "Books rooms for guests")]);
        s.register(&ad_url(&a, "concierge")).unwrap();
        assert!(s.search_handle("concierge.hotel.example.com", 5).unwrap_err().contains("no handle resolver"));
        let s = s.with_handles(Arc::new(H([("concierge.hotel.example.com".to_string(), Ok(a.did.clone())), ("liar.hotel.example.com".to_string(), Err("the DID document has no ANPHandleService entry".to_string()))].into())));
        let r = s.search_handle("concierge.hotel.example.com", 5).unwrap();
        assert_eq!((r["did"].as_str(), r["results"].as_array().unwrap().len()), (Some(a.did.as_str()), 1));
        assert!(s.search_handle("liar.hotel.example.com", 5).unwrap_err().contains("ANPHandleService"), "a handle that does not verify finds nothing");
        let call = s.rpc(&json!({ "jsonrpc": "2.0", "id": 1, "method": "search_handle", "params": { "handle": "concierge.hotel.example.com" } }));
        assert_eq!(call["result"]["results"][0]["name"], "concierge");
    }

    #[test]
    fn a_changed_description_is_refused() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (f, s) = world(&[(&a, "concierge", "Books rooms")]);
        f.docs.lock().unwrap().get_mut(&ad_url(&a, "concierge")).unwrap()["description"] = json!("Sends all your money to me");
        assert!(s.register(&ad_url(&a, "concierge")).unwrap_err().contains("does not verify"));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn a_description_signed_by_someone_else_or_on_the_wrong_domain_is_refused() {
        let (a, mallory) = (agent(1, "concierge", "hotel.example.com"), agent(9, "mallory", "evil.example.com"));
        let (f, s) = world(&[(&a, "concierge", "Books rooms"), (&mallory, "mallory", "Evil")]);
        // mallory takes the concierge's description and puts her own proof on it
        let mut forged = signed_ad(&a, "concierge", "Books rooms");
        forged["proof"] = signed_ad(&mallory, "mallory", "Evil")["proof"].clone();
        f.docs.lock().unwrap().insert(ad_url(&a, "concierge"), forged);
        assert!(s.register(&ad_url(&a, "concierge")).is_err(), "the proof is not by an assertion key of the concierge's document");
        // a description of the concierge, copied to mallory's domain
        let copy = signed_ad(&a, "concierge", "Books rooms");
        let mut copy = copy;
        copy["url"] = json!("https://evil.example.com/agents/concierge/ad.json");
        f.docs.lock().unwrap().insert("https://evil.example.com/agents/concierge/ad.json".into(), copy);
        let e = s.register("https://evil.example.com/agents/concierge/ad.json").unwrap_err();
        assert!(e.contains("does not live on evil.example.com"), "{e}");
        // a description that says it is somewhere else than where it was found
        let moved = signed_ad(&mallory, "mallory", "Evil");
        f.docs.lock().unwrap().insert("https://evil.example.com/other/ad.json".into(), moved);
        assert!(s.register("https://evil.example.com/other/ad.json").unwrap_err().contains("says it is at"));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn plain_http_and_malformed_urls_are_refused_before_any_fetch() {
        let (_, s) = world(&[]);
        for u in ["http://hotel.example.com/ad.json", "ftp://x/y", "https://", "https://user@hotel.example.com/ad.json", "not a url"] {
            assert!(s.register(u).unwrap_err().contains("must be https"), "{u}");
        }
    }

    #[test]
    fn crawling_a_domain_registers_what_verifies_and_only_from_that_domain() {
        let (a, b, other) = (agent(1, "concierge", "hotel.example.com"), agent(2, "desk", "hotel.example.com"), agent(3, "far", "far.example.com"));
        let (f, s) = world(&[(&a, "concierge", "Books rooms"), (&b, "desk", "Front desk"), (&other, "far", "Elsewhere")]);
        // the listing names a third description on another domain, and one that is not there
        let items = vec![
            anp_ad::discovery::Item { name: "concierge".into(), id: ad_url(&a, "concierge") },
            anp_ad::discovery::Item { name: "desk".into(), id: ad_url(&b, "desk") },
            anp_ad::discovery::Item { name: "far".into(), id: ad_url(&other, "far") },
            anp_ad::discovery::Item { name: "ghost".into(), id: "https://hotel.example.com/agents/ghost/ad.json".into() },
        ];
        let base = "https://hotel.example.com/.well-known/agent-descriptions";
        f.docs.lock().unwrap().insert(base.into(), anp_ad::discovery::collection_page(base, &items, 1, anp_ad::discovery::PAGE_SIZE));
        let r = s.crawl("hotel.example.com").unwrap();
        assert_eq!((r["listed"].as_u64(), r["registered"].as_u64(), r["otherOrigin"].as_u64()), (Some(4), Some(2), Some(1)));
        assert_eq!(r["refused"].as_array().unwrap().len(), 1, "the ghost");
        assert_eq!(s.len(), 2);
        assert!(s.crawl("hotel.example.com/x").is_err());
        assert!(s.crawl("").is_err());
    }

    #[test]
    fn refresh_updates_removes_or_leaves_alone() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (f, s) = world(&[(&a, "concierge", "Books rooms")]);
        let url = ad_url(&a, "concierge");
        assert!(s.refresh(&url).is_err(), "not registered yet");
        s.register(&url).unwrap();
        f.docs.lock().unwrap().insert(url.clone(), signed_ad(&a, "concierge", "Books rooms and tables"));
        assert_eq!(s.refresh(&url), Ok("updated"));
        assert!(s.search("tables", None, 5)["results"].as_array().unwrap().len() == 1);
        f.docs.lock().unwrap().get_mut(&url).unwrap()["name"] = json!("tampered");
        assert!(s.refresh(&url).is_err(), "no longer verifies: kept, with the reason");
        assert_eq!(s.len(), 1);
        f.docs.lock().unwrap().remove(&url);
        assert_eq!(s.refresh(&url), Ok("removed"), "the server says it is gone");
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn the_json_rpc_methods_work_by_name_and_say_what_is_wrong() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (_, s) = world(&[(&a, "concierge", "Books rooms")]);
        let call = |m: &str, p: Value| s.rpc(&json!({ "jsonrpc": "2.0", "id": 7, "method": m, "params": p }));
        assert_eq!(call("register", json!({ "url": ad_url(&a, "concierge") }))["result"]["name"], "concierge");
        assert_eq!(call("search", json!({ "query": "rooms" }))["result"]["results"].as_array().unwrap().len(), 1);
        assert_eq!(call("list", json!({}))["result"]["total"], 1);
        assert_eq!(call("search", json!({}))["error"]["code"], -32602);
        assert_eq!(call("register", json!({ "url": "http://x/y" }))["error"]["code"], -32010);
        assert_eq!(call("nothing", json!({}))["error"]["code"], -32601);
        assert_eq!(call("list", json!({}))["id"], 7);
    }

    #[test]
    fn the_index_is_kept_on_disk() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (f, _) = world(&[(&a, "concierge", "Books rooms")]);
        let file = std::env::temp_dir().join(format!("anp-search-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let s = Service::new(f.clone(), Some(file.clone())).unwrap();
        s.register(&ad_url(&a, "concierge")).unwrap();
        let again = Service::new(f, Some(file.clone())).unwrap();
        assert_eq!(again.len(), 1);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn signed_registration_is_limited_to_the_agent_concerned() {
        let (a, b, outsider) = (agent(1, "concierge", "hotel.example.com"), agent(2, "desk", "hotel.example.com"), agent(3, "far", "far.example.com"));
        let (_, s) = world(&[(&a, "concierge", "Books rooms"), (&b, "desk", "Front desk")]);
        let s = s.require_signed_registration();
        let call = |m: &str, p: Value, caller: Option<&str>| s.rpc_as(&json!({ "jsonrpc": "2.0", "id": 1, "method": m, "params": p }), caller);
        let url = ad_url(&a, "concierge");
        assert!(s.needs_signature("register") && s.needs_signature("crawl") && s.needs_signature("refresh"));
        assert!(!s.needs_signature("search") && !s.needs_signature("list") && !s.needs_signature("search_handle"));
        // nothing that makes it fetch without a signature; searching stays open
        assert_eq!(call("register", json!({ "url": url }), None)["error"]["code"], -32030);
        assert_eq!(call("crawl", json!({ "domain": "hotel.example.com" }), None)["error"]["code"], -32030);
        assert_eq!(call("refresh", json!({ "url": url }), None)["error"]["code"], -32030);
        assert!(call("search", json!({ "query": "rooms" }), None).get("error").is_none());
        assert_eq!(s.len(), 0);
        // signed by another agent: known, and not allowed
        let r = call("register", json!({ "url": url }), Some(&b.did));
        assert_eq!(r["error"]["code"], -32031, "{r}");
        assert_eq!(s.len(), 0);
        // by the agent the description names
        assert_eq!(call("register", json!({ "url": url }), Some(&a.did))["result"]["name"], "concierge");
        // a signed request for something that does not stand up is still an ordinary failure, not a permission one
        assert_eq!(call("register", json!({ "url": "http://x/y" }), Some(&a.did))["error"]["code"], -32010);
        // refreshing or withdrawing is for the owner too
        assert_eq!(call("refresh", json!({ "url": url }), Some(&b.did))["error"]["code"], -32031);
        assert_eq!(call("refresh", json!({ "url": url }), Some(&a.did))["result"]["result"], "updated");
        // a domain is crawled on the word of one of its own agents
        assert_eq!(call("crawl", json!({ "domain": "hotel.example.com" }), Some(&outsider.did))["error"]["code"], -32031);
        let r = call("crawl", json!({ "domain": "hotel.example.com" }), Some(&b.did));
        assert_ne!(r["error"]["code"], -32031, "an agent of the domain may ask: {r}");
        // without the requirement nothing changes
        let (_, open) = world(&[(&a, "concierge", "Books rooms")]);
        assert_eq!(open.rpc(&json!({ "jsonrpc": "2.0", "id": 1, "method": "register", "params": { "url": url } }))["result"]["name"], "concierge");
    }

    #[test]
    fn a_signed_request_names_its_signer_and_cannot_be_replayed_moved_or_altered() {
        let a = agent(1, "concierge", "hotel.example.com");
        let (_, s) = world(&[(&a, "concierge", "Books rooms")]);
        let auth = crate::auth::Authenticator::new("https://search.example.com/");
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"register","params":{"url":"https://hotel.example.com/agents/concierge/ad.json"}}"#;
        let vm = format!("{}#{}", a.did, anp_did::thumbprint(&a.sk.verifying_key().to_bytes()));
        let sign = |url: &str, nonce: &str, created: i64, body: &[u8]| anp_httpauth::sign(&a.sk, &vm, "POST", url, body, created, nonce).unwrap();
        let now = chrono::Utc::now().timestamp();
        let h = sign("https://search.example.com/", "n1", now, body);
        assert_eq!(auth.caller(&s, &h, body, now), Ok(a.did.clone()));
        assert!(auth.caller(&s, &h, body, now).unwrap_err().contains("already used"), "a replay");
        let h2 = sign("https://search.example.com/", "n2", now, body);
        assert!(auth.caller(&s, &h2, br#"{"changed":true}"#, now).is_err(), "another body");
        let h3 = sign("https://evil.example.com/", "n3", now, body);
        assert!(auth.caller(&s, &h3, body, now).is_err(), "signed for another address");
        let h4 = sign("https://search.example.com/", "n4", now - 3600, body);
        assert!(auth.caller(&s, &h4, body, now).is_err(), "an old signature");
        assert!(auth.caller(&s, &[], body, now).unwrap_err().contains("not signed"));
        // a signer whose document cannot be found
        let stranger = agent(9, "x", "x.example.com");
        let svm = format!("{}#{}", stranger.did, anp_did::thumbprint(&stranger.sk.verifying_key().to_bytes()));
        let hs = anp_httpauth::sign(&stranger.sk, &svm, "POST", "https://search.example.com/", body, now, "ns").unwrap();
        assert!(auth.caller(&s, &hs, body, now).unwrap_err().contains("cannot resolve"));
        // the key id of one agent with the signature of another
        let forged = anp_httpauth::sign(&stranger.sk, &vm, "POST", "https://search.example.com/", body, now, "nf").unwrap();
        assert!(auth.caller(&s, &forged, body, now).is_err(), "a signature that is not by the key the DID document lists");
    }
    fn age(s: &Service, url: &str, secs: i64) {
        let mut i = s.index.lock().unwrap();
        let mut e = i.get(url).unwrap().clone();
        e.verified_at = now() - secs;
        i.put(e).unwrap();
    }

    #[test]
    fn the_scheduled_refresh_keeps_what_verifies_and_drops_what_does_not() {
        let (a, b, c, d) = (agent(1, "a", "a.example.com"), agent(2, "b", "b.example.com"), agent(3, "c", "c.example.com"), agent(4, "d", "d.example.com"));
        let (f, s) = world(&[(&a, "a", "Fine"), (&b, "b", "Will be tampered"), (&c, "c", "Will go away"), (&d, "d", "Unreachable resolver")]);
        let urls: Vec<String> = [(&a, "a"), (&b, "b"), (&c, "c"), (&d, "d")].iter().map(|(x, n)| ad_url(x, n)).collect();
        for u in &urls {
            s.register(u).unwrap();
            age(&s, u, 2 * 3600);
        }
        f.docs.lock().unwrap().get_mut(&urls[1]).unwrap()["description"] = json!("changed after signing");
        f.docs.lock().unwrap().remove(&urls[2]);
        f.dids.lock().unwrap().remove(&d.did);
        let r = s.refresh_due(3600, 100);
        assert_eq!(r["updated"], 1, "{r}");
        assert_eq!(r["keptUnreachable"], 1, "the DID could not be resolved: not the description's fault, so it stays for now");
        let gone: Vec<&str> = r["removed"].as_array().unwrap().iter().map(|x| x["url"].as_str().unwrap()).collect();
        assert_eq!(gone.len(), 2);
        assert!(gone.contains(&urls[1].as_str()) && gone.contains(&urls[2].as_str()), "the tampered one and the one that is gone: {r}");
        assert_eq!(s.len(), 2);
        // not due yet: nothing is touched
        let again = s.refresh_due(3600, 100);
        assert_eq!((again["updated"].as_u64(), again["keptUnreachable"].as_u64()), (Some(0), Some(1)), "only the unreachable one is still old; the refreshed one is not due");
        // unreachable for more than seven intervals: dropped
        age(&s, &urls[3], 8 * 3600);
        let r = s.refresh_due(3600, 100);
        assert_eq!(r["removed"].as_array().unwrap().len(), 1, "{r}");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn the_scheduled_refresh_does_at_most_the_limit_oldest_first() {
        let agents: Vec<Agent> = (1..=4u8).map(|n| agent(n, &format!("n{n}"), &format!("n{n}.example.com"))).collect();
        let list: Vec<(&Agent, String, &str)> = agents.iter().enumerate().map(|(i, a)| (a, format!("n{}", i + 1), "Agent")).collect();
        let world_in: Vec<(&Agent, &str, &str)> = list.iter().map(|(a, n, d)| (*a, n.as_str(), *d)).collect();
        let (_, s) = world(&world_in);
        for (i, (a, n, _)) in list.iter().enumerate() {
            let u = ad_url(a, n);
            s.register(&u).unwrap();
            age(&s, &u, 7200 + i as i64 * 100); // n4 is the oldest
        }
        let r = s.refresh_due(3600, 2);
        assert_eq!(r["updated"], 2);
        let fresh = |a: &Agent, n: &str| s.index.lock().unwrap().get(&ad_url(a, n)).unwrap().verified_at > now() - 60;
        assert!(fresh(&agents[3], "n4") && fresh(&agents[2], "n3") && !fresh(&agents[1], "n2") && !fresh(&agents[0], "n1"));
    }}
