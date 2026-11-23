//! The search agent as a server: `anp-search --data DIR --http-port 8800 --did-host search.example.com`.
//!
//! Its own identity is a `did:wba` e1 DID (key in `DIR/search.key`); it publishes its DID document, its signed agent
//! description and its OpenRPC interface at the usual URLs, and speaks JSON-RPC at `POST /`. See the crate docs for what it
//! indexes. Registration is open (anyone can ask it to look at a description), so everything it fetches goes through the
//! guarded resolver and only what verifies is kept; `--allow-domain` narrows it to chosen domains.

struct WnsHandles(anp_wns::CachingClient);

impl anp_search::service::HandleResolver for WnsHandles {
    fn did_for(&self, handle: &str) -> Result<String, String> {
        let h = anp_wns::parse(handle).map_err(|e| e.to_string())?;
        self.0.verify(&h).map(|v| v.did).map_err(|e| e.to_string())
    }
}

use anp_search::{openrpc, ratelimit::Limiter, service::{FetchError, Fetcher, NetFetcher}, Service};

/// The network, except for DID documents the operator gave (`--allow-caller`): those are used as they are, for callers that cannot be fetched.
struct WithKnown {
    known: std::collections::HashMap<String, anp_did::Verified>,
    net: NetFetcher,
}

impl Fetcher for WithKnown {
    fn get_json(&self, url: &str) -> Result<Value, FetchError> {
        self.net.get_json(url)
    }
    fn did_document(&self, did: &str) -> Result<anp_did::Verified, String> {
        match self.known.get(did) {
            Some(v) => Ok(v.clone()),
            None => self.net.did_document(did),
        }
    }
}
use axum::{extract::{ConnectInfo, Path, State}, http::{header, HeaderMap, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

struct App {
    service: Arc<Service>,
    did: String,
    did_doc: Value,
    ad: Value,
    openrpc: Value,
    /// Per client, for the methods that fetch from the network.
    limiter: Option<Limiter>,
    /// Take the client address from `X-Forwarded-For` (only behind a proxy that sets it).
    trust_forwarded_for: bool,
    started: std::time::Instant,
    /// Checks the signature of a request for a method that needs one (`--require-signed-registration`).
    auth: Option<Arc<anp_search::auth::Authenticator>>,
}

fn usage() -> String {
    "usage: anp-search --data DIR --http-port P --did-host HOST[:PORT] [--allow-domain HOST[:PORT]]... [--resolver-roots CA.pem] [--handle-base URL (fetch handle documents from there, for tests)] [--resolver-allow-private]\n       [--rate-limit BURST (default 10, 0 = off)] [--rate-seconds S (one more request every S seconds, default 6)] [--trust-forwarded-for]\n       [--refresh-hours H (re-verify what is older, default 24, 0 = never)]\n       [--store cbl|json (default cbl: a Couchbase Lite database in DIR/index.cblite2; json: the single file DIR/index.json)]\n       [--require-signed-registration [--public-origin https://HOST[:PORT]] [--allow-caller DID_DOC.json]... (register, crawl and refresh only in requests signed by the agent concerned, ANP-02; callers' documents are fetched from their domains, or given here)]".into()
}

fn parse_args() -> Result<std::collections::HashMap<String, Vec<String>>, String> {
    let mut m: std::collections::HashMap<String, Vec<String>> = Default::default();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--resolver-allow-private" | "--trust-forwarded-for" | "--require-signed-registration" => m.entry(a).or_default().push(String::new()),
            "--data" | "--http-port" | "--did-host" | "--allow-domain" | "--resolver-roots" | "--handle-base" | "--rate-limit" | "--rate-seconds" | "--refresh-hours" | "--store" | "--public-origin" | "--allow-caller" => {
                let v = it.next().ok_or_else(|| format!("{a} needs a value\n{}", usage()))?;
                m.entry(a).or_default().push(v);
            }
            _ => return Err(usage()),
        }
    }
    Ok(m)
}

fn load_key(dir: &std::path::Path) -> Result<anp_did::SigningKey, String> {
    let f = dir.join("search.key");
    match std::fs::read_to_string(&f) {
        Ok(h) => {
            let b = hex::decode(h.trim()).map_err(|e| format!("{}: {e}", f.display()))?;
            let seed: [u8; 32] = b.try_into().map_err(|_| format!("{}: expected 32 bytes", f.display()))?;
            Ok(anp_did::SigningKey::from_bytes(&seed))
        }
        Err(_) => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
            std::fs::write(&f, hex::encode(seed)).map_err(|e| format!("{}: {e}", f.display()))?;
            Ok(anp_did::SigningKey::from_bytes(&seed))
        }
    }
}

fn build_identity(sk: &anp_did::SigningKey, auth: &str) -> Result<(String, Value, Value, Value), String> {
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (auth, None),
    };
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let did = anp_did::did_for_key(host, port, &["agents", "search"], &sk.verifying_key().to_bytes());
    let ad_url = format!("https://{auth}/agents/search/ad.json");
    let service = json!({ "id": format!("{did}#agent-description"), "type": "AgentDescription", "serviceEndpoint": ad_url });
    let did_doc = anp_did::build_document(&did, sk, &[service], &created).map_err(|e| e.to_string())?;
    let rpc_url = format!("https://{auth}/");
    let orpc = openrpc::interface(&rpc_url);
    let mut ad = anp_ad::build(&anp_ad::Spec {
        name: "search".into(),
        did: did.clone(),
        url: ad_url,
        description: Some("Finds agents: register an agent description or crawl a domain, then search what verified".into()),
        owner: None,
        created: created.clone(),
        informations: vec![anp_ad::Info { ty: "Information".into(), description: "Searches the descriptions it has verified: name, description and what each agent offers".into(), url: None }],
        interfaces: vec![anp_ad::Interface {
            ty: "StructuredInterface".into(),
            protocol: "openrpc".into(),
            version: None,
            url: format!("https://{auth}/agents/search/openrpc.json"),
            description: Some("register, crawl, refresh, search, list".into()),
            human_authorization: None,
        }],
    });
    anp_ad::sign(&mut ad, sk, &did, &created, Some((auth, &uuid_like()))).map_err(|e| e.0)?;
    Ok((did, did_doc, ad, orpc))
}

fn uuid_like() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    hex::encode(b)
}

fn json_response(v: &Value, ct: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct)], v.to_string()).into_response()
}

async fn did_document(State(app): State<Arc<App>>, Path((name, fp)): Path<(String, String)>) -> Response {
    let wanted = format!("/agents/{name}/{fp}/did.json");
    match anp_did::WbaDid::parse(&app.did) {
        Ok(d) if d.document_path() == wanted => json_response(&app.did_doc, "application/did+json"),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn ad_doc(State(app): State<Arc<App>>) -> Response {
    json_response(&app.ad, "application/json")
}

async fn openrpc_doc(State(app): State<Arc<App>>) -> Response {
    json_response(&app.openrpc, "application/json")
}

async fn listing(State(app): State<Arc<App>>) -> Response {
    let url = app.ad["url"].as_str().unwrap_or("");
    let base = anp_ad::discovery::origin(url).unwrap_or("").to_string();
    let items = [anp_ad::discovery::Item { name: "search".into(), id: url.to_string() }];
    json_response(&anp_ad::discovery::collection_page(&format!("{base}/.well-known/agent-descriptions"), &items, 1, anp_ad::discovery::PAGE_SIZE), "application/ld+json")
}

async fn rpc(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })).into_response(),
    };
    // the methods that make this agent fetch from the network are rationed per client; searching is not
    if let (Some(limiter), Some("register" | "crawl" | "refresh")) = (&app.limiter, req["method"].as_str()) {
        let client = if app.trust_forwarded_for {
            headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next()).map(|s| s.trim().to_string()).unwrap_or_else(|| peer.ip().to_string())
        } else {
            peer.ip().to_string()
        };
        if let Err(wait) = limiter.allow(&client, app.started.elapsed().as_secs_f64()) {
            let body = json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32029, "message": format!("rate limited: try again in {wait} s") } });
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, wait.to_string())], Json(body)).into_response();
        }
    }
    // a method that needs a signature: the signer is worked out first (it may fetch the caller's DID document), then the service decides what it may do
    let wants_signature = req["method"].as_str().map_or(false, |m| app.service.needs_signature(m));
    let svc = app.service.clone();
    let signer: Option<String> = if wants_signature {
        let (auth, svc2) = (app.auth.clone(), svc.clone());
        let hdrs: Vec<(String, String)> = headers.iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string()))).collect();
        let (b2, now) = (body.clone(), chrono::Utc::now().timestamp());
        match tokio::task::spawn_blocking(move || match auth {
            Some(a) => a.caller(&svc2, &hdrs, &b2, now),
            None => Err("this agent is not set up to check signatures".to_string()),
        })
        .await
        {
            Ok(Ok(did)) => Some(did),
            Ok(Err(why)) => {
                let body = json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32030, "message": format!("signed request required: {why}") } });
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        None
    };
    match tokio::task::spawn_blocking(move || svc.rpc_as(&req, signer.as_deref())).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    if let Err(e) = run().await {
        eprintln!("anp-search: {e}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let a = parse_args()?;
    let one = |k: &str| a.get(k).and_then(|v| v.first().cloned());
    let dir = std::path::PathBuf::from(one("--data").ok_or_else(usage)?);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let port: u16 = one("--http-port").ok_or_else(usage)?.parse().map_err(|_| "--http-port must be a number".to_string())?;
    let auth = one("--did-host").ok_or_else(usage)?.to_ascii_lowercase();
    let mut roots = vec![];
    if let Some(p) = one("--resolver-roots") {
        roots = anp_resolve::pem_certificates(&std::fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?)?;
    }
    let resolver = anp_resolve::Resolver::new(anp_resolve::Config { allow_private: a.contains_key("--resolver-allow-private"), extra_roots: roots.clone(), max_bytes: 256 * 1024, ..Default::default() })?;
    let wns_cfg = anp_resolve::Config { allow_private: a.contains_key("--resolver-allow-private"), extra_roots: roots, max_bytes: 256 * 1024, ..Default::default() };
    // the index: a Couchbase Lite database (one document per entry), or the single JSON file
    let store: Arc<dyn anp_search::store::Store> = match one("--store").as_deref().unwrap_or("cbl") {
        "json" => Arc::new(anp_search::store::JsonFile::open(&dir.join("index.json"))?),
        "cbl" => {
            let db = Arc::new(anp_search::store::Cbl::open(&dir, "index")?);
            // an index kept by an earlier version in index.json comes along once
            let old = dir.join("index.json");
            if old.exists() && anp_search::store::Store::load(&*db)?.is_empty() {
                let from = anp_search::store::JsonFile::open(&old)?;
                let entries = anp_search::store::Store::load(&from)?;
                for e in &entries {
                    anp_search::store::Store::put(&*db, e)?;
                }
                std::fs::rename(&old, dir.join("index.json.migrated")).map_err(|e| e.to_string())?;
                println!("moved {} entries from index.json into the database (the old file is index.json.migrated)", entries.len());
            }
            db
        }
        other => return Err(format!("--store is cbl or json, not {other}")),
    };
    let mut known = std::collections::HashMap::new();
    for f in a.get("--allow-caller").into_iter().flatten() {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?).map_err(|e| format!("{f}: {e}"))?;
        let did = doc["id"].as_str().ok_or_else(|| format!("{f}: no id"))?.to_string();
        let verified = anp_did::verify_document(&doc, Some(&did)).map_err(|e| format!("{f}: {e}"))?;
        known.insert(did, verified);
    }
    let mut service = Service::with_store(Arc::new(WithKnown { known, net: NetFetcher(resolver) }), Some(store))?;
    if a.contains_key("--require-signed-registration") {
        service = service.require_signed_registration();
    }
    // handles (ANP-04): verified both ways, answers kept for the provider's ttl, an older binding refused after a newer one was seen
    let mut wns = anp_wns::CachingClient::new(anp_wns::Client::new(wns_cfg)?);
    if let Some(base) = one("--handle-base") {
        wns.client = wns.client.with_base(&base);
    }
    service = service.with_handles(Arc::new(WnsHandles(wns)));
    if let Some(d) = a.get("--allow-domain") {
        service = service.restrict_to(d.clone());
    }
    let sk = load_key(&dir)?;
    let (did, did_doc, ad, openrpc) = build_identity(&sk, &auth)?;
    println!("DID {did}");
    println!("search agent on http://0.0.0.0:{port} (describes itself as https://{auth}; put TLS in front); {} entries indexed", service.len());
    let num = |k: &str, d: f64| -> Result<f64, String> { one(k).map_or(Ok(d), |v| v.parse::<f64>().map_err(|_| format!("{k} must be a number"))) };
    let (burst, per, refresh_hours) = (num("--rate-limit", 10.0)?, num("--rate-seconds", 6.0)?, num("--refresh-hours", 24.0)?);
    let limiter = (burst >= 1.0).then(|| Limiter::new(burst as u32, per));
    let service = Arc::new(service);
    let signer_auth = a.contains_key("--require-signed-registration").then(|| Arc::new(anp_search::auth::Authenticator::new(&one("--public-origin").unwrap_or_else(|| format!("https://{auth}")))));
    if refresh_hours > 0.0 {
        // what has not been verified for a while is looked at again, so that the index holds only what still stands
        let (svc, max_age) = (service.clone(), (refresh_hours * 3600.0) as i64);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600.min(max_age.max(1) as u64))).await;
                let s = svc.clone();
                match tokio::task::spawn_blocking(move || s.refresh_due(max_age, 50)).await {
                    Ok(r) if r["updated"] != 0 || r["keptUnreachable"] != 0 || !r["removed"].as_array().map_or(true, |a| a.is_empty()) => log::info!("scheduled refresh: {r}"),
                    Ok(_) => {}
                    Err(e) => log::warn!("scheduled refresh failed: {e}"),
                }
            }
        });
    }
    let app = Arc::new(App { service, did, did_doc, ad, openrpc, limiter, trust_forwarded_for: a.contains_key("--trust-forwarded-for"), started: std::time::Instant::now(), auth: signer_auth });
    let router = Router::new()
        .route("/agents/:name/:fingerprint/did.json", get(did_document))
        .route("/agents/search/ad.json", get(ad_doc))
        .route("/agents/search/openrpc.json", get(openrpc_doc))
        .route("/.well-known/agent-descriptions", get(listing))
        .route("/", post(rpc))
        .with_state(app);
    let l = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| e.to_string())?;
    axum::serve(l, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.map_err(|e| e.to_string())
}