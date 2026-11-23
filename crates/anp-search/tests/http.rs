//! The search agent as a program, over HTTP: signed registration (ANP-02), what an unsigned or misdirected request gets, and the database
//! store with the move from an index.json kept by an earlier version.

use anp_did::SigningKey;
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};

struct Agent {
    child: Child,
    port: u16,
    dir: std::path::PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn temp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("anp-search-http-{tag}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(dir: &std::path::Path, extra: &[String]) -> Agent {
    start_on(dir, free_port(), extra)
}

fn start_on(dir: &std::path::Path, port: u16, extra: &[String]) -> Agent {
    let mut args = vec!["--data".to_string(), dir.display().to_string(), "--http-port".into(), port.to_string(), "--did-host".into(), "search.example.com".into(), "--rate-limit".into(), "0".into(), "--refresh-hours".into(), "0".into()];
    args.extend(extra.iter().cloned());
    let child = Command::new(env!("CARGO_BIN_EXE_anp-search")).args(&args).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("start anp-search");
    let mut a = Agent { child, port, dir: dir.to_path_buf() };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return a;
        }
        if let Ok(Some(status)) = a.child.try_wait() {
            panic!("anp-search exited early: {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("anp-search did not listen");
}

fn rpc(port: u16, method: &str, params: Value, headers: &[(String, String)], body_override: Option<String>) -> (u16, Value) {
    let body = body_override.unwrap_or_else(|| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string());
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/")).set("content-type", "application/json");
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.send_string(&body) {
        Ok(r) => (r.status(), serde_json::from_str(&r.into_string().unwrap()).unwrap()),
        Err(ureq::Error::Status(c, r)) => (c, serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
        Err(e) => panic!("POST: {e}"),
    }
}

struct Caller {
    sk: SigningKey,
    vm: String,
}

fn caller(seed: u8, domain: &str) -> (Caller, std::path::PathBuf) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = anp_did::did_for_key(domain, None, &["agents", "caller"], &sk.verifying_key().to_bytes());
    let doc = anp_did::build_document(&did, &sk, &[], "2026-11-20T10:00:00Z").unwrap();
    let f = std::env::temp_dir().join(format!("anp-search-caller-{seed}-{}.did.json", std::process::id()));
    std::fs::write(&f, doc.to_string()).unwrap();
    let vm = format!("{did}#{}", anp_did::thumbprint(&sk.verifying_key().to_bytes()));
    (Caller { sk, vm }, f)
}

fn signed(c: &Caller, origin: &str, method: &str, params: Value, nonce: &str) -> (Vec<(String, String)>, String) {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    (anp_httpauth::sign(&c.sk, &c.vm, "POST", &format!("{origin}/"), body.as_bytes(), created, nonce).unwrap(), body)
}

#[test]
fn registration_needs_a_signature_from_the_agent_concerned_and_searching_does_not() {
    let (me, doc) = caller(7, "caller.example");
    let dir = temp("signed");
    // the public origin has to name the port the agent listens on, so the port is chosen first
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let agent = start_on(&dir, port, &["--require-signed-registration".into(), "--public-origin".into(), origin.clone(), "--store".into(), "json".into(), "--allow-caller".into(), doc.display().to_string()]);
    // searching is open
    let (status, v) = rpc(port, "search", json!({ "query": "rooms" }), &[], None);
    assert_eq!(status, 200, "{v}");
    assert!(v["result"]["results"].as_array().unwrap().is_empty());
    // registering, crawling and refreshing without a signature: refused before anything is fetched
    for (m, p) in [("register", json!({ "url": "https://localhost:9/ad.json" })), ("crawl", json!({ "domain": "caller.example" })), ("refresh", json!({ "url": "https://localhost:9/ad.json" }))] {
        let (status, v) = rpc(port, m, p, &[], None);
        assert_eq!((status, v["error"]["code"].as_i64()), (401, Some(-32030)), "{m}: {v}");
    }
    // signed by a DID it was given: the request gets through to the service, which then looks at what is asked
    let (h, body) = signed(&me, &origin, "crawl", json!({ "domain": "other.example" }), "n-crawl-other");
    let (status, v) = rpc(port, "crawl", Value::Null, &h, Some(body));
    assert_eq!((status, v["error"]["code"].as_i64()), (200, Some(-32031)), "an agent of caller.example cannot ask for other.example to be crawled: {v}");
    let (h, body) = signed(&me, &origin, "register", json!({ "url": "https://localhost:9/ad.json" }), "n-register");
    let (status, v) = rpc(port, "register", Value::Null, &h, Some(body.clone()));
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["error"]["code"], -32010, "past the signature, the description itself cannot be fetched: {v}");
    // the same signed request again is a replay
    let (status, v) = rpc(port, "register", Value::Null, &h, Some(body));
    assert_eq!((status, v["error"]["code"].as_i64()), (401, Some(-32030)), "{v}");
    // a signature for another address (a request captured on one agent and sent to another)
    let (h, body) = signed(&me, "http://127.0.0.1:1", "register", json!({ "url": "https://localhost:9/ad.json" }), "n-elsewhere");
    assert_eq!(rpc(port, "register", Value::Null, &h, Some(body)).0, 401);
    // a body changed after signing
    let (h, _) = signed(&me, &origin, "register", json!({ "url": "https://localhost:9/ad.json" }), "n-changed");
    let tampered = json!({ "jsonrpc": "2.0", "id": 1, "method": "register", "params": { "url": "https://localhost:9/other.json" } }).to_string();
    assert_eq!(rpc(port, "register", Value::Null, &h, Some(tampered)).0, 401);
    // a signer the agent has no document for (and cannot fetch)
    let (stranger, _) = caller(8, "stranger.example");
    let (h, body) = signed(&stranger, &origin, "register", json!({ "url": "https://localhost:9/ad.json" }), "n-stranger");
    assert_eq!(rpc(port, "register", Value::Null, &h, Some(body)).0, 401);
    drop(agent);
    let _ = std::fs::remove_file(&doc);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_index_json_from_an_earlier_version_moves_into_the_database_once() {
    let dir = temp("migrate");
    let entry = json!({ "url": "https://hotel.example.com/agents/concierge/ad.json", "did": "did:wba:hotel.example.com:agents:concierge:e1_x", "name": "concierge", "description": "Books rooms for guests", "protocols": ["A2A"], "offers": ["Room policies"], "verifiedAt": 1_700_000_000 });
    std::fs::write(dir.join("index.json"), json!([entry]).to_string()).unwrap();
    {
        let a = start(&dir, &[]);
        let (status, v) = rpc(a.port, "search", json!({ "query": "rooms" }), &[], None);
        assert_eq!(status, 200);
        assert_eq!(v["result"]["results"][0]["name"], "concierge", "{v}");
        assert!(!a.dir.join("index.json").exists() && a.dir.join("index.json.migrated").exists(), "the old file is set aside");
    }
    // a new run reads the database, not the file
    let a = start(&dir, &[]);
    let (_, v) = rpc(a.port, "list", json!({}), &[], None);
    assert_eq!(v["result"]["total"], 1, "{v}");
    assert!(a.dir.join("index.cblite2").exists(), "a Couchbase Lite database");
    drop(a);
    let _ = std::fs::remove_dir_all(&dir);
}