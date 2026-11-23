//! The resolver against a real HTTPS server on localhost, with certificates made here.

use anp_did::{build_document, did_for_key, SigningKey, WbaDid};
use anp_resolve::{Config, Method, ResolveError, Resolver};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}
fn ca(name: &str) -> Ca {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    Ca { cert: p.self_signed(&key).unwrap(), key }
}
/// A leaf certificate for `san`, signed by `ca`: its DER and the key (PKCS#8 DER).
fn leaf(ca: &Ca, san: &str) -> (Vec<u8>, Vec<u8>) {
    let p = CertificateParams::new(vec![san.to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

enum Route {
    Json(String),
    Redirect(String),
    Status(u16),
    Raw(Vec<u8>),
    Hang,
}

struct Server {
    port: u16,
    hits: Arc<AtomicUsize>,
    routes: Arc<Mutex<HashMap<String, Route>>>,
}

impl Server {
    fn start(cert: Vec<u8>, key: Vec<u8>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
                .unwrap(),
        );
        let hits = Arc::new(AtomicUsize::new(0));
        let routes: Arc<Mutex<HashMap<String, Route>>> = Arc::new(Mutex::new(HashMap::new()));
        let (h, r) = (hits.clone(), routes.clone());
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (cfg, h, r) = (cfg.clone(), h.clone(), r.clone());
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(cfg).unwrap();
                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                    let mut reader = BufReader::new(&mut tls);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line.is_empty() {
                        return; // the handshake failed (a client that does not trust us): nothing to serve
                    }
                    loop {
                        let mut l = String::new();
                        if reader.read_line(&mut l).is_err() || l == "\r\n" || l.is_empty() {
                            break;
                        }
                    }
                    h.fetch_add(1, Ordering::SeqCst);
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (status, headers, body): (String, String, Vec<u8>) = match r.lock().unwrap().get(&path) {
                        Some(Route::Json(b)) => ("200 OK".into(), "content-type: application/did+json\r\n".into(), b.clone().into_bytes()),
                        Some(Route::Raw(b)) => ("200 OK".into(), "content-type: application/json\r\n".into(), b.clone()),
                        Some(Route::Redirect(to)) => ("302 Found".into(), format!("location: {to}\r\n"), vec![]),
                        Some(Route::Status(c)) => (format!("{c} Status"), String::new(), vec![]),
                        Some(Route::Hang) => {
                            std::thread::sleep(Duration::from_secs(4));
                            return;
                        }
                        None => ("404 Not Found".into(), String::new(), vec![]),
                    };
                    drop(reader);
                    let _ = write!(tls, "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n", body.len());
                    let _ = tls.write_all(&body);
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        Server { port, hits, routes }
    }
    fn set(&self, path: &str, r: Route) {
        self.routes.lock().unwrap().insert(path.to_string(), r);
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn cfg(roots: Vec<Vec<u8>>) -> Config {
    Config { allow_private: true, extra_roots: roots, timeout: Duration::from_secs(3), ..Config::default() }
}

/// A server whose certificate is valid for `localhost` under `ca`.
fn good() -> (Server, Ca) {
    let ca = ca("test CA");
    let (c, k) = leaf(&ca, "localhost");
    (Server::start(c, k), ca)
}

/// An e1 DID on `localhost:<port>` and its (signed) document.
fn wba(port: u16, seed: u8) -> (String, Value, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = did_for_key("localhost", Some(port), &["agents", "bot"], &sk.verifying_key().to_bytes());
    let doc = build_document(&did, &sk, &[json!({ "id": format!("{did}#ad"), "type": "AgentDescription", "serviceEndpoint": "https://localhost/ad.json" })], "2026-11-13T10:00:00Z").unwrap();
    let path = WbaDid::parse(&did).unwrap().document_path();
    (did, doc, path)
}

#[test]
fn a_did_wba_document_is_fetched_over_https_verified_and_cached() {
    let (srv, ca) = good();
    let (did, doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Json(doc.to_string()));
    let r = Resolver::new(cfg(vec![ca.cert.der().to_vec()])).unwrap();
    let got = r.resolve(&did).expect("a good document resolves");
    assert_eq!(got.method, Method::Wba);
    assert_eq!(got.domain, format!("localhost:{}", srv.port));
    assert_eq!(got.url, format!("https://localhost:{}{path}", srv.port));
    let v = got.verified.expect("did:wba documents come back verified");
    assert_eq!(v.did_string, did);
    assert_eq!(v.service_endpoint("AgentDescription").as_deref(), Some("https://localhost/ad.json"));
    assert_eq!(srv.hits(), 1);
    r.resolve(&did).unwrap();
    assert_eq!(srv.hits(), 1, "the second resolution came from the cache");
    assert!(r.cached(&did).is_some());
    r.forget(&did);
    assert!(r.cached(&did).is_none());
    r.resolve(&did).unwrap();
    assert_eq!(srv.hits(), 2);
}

#[test]
fn a_did_web_document_resolves_and_must_name_itself() {
    let (srv, ca) = good();
    let r = Resolver::new(cfg(vec![ca.cert.der().to_vec()])).unwrap();
    let did = format!("did:web:localhost%3A{}:users:alice", srv.port);
    srv.set("/users/alice/did.json", Route::Json(json!({ "id": did, "verificationMethod": [], "authentication": [] }).to_string()));
    let got = r.resolve(&did).unwrap();
    assert_eq!(got.method, Method::Web);
    assert!(got.verified.is_none(), "a did:web document is vouched for by its domain, not by its key");
    let well_known = format!("did:web:localhost%3A{}", srv.port);
    srv.set("/.well-known/did.json", Route::Json(json!({ "id": "did:web:someone-else.example" }).to_string()));
    assert!(matches!(r.resolve(&well_known), Err(ResolveError::Invalid(m)) if m.contains("not")));
}

#[test]
fn a_certificate_nobody_trusts_is_a_failure_and_no_document_is_delivered() {
    let (srv, _ca) = good();
    let (did, doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Json(doc.to_string()));
    // no extra roots: the test CA is unknown
    let r = Resolver::new(cfg(vec![])).unwrap();
    assert!(matches!(r.resolve(&did), Err(ResolveError::Fetch(_))), "{:?}", r.resolve(&did));
    // a different CA is just as unknown
    let other = ca("another CA");
    let r = Resolver::new(cfg(vec![other.cert.der().to_vec()])).unwrap();
    assert!(matches!(r.resolve(&did), Err(ResolveError::Fetch(_))));
    assert_eq!(srv.hits(), 0, "the handshake failed before any request was made");
}

#[test]
fn a_certificate_for_another_hostname_is_refused() {
    let ca = ca("test CA");
    let (c, k) = leaf(&ca, "other.example");
    let srv = Server::start(c, k);
    let (did, doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Json(doc.to_string()));
    let r = Resolver::new(cfg(vec![ca.cert.der().to_vec()])).unwrap();
    assert!(matches!(r.resolve(&did), Err(ResolveError::Fetch(_))), "the chain is fine, the name is not");
    assert_eq!(srv.hits(), 0);
}

#[test]
fn redirects_errors_and_odd_bodies_are_not_documents() {
    let (srv, ca) = good();
    let roots = vec![ca.cert.der().to_vec()];
    let (did, doc, path) = wba(srv.port, 7);
    let r = || Resolver::new(cfg(roots.clone())).unwrap();
    srv.set(&path, Route::Redirect("https://localhost/elsewhere".into()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::Refused(m)) if m.contains("redirect")));
    srv.set(&path, Route::Status(404));
    assert_eq!(r().resolve(&did).unwrap_err(), ResolveError::Status(404));
    srv.set(&path, Route::Status(500));
    assert_eq!(r().resolve(&did).unwrap_err(), ResolveError::Status(500));
    srv.set(&path, Route::Raw(b"<html>not json</html>".to_vec()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::NotJson(_))));
    srv.set(&path, Route::Raw(vec![0xff, 0xfe, 0x00]));
    assert!(matches!(r().resolve(&did), Err(ResolveError::NotJson(_))));
    let big = json!({ "id": did, "pad": "x".repeat(70_000) }).to_string();
    srv.set(&path, Route::Raw(big.into_bytes()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::TooLarge(_))));
    // and the genuine document still works through the same resolver settings
    srv.set(&path, Route::Json(doc.to_string()));
    assert!(r().resolve(&did).is_ok());
    // a byte-order mark (Windows tools add them) is tolerated
    srv.set(&path, Route::Raw(format!("\u{feff}{doc}").into_bytes()));
    assert!(r().resolve(&did).is_ok());
}

#[test]
fn a_document_that_is_not_valid_for_the_did_is_refused() {
    let (srv, ca) = good();
    let roots = vec![ca.cert.der().to_vec()];
    let (did, doc, path) = wba(srv.port, 7);
    let r = || Resolver::new(cfg(roots.clone())).unwrap();
    // tampered after signing
    let mut t = doc.clone();
    t["service"][0]["serviceEndpoint"] = json!("https://evil.example/ad.json");
    srv.set(&path, Route::Json(t.to_string()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::Invalid(_))));
    // another agent's document at this URL (its id is not ours)
    let (_, other, _) = wba(srv.port, 8);
    srv.set(&path, Route::Json(other.to_string()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::Invalid(_))));
    // a document whose own id is right but whose key is not the one the DID names (a forged document)
    let mut forged = doc.clone();
    forged["verificationMethod"][0]["publicKeyMultibase"] = other["verificationMethod"][0]["publicKeyMultibase"].clone();
    srv.set(&path, Route::Json(forged.to_string()));
    assert!(matches!(r().resolve(&did), Err(ResolveError::Invalid(_))));
}

#[test]
fn internal_addresses_are_refused_unless_allowed() {
    let (srv, ca) = good();
    let (did, doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Json(doc.to_string()));
    // localhost resolves to a loopback address: with the default guard that is refused, and nothing is requested
    let strict = Config { allow_private: false, extra_roots: vec![ca.cert.der().to_vec()], timeout: Duration::from_secs(3), ..Config::default() };
    let r = Resolver::new(strict).unwrap();
    assert!(matches!(r.resolve(&did), Err(ResolveError::Refused(m)) if m.contains("internal")), "{:?}", r.resolve(&did));
    assert_eq!(srv.hits(), 0);
    // allowed explicitly, it works
    assert!(Resolver::new(cfg(vec![ca.cert.der().to_vec()])).unwrap().resolve(&did).is_ok());
}

#[test]
fn failures_are_remembered_briefly_and_the_cache_expires_and_is_bounded() {
    let (srv, ca) = good();
    let roots = vec![ca.cert.der().to_vec()];
    let (did, doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Status(500));
    let r = Resolver::new(Config { negative_ttl: Duration::from_millis(400), ttl: Duration::from_millis(400), ..cfg(roots.clone()) }).unwrap();
    assert_eq!(r.resolve(&did).unwrap_err(), ResolveError::Status(500));
    assert_eq!(r.resolve(&did).unwrap_err(), ResolveError::Status(500));
    assert_eq!(srv.hits(), 1, "the failure was remembered: a bad host is not hammered through us");
    srv.set(&path, Route::Json(doc.to_string()));
    std::thread::sleep(Duration::from_millis(500));
    assert!(r.resolve(&did).is_ok(), "after the negative ttl it is tried again");
    assert_eq!(srv.hits(), 2);
    std::thread::sleep(Duration::from_millis(500));
    assert!(r.cached(&did).is_none(), "an entry past its ttl is not served as cached");
    assert!(r.resolve(&did).is_ok());
    assert_eq!(srv.hits(), 3);
    // bounded
    let r = Resolver::new(Config { max_cache: 2, ..cfg(roots) }).unwrap();
    let dids: Vec<String> = (10..13u8)
        .map(|seed| {
            let (d, doc, p) = wba(srv.port, seed);
            srv.set(&p, Route::Json(doc.to_string()));
            d
        })
        .collect();
    for d in &dids {
        r.resolve(d).unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(r.cached(&dids[0]).is_none(), "the oldest entry made room");
    assert!(r.cached(&dids[1]).is_some() && r.cached(&dids[2]).is_some());
}

#[test]
fn a_server_that_never_answers_is_given_up_on() {
    let (srv, ca) = good();
    let (did, _doc, path) = wba(srv.port, 7);
    srv.set(&path, Route::Hang);
    let r = Resolver::new(Config { timeout: Duration::from_millis(600), ..cfg(vec![ca.cert.der().to_vec()]) }).unwrap();
    let t0 = std::time::Instant::now();
    assert!(matches!(r.resolve(&did), Err(ResolveError::Fetch(_))));
    assert!(t0.elapsed() < Duration::from_secs(3), "gave up after the timeout, not the server's 4 s");
}
