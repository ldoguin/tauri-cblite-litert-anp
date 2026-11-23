//! Checks against the ANP SDK's published authentication vectors (agent-network-protocol/anp, Apache-2.0; see
//! `testdata/anp-sdk/NOTICE.md`), plus our own signer and the attacks a verifier must stop.

use anp_httpauth::{anp_did, sign, verify, Policy, ReplayCache, Request};
use serde_json::Value;

fn load(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}
fn headers(v: &Value) -> Vec<(String, String)> {
    v.as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()).unwrap_or_default()
}

#[test]
fn the_sdks_security_vectors_are_accepted_and_rejected_as_it_does() {
    let v = load(include_str!("../../../testdata/anp-sdk/authentication_security_vectors_v1.json"));
    let policy = Policy { max_age: v["policy"]["maxAgeSeconds"].as_i64().unwrap(), future_skew: v["policy"]["futureSkewSeconds"].as_i64().unwrap(), require_nonce: false };
    let now = v["now"].as_i64().unwrap();
    let doc = v["document"].clone();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    let mut wrong = Vec::new();
    for c in cases {
        let h = headers(&c["headers"]);
        let req = Request { method: c["method"].as_str().unwrap(), url: c["url"].as_str().unwrap(), headers: &h, body: c["body"].as_str().unwrap_or("").as_bytes() };
        let got = verify(&req, &|k| anp_did::authentication_key(&doc, k), &policy, now);
        let want = c["accepted"].as_bool().unwrap();
        if got.is_ok() != want {
            wrong.push(format!("{}: expected accepted={want}, got {:?}", c["id"], got.map(|_| ())));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn every_authority_spelling_in_the_sdks_compatibility_vectors_verifies() {
    // default port written or not, IPv6 bracketed or not, expanded or compressed: all sign the same target URI
    let v = load(include_str!("../../../testdata/anp-sdk/authentication_authority_compatibility_v1.json"));
    let doc = v["document"].clone();
    let now = v["now"].as_i64().unwrap();
    let mut wrong = Vec::new();
    for c in v["cases"].as_array().unwrap() {
        let h = headers(&c["headers"]);
        let req = Request { method: "GET", url: c["url"].as_str().unwrap(), headers: &h, body: b"" };
        if let Err(e) = verify(&req, &|k| anp_did::authentication_key(&doc, k), &Policy::default(), now) {
            wrong.push(format!("{}: {e}", c["id"]));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn an_ipv4_mapped_ipv6_alias_is_refused() {
    let v = load(include_str!("../../../testdata/anp-sdk/authentication_authority_compatibility_v1.json"));
    let doc = v["document"].clone();
    let c = &v["cases"][2]; // an @authority case; same signature, but the URL now names a mapped alias
    let h = headers(&c["headers"]);
    let req = Request { method: "GET", url: "https://[::ffff:192.0.2.1]:443/rpc", headers: &h, body: b"" };
    assert!(verify(&req, &|k| anp_did::authentication_key(&doc, k), &Policy::default(), v["now"].as_i64().unwrap()).is_err());
}

// ── our own signer and verifier ─────────────────────────────────────────────────────────────────────────

const NOW: i64 = 1_794_556_800;
fn identity() -> (anp_did::SigningKey, String, Value) {
    let sk = anp_did::SigningKey::from_bytes(&[42; 32]);
    let did = anp_did::did_for_key("alice.example.com", None, &["agents", "alice"], &sk.verifying_key().to_bytes());
    let doc = anp_did::build_document(&did, &sk, &[], "2026-11-13T10:00:00Z").unwrap();
    (sk, did, doc)
}
fn key_id(did: &str) -> String {
    format!("{did}#{}", did.rsplit(':').next().unwrap().trim_start_matches("e1_"))
}

#[test]
fn a_request_we_signed_verifies_and_every_change_breaks_it() {
    let (sk, did, doc) = identity();
    let kid = key_id(&did);
    let url = "https://node.example.com:8800/rpc?x=1";
    let body = br#"{"jsonrpc":"2.0","method":"ListTasks"}"#;
    let h = sign(&sk, &kid, "POST", url, body, NOW, "n-1").unwrap();
    let find = |k: &str| anp_did::authentication_key(&doc, k);
    let ok = verify(&Request { method: "POST", url, headers: &h, body }, &find, &Policy::default(), NOW).unwrap();
    assert_eq!(ok.did, did);
    assert_eq!(ok.nonce.as_deref(), Some("n-1"));
    // another method, URL (path, query, host, scheme), or body
    let bad = |m: &str, u: &str, b: &[u8]| verify(&Request { method: m, url: u, headers: &h, body: b }, &find, &Policy::default(), NOW);
    assert!(bad("GET", url, body).is_err(), "method");
    assert!(bad("POST", "https://node.example.com:8800/other?x=1", body).is_err(), "path");
    assert!(bad("POST", "https://node.example.com:8800/rpc?x=2", body).is_err(), "query");
    assert!(bad("POST", "https://evil.example.com:8800/rpc?x=1", body).is_err(), "host (the signature covers @authority)");
    assert!(bad("POST", "http://node.example.com:8800/rpc?x=1", body).is_err(), "scheme (the target URI is signed)");
    assert!(bad("POST", url, b"{}").is_err(), "body");
    // a stripped or tampered header
    let without = |name: &str| -> Vec<(String, String)> { h.iter().filter(|(k, _)| !k.eq_ignore_ascii_case(name)).cloned().collect() };
    for name in ["Signature", "Signature-Input", "Content-Digest"] {
        let hh = without(name);
        assert!(verify(&Request { method: "POST", url, headers: &hh, body }, &find, &Policy::default(), NOW).is_err(), "{name} removed");
    }
    let mut tampered = h.clone();
    for (k, v) in tampered.iter_mut() {
        if k == "Signature-Input" {
            *v = v.replace("expires=", "expires=9");
        }
    }
    assert!(verify(&Request { method: "POST", url, headers: &tampered, body }, &find, &Policy::default(), NOW).is_err(), "signed parameters are covered");
}

#[test]
fn the_wrong_key_the_wrong_document_and_stale_signatures_are_refused() {
    let (sk, did, doc) = identity();
    let kid = key_id(&did);
    let url = "https://node.example.com/rpc";
    let h = sign(&sk, &kid, "GET", url, b"", NOW, "n").unwrap();
    let req = Request { method: "GET", url, headers: &h, body: b"" };
    let p = Policy::default();
    // someone else's key under the same key id
    let other = anp_did::SigningKey::from_bytes(&[43; 32]).verifying_key();
    assert!(verify(&req, &|_| Some(other), &p, NOW).is_err());
    // a key id the document does not list for authentication
    assert!(verify(&req, &|_| None, &p, NOW).is_err());
    let mut no_auth = doc.clone();
    no_auth["authentication"] = serde_json::json!([]);
    assert!(verify(&req, &|k| anp_did::authentication_key(&no_auth, k), &p, NOW).is_err());
    // time
    assert!(verify(&req, &|k| anp_did::authentication_key(&doc, k), &p, NOW + 301).is_err(), "too old");
    assert!(verify(&req, &|k| anp_did::authentication_key(&doc, k), &p, NOW - 61).is_err(), "from the future");
    assert!(verify(&req, &|k| anp_did::authentication_key(&doc, k), &p, NOW + 300).is_ok(), "at the age limit");
    // a nonce can be demanded
    let strict = Policy { require_nonce: true, ..Policy::default() };
    assert!(verify(&req, &|k| anp_did::authentication_key(&doc, k), &strict, NOW).is_ok());
}

#[test]
fn a_replayed_request_is_recognised() {
    let (sk, did, doc) = identity();
    let kid = key_id(&did);
    let url = "https://node.example.com/rpc";
    let h = sign(&sk, &kid, "GET", url, b"", NOW, "once").unwrap();
    let find = |k: &str| anp_did::authentication_key(&doc, k);
    let cache = ReplayCache::new(&Policy::default());
    let v1 = verify(&Request { method: "GET", url, headers: &h, body: b"" }, &find, &Policy::default(), NOW).unwrap();
    assert!(cache.accept(&v1, NOW));
    let v2 = verify(&Request { method: "GET", url, headers: &h, body: b"" }, &find, &Policy::default(), NOW + 5).unwrap();
    assert!(!cache.accept(&v2, NOW + 5), "the same signature again");
    // a fresh nonce is a new request; after the window the entry is forgotten (the signature is too old by then anyway)
    let h2 = sign(&sk, &kid, "GET", url, b"", NOW + 6, "twice").unwrap();
    let v3 = verify(&Request { method: "GET", url, headers: &h2, body: b"" }, &find, &Policy::default(), NOW + 6).unwrap();
    assert!(cache.accept(&v3, NOW + 6));
    assert!(cache.accept(&v1, NOW + 1000), "forgotten after the window");
}
// ── live checks against the SDK itself: fixtures exchanged through files (see scripts/interop) ──────────

/// Writes a request this crate signed, with its DID document, to `ANP_FIXTURE_OUT`, for the SDK to verify.
#[test]
fn dump_signed_request_for_the_sdk() {
    let Ok(path) = std::env::var("ANP_FIXTURE_OUT") else { return };
    let (sk, did, doc) = identity();
    let (url, body) = ("https://node.example.com:8800/rpc?x=1", br#"{"jsonrpc":"2.0","method":"ListTasks"}"#.to_vec());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let h = sign(&sk, &key_id(&did), "POST", url, &body, now, "interop-nonce-1").unwrap();
    let out = serde_json::json!({ "did_document": doc, "method": "POST", "url": url, "body": String::from_utf8(body).unwrap(), "headers": h.into_iter().collect::<std::collections::BTreeMap<_, _>>() });
    std::fs::write(path, out.to_string()).unwrap();
}

/// Verifies a request the SDK signed, from the file named by `ANP_SDK_REQUEST` (written by `sdk_sign_request.py`).
#[test]
fn a_request_signed_by_the_sdk_verifies() {
    let Ok(path) = std::env::var("ANP_SDK_REQUEST") else { return };
    let v = load(&std::fs::read_to_string(path).unwrap());
    let doc = v["did_document"].clone();
    let h = headers(&v["headers"]);
    let body = v["body"].as_str().unwrap().as_bytes();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let req = Request { method: v["method"].as_str().unwrap(), url: v["url"].as_str().unwrap(), headers: &h, body };
    let ok = verify(&req, &|k| anp_did::authentication_key(&doc, k), &Policy::default(), now).expect("the SDK's signed request must verify");
    assert_eq!(ok.did, doc["id"].as_str().unwrap());
    // and the same request with a changed body does not
    let bad = Request { body: b"{}", ..req };
    assert!(verify(&bad, &|k| anp_did::authentication_key(&doc, k), &Policy::default(), now).is_err());
}