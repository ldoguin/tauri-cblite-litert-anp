//! The P5 v2 wire objects against the ANP SDK's published vectors (`testdata/anp-sdk`, Apache-2.0).

use anp_e2ee::wire::*;
use serde_json::{json, Value};

fn v() -> Value {
    serde_json::from_str(include_str!("../../../testdata/anp-sdk/direct_e2ee_p5_v2_wire_vectors.json")).unwrap()
}

#[test]
fn every_request_and_result_in_the_vectors_parses() {
    let v = v();
    let (meta, body, init) = parse_direct_send_request(&v["direct_init_request"]).unwrap();
    assert!(init);
    assert_eq!(meta["message_id"], "msg-a-b-001");
    assert_eq!(body["recipient_one_time_prekey_id"], "opk-b-001");
    let (_, body, init) = parse_direct_send_request(&v["direct_cipher_request"]).unwrap();
    assert!(!init);
    assert_eq!(body["ratchet_header"]["n"], "1");
    parse_direct_send_result(&v["direct_send_result"]).unwrap();
    let (meta, bundle, opks) = parse_publish_prekey_bundle_request(&v["publish_request"]).unwrap();
    assert_eq!(meta["target"]["kind"], "service");
    assert_eq!(bundle["bundle_id"], "bundle-b-001");
    assert_eq!(opks.len(), 1);
    parse_publish_prekey_bundle_result(&v["publish_result"]).unwrap();
    let (_, did, dev, suite, require_opk) = parse_get_prekey_bundle_request(&v["get_request"]).unwrap();
    assert_eq!((did.as_str(), dev.as_str()), ("did:wba:b.example:agents:bob:e1_fixture", "dev-b-9R5TLM"));
    assert_eq!(suite.as_deref(), Some("ANP-DIRECT-E2EE-X3DH-25519-AES256GCM-SHA256-V1"));
    assert!(require_opk);
    parse_get_prekey_bundle_result(&v["get_result"]).unwrap();
}

#[test]
fn our_builders_reproduce_the_vectors_exactly() {
    let v = v();
    let m = &v["direct_init_request"]["params"];
    assert_eq!(direct_send_request(&m["meta"], &m["body"]).unwrap(), v["direct_init_request"]);
    let m = &v["direct_cipher_request"]["params"];
    assert_eq!(direct_send_request(&m["meta"], &m["body"]).unwrap(), v["direct_cipher_request"]);
    let m = &v["publish_request"]["params"];
    let opks = m["body"]["one_time_prekeys"].as_array().unwrap();
    assert_eq!(publish_prekey_bundle_request(&m["meta"], &m["body"]["prekey_bundle"], opks).unwrap(), v["publish_request"]);
    let m = &v["get_request"]["params"];
    assert_eq!(
        get_prekey_bundle_request(&m["meta"], "did:wba:b.example:agents:bob:e1_fixture", "dev-b-9R5TLM", Some("ANP-DIRECT-E2EE-X3DH-25519-AES256GCM-SHA256-V1"), Some(true)).unwrap(),
        v["get_request"]
    );
    let r = &v["direct_send_result"];
    assert_eq!(direct_send_result("msg-a-b-001", "did:wba:b.example:agents:bob:e1_fixture", "dev-b-9R5TLM", "2026-07-19T00:01:01Z"), *r);
    let r = &v["publish_result"];
    assert_eq!(publish_prekey_bundle_result("did:wba:b.example:agents:bob:e1_fixture", "dev-b-9R5TLM", "bundle-b-001", "2026-07-19T00:00:01Z", 1), *r);
    let r = &v["get_result"];
    assert_eq!(get_prekey_bundle_result("did:wba:b.example:agents:bob:e1_fixture", "dev-b-9R5TLM", &r["prekey_bundle"], Some(&r["one_time_prekey"])), *r);
}

#[test]
fn the_error_table_is_the_sdks() {
    let v = v();
    let theirs: Vec<(i64, String)> = v["errors"].as_array().unwrap().iter().map(|e| (e["code"].as_i64().unwrap(), e["anp_code"].as_str().unwrap().to_string())).collect();
    let ours: Vec<(i64, String)> = ERRORS.iter().map(|(c, n)| (*c as i64, n.to_string())).collect();
    assert_eq!(ours, theirs);
    assert_eq!(error_name(4009), Some("anp.direct.e2ee.decrypt_failed"));
    assert_eq!(error_code("anp.direct.e2ee.invalid_security_binding"), Some(4012));
    let e = rpc_error(4008, "seen before");
    assert_eq!((e["code"].as_i64(), e["message"].as_str()), (Some(4008), Some("anp.direct.e2ee.replay_detected")));
}

#[test]
fn the_negative_encodings_in_the_vectors_are_refused() {
    let v = v();
    let neg = &v["encoding_negative_values"];
    let base = v["direct_init_request"].clone();
    let with = |path: &str, val: &Value| -> Value {
        let mut r = base.clone();
        let (obj, key) = path.rsplit_once('/').unwrap();
        r.pointer_mut(obj).unwrap()[key] = val.clone();
        r
    };
    assert!(parse_direct_send_request(&with("/params/body/session_id", &neg["session_id"])).is_err(), "padded, wrong length");
    assert!(parse_direct_send_request(&with("/params/body/sender_ephemeral_pub_b64u", &neg["x25519_public_key"])).is_err());
    assert!(parse_direct_send_request(&with("/params/body/ciphertext_b64u", &neg["ciphertext_b64u"])).is_err(), "padding is not allowed");
    assert!(parse_direct_send_request(&with("/params/meta/created_at", &neg["created_at"])).is_err());
    assert!(parse_direct_send_request(&base).is_ok(), "and the genuine request still parses");
}

#[test]
fn the_rules_the_sdk_enforces_are_enforced_here() {
    let v = v();
    let init = v["direct_init_request"].clone();
    let tweak = |f: &dyn Fn(&mut Value)| -> Value {
        let mut r = init.clone();
        f(&mut r);
        r
    };
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["meta"]["operation_id"] = json!("other"))).is_err(), "operation_id must equal message_id");
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["meta"]["extra"] = json!(1))).is_err(), "an unknown member");
    assert!(parse_direct_send_request(&tweak(&|r| r["extra"] = json!(1))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| r["method"] = json!("direct.recv"))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["meta"]["target"]["kind"] = json!("service"))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["meta"]["security_profile"] = json!("transport-protected"))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["meta"]["content_type"] = json!("text/plain"))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| r["params"]["body"]["suite"] = json!("OTHER"))).is_err());
    assert!(parse_direct_send_request(&tweak(&|r| { r["params"]["body"].as_object_mut().unwrap().remove("ciphertext_b64u"); })).is_err());
    // a cipher body under the init content type
    assert!(direct_send_request(&init["params"]["meta"], &v["direct_cipher_request"]["params"]["body"]).is_err());
    // counters are canonical decimal strings
    let cipher = v["direct_cipher_request"].clone();
    for bad in ["01", "-1", "", "1.0", "4294967296"] {
        let mut c = cipher.clone();
        c["params"]["body"]["ratchet_header"]["n"] = json!(bad);
        assert!(parse_direct_send_request(&c).is_err(), "n = {bad:?}");
    }
    // key service
    let publish = v["publish_request"].clone();
    let mut p = publish.clone();
    p["params"]["meta"]["sender_device_id"] = json!("dev-someone-else");
    assert!(parse_publish_prekey_bundle_request(&p).is_err(), "a device may only publish its own bundle");
    let mut p = publish.clone();
    p["params"]["body"]["one_time_prekeys"] = json!([]);
    assert!(parse_publish_prekey_bundle_request(&p).is_err(), "one_time_prekeys is omitted or non-empty");
    let mut p = publish.clone();
    p["params"]["meta"]["security_profile"] = json!("direct-e2ee");
    assert!(parse_publish_prekey_bundle_request(&p).is_err(), "key-service calls are transport-protected");
    let get = v["get_request"].clone();
    let mut g = get.clone();
    g["params"]["body"]["preferred_suite"] = json!("");
    assert!(parse_get_prekey_bundle_request(&g).is_err());
    let mut g = get.clone();
    g["params"]["body"]["require_opk"] = json!("yes");
    assert!(parse_get_prekey_bundle_request(&g).is_err());
    // results
    let mut r = v["get_result"].clone();
    r["target_device_id"] = json!("dev-other");
    assert!(parse_get_prekey_bundle_result(&r).is_err(), "the bundle returned must be the one asked for");
    let mut r = v["direct_send_result"].clone();
    r["accepted"] = json!(false);
    assert!(parse_direct_send_result(&r).is_err());
    let mut r = v["publish_result"].clone();
    r["published_at"] = json!("yesterday");
    assert!(parse_publish_prekey_bundle_result(&r).is_err());
}

#[test]
fn rfc3339_timestamps() {
    for ok in ["2026-07-19T00:00:00Z", "2026-07-19T00:00:00.123Z", "2026-07-19T01:02:03+02:00", "2026-07-19t00:00:00z"] {
        assert!(is_rfc3339(ok), "{ok}");
    }
    for bad in ["2026-07-19", "not-rfc3339", "2026-07-19 00:00:00Z", "2026-07-19T00:00:00", "2026-07-19T00:00:00.Z", "2026-07-19T00:00:00+0200"] {
        assert!(!is_rfc3339(bad), "{bad}");
    }
}

#[test]
fn session_failures_map_to_p5_error_codes() {
    use anp_e2ee::E2eeError;
    assert_eq!(error_code_for(&E2eeError("too many messages skipped".into())), 4010);
    assert_eq!(error_code_for(&E2eeError("a replay, or a message whose key is gone".into())), 4008);
    assert_eq!(error_code_for(&E2eeError("decryption failed (wrong key, or the message was altered or moved)".into())), 4009);
    assert_eq!(error_code_for(&E2eeError("the first reply must have pn = 0 and n = 0".into())), 4007);
    assert_eq!(error_code_for(&E2eeError("the sender's key-agreement id does not match".into())), 4012);
}
