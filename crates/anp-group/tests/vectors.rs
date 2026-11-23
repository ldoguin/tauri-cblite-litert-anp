//! The SDK's shared P6 v2 wire vectors (testdata/anp-sdk/group_e2ee_p6_v2_wire_vectors.json): every object must be read and rebuilt, and
//! the canonical bytes must be exactly the SDK's. Then the negative cases and the cryptographic parts (binding, origin proof).

use anp_did::SigningKey;
use anp_group::{aad, binding, origin, wire, *};
use serde_json::{json, Value};

fn fx() -> Value {
    serde_json::from_str(include_str!("../../../testdata/anp-sdk/group_e2ee_p6_v2_wire_vectors.json")).unwrap()
}

fn round_trip(method: &str, v: &Value) {
    let (meta, body, auth) = wire::parse_request(method, v).unwrap_or_else(|e| panic!("{method}: {e}"));
    assert_eq!(&wire::request(method, &meta, &body, auth.as_ref()).unwrap(), v, "{method} is rebuilt as it was read");
}

#[test]
fn every_request_and_notification_of_the_vectors_is_read_and_rebuilt() {
    let f = fx();
    for (name, method) in [
        ("publish_request", METHOD_PUBLISH_KEY_PACKAGE),
        ("get_request", METHOD_GET_KEY_PACKAGE),
        ("create_request", METHOD_CREATE),
        ("add_request", METHOD_ADD),
        ("remove_request", METHOD_REMOVE),
        ("send_request", METHOD_SEND),
        ("notice_notification", METHOD_NOTICE),
        ("incoming_notification", METHOD_INCOMING),
    ] {
        round_trip(method, &f[name]);
    }
}

#[test]
fn every_result_of_the_vectors_is_accepted() {
    let f = fx();
    wire::check_publish_key_package_result(&f["publish_result"]).unwrap();
    wire::check_get_key_package_result(&f["get_result"]).unwrap();
    wire::check_create_result(&f["create_result"]).unwrap();
    wire::check_membership_result(&f["add_result"]).unwrap();
    wire::check_send_result(&f["send_result"]).unwrap();
    wire::check_key_package(&f["creator_key_package"]).unwrap();
    wire::check_key_package(&f["member_key_package"]).unwrap();
}

#[test]
fn the_canonical_bytes_are_the_sdks() {
    let f = fx();
    let s = |k: &str| f[k].as_str().unwrap().as_bytes().to_vec();
    let (m, b, _) = wire::parse_request(METHOD_SEND, &f["send_request"]).unwrap();
    assert_eq!(aad::send_authenticated_data(&m, &b).unwrap(), s("expected_send_authenticated_data_jcs"));
    let (m, b, _) = wire::parse_request(METHOD_ADD, &f["add_request"]).unwrap();
    assert_eq!(aad::add_submission_binding(&m, &b).unwrap(), s("expected_add_submission_binding_jcs"));
    let (m, b, _) = wire::parse_request(METHOD_REMOVE, &f["remove_request"]).unwrap();
    assert_eq!(aad::remove_submission_binding(&m, &b).unwrap(), s("expected_remove_submission_binding_jcs"));
    assert_eq!(aad::canonical_application_plaintext(&f["application_plaintext"]).unwrap(), s("expected_application_plaintext_jcs"));
    assert_eq!(anp_did::jcs(&f["member_key_package"]["did_wba_binding"]).unwrap().into_bytes(), s("expected_member_binding_jcs"));
    assert_eq!(f["draft_extension_type"], DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT);
}

#[test]
fn the_error_table_is_the_specs() {
    assert_eq!(ERRORS.len(), 14);
    assert_eq!(error_name(5002), Some("group.e2ee.did_binding_invalid"));
    assert_eq!(error_name(5013), Some("group.e2ee.leaf_not_current"));
    assert_eq!(error_name(4000), None);
    assert_eq!(rpc_error(5005, "x")["message"], "group.e2ee.epoch_conflict");
    assert!(ensure_public_release_ready().is_err(), "the draft extension has no registered code point");
}

fn must_fail(method: &str, v: &Value, why: &str) {
    assert!(wire::parse_request(method, v).is_err(), "should be refused: {why}");
}

fn mutate(v: &Value, f: impl Fn(&mut Value)) -> Value {
    let mut c = v.clone();
    f(&mut c);
    c
}

#[test]
fn the_strictness_the_sdk_has() {
    let f = fx();
    let send = &f["send_request"];
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["extra"] = json!(1)), "an unknown member of params");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["surprise"] = json!(1)), "an unknown member of the body");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["meta"]["created_at"] = Value::Null), "null for an optional member");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["epoch"] = json!("09")), "a leading zero in a counter");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["epoch"] = json!(9)), "a number for a counter");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["private_message_b64u"] = json!("bWxzLXByaXZhdGUtbWVzc2FnZQ==")), "padded base64url");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["private_message_b64u"] = json!("")), "empty base64url");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["private_message_b64u"] = json!("bWxzLXByaXZhdGUtbWVzc2FnZR")), "non-canonical base64url (stray trailing bits)");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["body"]["group_state_ref"]["group_did"] = json!("did:wba:other.example:g")), "a state ref for another group than the target");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["meta"]["profile"] = json!("anp.group.e2ee.v1")), "the wrong profile");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["meta"]["content_type"] = json!("application/json")), "the wrong content type");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["meta"]["target"]["kind"] = json!("agent")), "the wrong target kind");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["meta"]["created_at"] = json!("yesterday")), "a timestamp that is not RFC 3339");
    must_fail(METHOD_SEND, &mutate(send, |v| { v["params"].as_object_mut().unwrap().remove("auth"); }), "a send without auth");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["auth"]["scheme"] = json!("other")), "another auth scheme");
    must_fail(METHOD_SEND, &mutate(send, |v| v["params"]["auth"]["origin_proof"]["signature"] = json!("")), "an empty proof member");
    must_fail(METHOD_SEND, &mutate(send, |v| v["jsonrpc"] = json!("2.0")), "a JSON-RPC envelope member on the object");
    must_fail(METHOD_ADD, send, "the wrong method");
    // key packages
    let publish = &f["publish_request"];
    must_fail(METHOD_PUBLISH_KEY_PACKAGE, &mutate(publish, |v| v["params"]["meta"]["sender_device_id"] = json!("dev-other")), "publishing another device's package");
    must_fail(METHOD_PUBLISH_KEY_PACKAGE, &mutate(publish, |v| v["params"]["body"]["group_key_package"]["suite"] = json!("MLS_256_OTHER")), "another suite");
    must_fail(METHOD_PUBLISH_KEY_PACKAGE, &mutate(publish, |v| v["params"]["body"]["group_key_package"]["did_wba_binding"]["device_id"] = json!("dev-x")), "a binding for another device than the package's");
    must_fail(METHOD_PUBLISH_KEY_PACKAGE, &mutate(publish, |v| v["params"]["body"]["group_key_package"]["did_wba_binding"]["leaf_signature_key_b64u"] = json!("AAAA")), "a leaf key that is not 32 bytes");
    must_fail(METHOD_PUBLISH_KEY_PACKAGE, &mutate(publish, |v| v["params"]["body"]["group_key_package"]["did_wba_binding"]["proof"]["verificationMethod"] = json!("did:wba:x#y")), "a proof by another method than the binding names");
    // add / remove / notice / incoming
    let add = &f["add_request"];
    must_fail(METHOD_ADD, &mutate(add, |v| v["params"]["body"]["member_device_id"] = json!("dev-other")), "a key package that is not the added device's");
    let notice = &f["notice_notification"];
    must_fail(METHOD_NOTICE, &mutate(notice, |v| v["params"]["body"]["commit_b64u"] = json!("Y29tbWl0")), "a welcome notice that also carries a commit");
    must_fail(METHOD_NOTICE, &mutate(notice, |v| v["params"]["body"]["notice_type"] = json!("other")), "an unknown notice type");
    must_fail(METHOD_NOTICE, &mutate(notice, |v| v["params"]["meta"]["recipient_device_id"] = json!("dev-z")), "a welcome for another device than the subject");
    must_fail(METHOD_NOTICE, &mutate(notice, |v| v["params"]["body"]["subject_status"] = json!("banned")), "an unknown subject status");
    let inc = &f["incoming_notification"];
    must_fail(METHOD_INCOMING, &mutate(inc, |v| v["params"]["body"]["group_state_version"] = json!("43")), "an ordering field that disagrees with the cipher object");
    must_fail(METHOD_INCOMING, &mutate(inc, |v| v["params"]["auth"]["origin_context"]["extra_meta"] = json!({ "sender_did": "x" })), "an origin context that overrides a reserved field");
    must_fail(METHOD_INCOMING, &mutate(inc, |v| { v["params"]["auth"].as_object_mut().unwrap().remove("origin_context"); }), "a delivery without its origin context");
    // results
    assert!(wire::check_send_result(&mutate(&f["send_result"], |v| v["accepted"] = json!(false))).is_err());
    assert!(wire::check_create_result(&mutate(&f["create_result"], |v| v["group_state_ref"]["group_did"] = json!("did:wba:other"))).is_err());
    assert!(wire::check_get_key_package_result(&mutate(&f["get_result"], |v| v["target_device_id"] = json!("dev-z"))).is_err());
}

#[test]
fn the_group_plaintext_rules() {
    let ok = |v: Value| aad::check_application_plaintext(&v).is_ok();
    assert!(ok(json!({ "application_content_type": "text/plain", "text": "hi" })));
    assert!(ok(json!({ "application_content_type": "application/json", "payload": { "a": 1 } })));
    assert!(ok(json!({ "application_content_type": "image/png", "payload_b64u": "iVBORw" })));
    assert!(!ok(json!({ "application_content_type": "text/plain", "payload": { "a": 1 } })), "text/plain must use text");
    assert!(!ok(json!({ "application_content_type": "application/json", "text": "{}" })), "JSON must use payload");
    assert!(!ok(json!({ "application_content_type": "text/plain", "text": "hi", "payload": {} })), "exactly one body member");
    assert!(!ok(json!({ "application_content_type": "text/plain" })), "at least one");
    assert!(!ok(json!({ "application_content_type": "text/plain", "text": "" })));
    assert!(!ok(json!({ "application_content_type": "application/json", "payload": [1] })), "payload is an object");
    assert!(!ok(json!({ "application_content_type": "text/plain", "text": "hi", "annotations": "x" })));
    assert!(!ok(json!({ "application_content_type": "text/plain", "text": "hi", "extra": 1 })));
    let bytes = aad::canonical_application_plaintext(&json!({ "text": "hi", "application_content_type": "text/plain" })).unwrap();
    assert_eq!(bytes, br#"{"application_content_type":"text/plain","text":"hi"}"#);
    assert_eq!(aad::parse_application_plaintext(&bytes).unwrap()["text"], "hi");
}

// ── the cryptographic parts ──────────────────────────────────────────────────────────────────────────────

struct Device {
    sk: SigningKey,
    did: String,
    doc: Value,
    vm: String,
}

/// A DID document of a device that is P6-eligible (its manifest lists the group profiles), signed by its own key.
fn device(seed: u8, host: &str, name: &str, eligible: bool) -> Device {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = anp_did::did_for_key(host, None, &["agents", name], &sk.verifying_key().to_bytes());
    let ka = anp_e2ee_free_agreement_key(seed);
    let mut doc = anp_did::build_document_full(&did, &sk, &[], "2026-11-15T10:00:00Z", Some(&ka), Some(&format!("dev-{name}"))).unwrap();
    let vm = doc["deviceManifest"]["devices"][0]["signing_key_id"].as_str().unwrap().to_string();
    if eligible {
        doc["deviceManifest"]["devices"][0]["profiles"] = json!(binding::P6_PROFILES);
    }
    doc.as_object_mut().unwrap().remove("proof");
    anp_did::add_proof_legacy(&mut doc, &sk, &format!("{did}#{}", anp_did::thumbprint(&sk.verifying_key().to_bytes())), "assertionMethod", "2026-11-15T10:00:00Z", &Default::default()).unwrap();
    Device { sk, did, doc, vm }
}

/// Any 32 bytes will do as an X25519 public key here.
fn anp_e2ee_free_agreement_key(seed: u8) -> [u8; 32] {
    [seed.wrapping_add(100); 32]
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn evidence(b: &Value, leaf_key: &str) -> binding::LeafEvidence {
    binding::LeafEvidence {
        credential_identity: b["agent_did"].as_str().unwrap().as_bytes().to_vec(),
        leaf_signature_key_b64u: leaf_key.to_string(),
        extensions: vec![(DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT, anp_did::jcs(b).unwrap().into_bytes())],
        leaf_capability_extensions: vec![DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT],
    }
}

const NOW: &str = "2026-11-20T00:00:00Z";

fn signed_binding(d: &Device, leaf_key: &str) -> Value {
    let unsigned = binding::unsigned_binding(&d.did, &d.doc["deviceManifest"]["devices"][0]["device_id"].as_str().unwrap().to_string(), &d.vm, leaf_key, "2026-11-15T00:00:00Z", "2026-12-15T00:00:00Z").unwrap();
    binding::sign(&unsigned, &d.sk, "2026-11-15T00:00:00Z").unwrap()
}

#[test]
fn a_device_binding_is_signed_and_verified_through_the_whole_chain() {
    let d = device(1, "member.example", "bob", true);
    let leaf = b64(&[7u8; 32]);
    let b = signed_binding(&d, &leaf);
    wire::check_binding_structure(&b).unwrap();
    binding::verify(&b, &d.doc, &evidence(&b, &leaf), &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT], NOW, true).unwrap();

    let ok = |b: &Value, e: &binding::LeafEvidence, req: &[u16], now: &str, neg: bool| binding::verify(b, &d.doc, e, req, now, neg);
    let req = [DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT];
    assert!(ok(&b, &evidence(&b, &leaf), &req, NOW, false).is_err(), "the draft extension needs explicit negotiation");
    assert!(ok(&b, &evidence(&b, &leaf), &req, "2027-01-01T00:00:00Z", true).is_err(), "expired");
    assert!(ok(&b, &evidence(&b, &leaf), &req, "2026-11-14T00:00:00Z", true).is_err(), "not yet valid");
    assert!(ok(&b, &evidence(&b, &leaf), &[], NOW, true).is_err(), "the group does not require the extension");
    let mut e = evidence(&b, &leaf);
    e.credential_identity = b"did:wba:evil.example:agents:x".to_vec();
    assert!(ok(&b, &e, &req, NOW, true).is_err(), "the MLS credential names another DID");
    assert!(ok(&b, &evidence(&b, &b64(&[8u8; 32])), &req, NOW, true).is_err(), "the MLS leaf uses another key than the binding names");
    let mut e = evidence(&b, &leaf);
    e.extensions.clear();
    assert!(ok(&b, &e, &req, NOW, true).is_err(), "no extension in the leaf");
    let mut e = evidence(&b, &leaf);
    e.extensions.push(e.extensions[0].clone());
    assert!(ok(&b, &e, &req, NOW, true).is_err(), "two extensions");
    let mut e = evidence(&b, &leaf);
    e.extensions[0].1 = b"{}".to_vec();
    assert!(ok(&b, &e, &req, NOW, true).is_err(), "the extension is not the canonical binding");
    let mut e = evidence(&b, &leaf);
    e.leaf_capability_extensions.clear();
    assert!(ok(&b, &e, &req, NOW, true).is_err(), "the leaf does not list the extension in its capabilities");
    // a changed binding no longer verifies
    let forged = mutate(&b, |v| v["expires_at"] = json!("2030-01-01T00:00:00Z"));
    assert!(ok(&forged, &evidence(&forged, &leaf), &req, NOW, true).is_err(), "the proof covers the window");
    // another DID's document
    let other = device(2, "member.example", "carol", true);
    assert!(binding::verify(&b, &other.doc, &evidence(&b, &leaf), &req, NOW, true).is_err());
    // a device that is not P6-eligible
    let plain = device(3, "member.example", "dan", false);
    let pb = signed_binding(&plain, &leaf);
    assert!(binding::verify(&pb, &plain.doc, &evidence(&pb, &leaf), &req, NOW, true).unwrap_err().0.contains("eligible"));
    // the signing key must be the manifest's
    let wrong_vm = mutate(&b, |v| {
        v["verification_method"] = json!(format!("{}#other", d.did));
        v["proof"]["verificationMethod"] = json!(format!("{}#other", d.did));
    });
    assert!(binding::verify(&wrong_vm, &d.doc, &evidence(&wrong_vm, &leaf), &req, NOW, true).is_err());
}

#[test]
fn leaves_of_one_did_must_differ_in_device_and_key() {
    let (k1, k2) = (b64(&[1u8; 32]), b64(&[2u8; 32]));
    let leaf = |d: &str, dev: &str, k: &str| binding::LeafIdentity { agent_did: d.into(), device_id: dev.into(), leaf_signature_key_b64u: k.into() };
    assert!(binding::check_leaf_identity_set(&[leaf("did:a", "d1", &k1), leaf("did:a", "d2", &k2), leaf("did:b", "d1", &b64(&[3u8; 32]))]).is_ok());
    assert!(binding::check_leaf_identity_set(&[leaf("did:a", "d1", &k1), leaf("did:a", "d1", &k2)]).is_err(), "the same device twice");
    assert!(binding::check_leaf_identity_set(&[leaf("did:a", "d1", &k1), leaf("did:a", "d2", &k1)]).is_err(), "one key for two leaves");
    assert!(binding::check_leaf_identity_set(&[leaf("did:a", "d1", "AAAA")]).is_err());
}

#[test]
fn an_origin_proof_binds_the_submission_to_its_sender() {
    let f = fx();
    let alice = device(10, "owner.example", "alice", true);
    let keyid = alice.doc["authentication"][0].as_str().unwrap().to_string();
    let (meta, body, _) = wire::parse_request(METHOD_SEND, &f["send_request"]).unwrap();
    let proof = origin::generate(METHOD_SEND, &meta, &body, &alice.sk, &keyid, 1784419200, None, "n-1").unwrap();
    assert!(proof["signatureInput"].as_str().unwrap().starts_with("sig1=(\"@method\" \"@target-uri\" \"content-digest\");created=1784419200;nonce=\"n-1\";keyid=\""));
    assert!(proof["contentDigest"].as_str().unwrap().starts_with("sha-256=:"));
    origin::verify(&proof, METHOD_SEND, &meta, &body, &alice.doc, Some(&alice.did)).unwrap();
    assert_eq!(origin::logical_target_uri(&meta).unwrap(), "anp://group/did%3Awba%3Agroups.example%3Ateams%3Ablue%3Ae1_group");

    // a change anywhere in what was signed breaks it
    let other_body = mutate(&body, |v| v["epoch"] = json!("10"));
    assert!(origin::verify(&proof, METHOD_SEND, &meta, &other_body, &alice.doc, None).is_err());
    let other_meta = mutate(&meta, |v| v["message_id"] = json!("msg-2"));
    assert!(origin::verify(&proof, METHOD_SEND, &other_meta, &body, &alice.doc, None).is_err());
    assert!(origin::verify(&proof, METHOD_ADD, &meta, &body, &alice.doc, None).is_err(), "the method is signed too");
    // another sender
    let mallory = device(11, "owner.example", "mallory", true);
    assert!(origin::verify(&proof, METHOD_SEND, &meta, &body, &mallory.doc, None).is_err(), "not her key");
    assert!(origin::verify(&proof, METHOD_SEND, &meta, &body, &alice.doc, Some(&mallory.did)).is_err(), "not the expected DID");
    // only authentication keys count
    let mut no_auth = alice.doc.clone();
    no_auth["authentication"] = json!([]);
    assert!(origin::verify(&proof, METHOD_SEND, &meta, &body, &no_auth, None).is_err());
    // damaged proof members
    for (k, v) in [("contentDigest", "sha-256=:AAAA:"), ("signature", "sig1=:AAAA:"), ("signatureInput", "sig2=(\"@method\");keyid=\"x\"")] {
        let bad = mutate(&proof, |p| p[k] = json!(v));
        assert!(origin::verify(&bad, METHOD_SEND, &meta, &body, &alice.doc, None).is_err(), "{k}");
    }
    // the covered components are fixed
    let narrow = mutate(&proof, |p| p["signatureInput"] = json!(format!("sig1=(\"@method\");created=1;keyid=\"{keyid}\"")));
    assert!(origin::verify(&narrow, METHOD_SEND, &meta, &body, &alice.doc, None).is_err());
}

#[test]
fn the_proof_survives_delivery_through_the_host() {
    let f = fx();
    let alice = device(10, "owner.example", "alice", true);
    let keyid = alice.doc["authentication"][0].as_str().unwrap().to_string();
    // alice submits a send ...
    let (meta, body, _) = wire::parse_request(METHOD_SEND, &f["send_request"]).unwrap();
    let proof = origin::generate(METHOD_SEND, &meta, &body, &alice.sk, &keyid, 1784419200, None, "n-2").unwrap();
    // ... the host delivers it to bob: a new target and timestamp, the cipher object, and the context needed to rebuild the original
    let bob = "did:wba:member.example:agents:bob:e1_fixture";
    let in_meta = json!({
        "anp_version": "2.0", "profile": PROFILE, "security_profile": SECURITY_PROFILE,
        "sender_did": meta["sender_did"], "sender_device_id": meta["sender_device_id"],
        "target": { "kind": "agent", "did": bob }, "recipient_device_id": "dev-b-1",
        "operation_id": meta["operation_id"], "message_id": meta["message_id"], "content_type": CIPHER_CONTENT_TYPE,
        "created_at": "2026-07-19T00:00:02Z",
    });
    let in_body = json!({
        "group_did": meta["target"]["did"], "group_state_version": body["group_state_ref"]["group_state_version"],
        "group_event_seq": "101", "accepted_at": "2026-07-19T00:00:01Z", "group_receipt": { "group_event_seq": "101" },
        "group_cipher_object": body,
    });
    let auth = json!({
        "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": proof,
        "origin_context": { "created_at": meta["created_at"], "extra_meta": { "anp_version": "2.0" } },
    });
    wire::request(METHOD_INCOMING, &in_meta, &in_body, Some(&auth)).unwrap();
    origin::verify_incoming(&in_meta, &in_body, &auth, &alice.doc, Some(&alice.did)).unwrap();
    // a host that changes the ciphertext on the way is caught by the sender's proof
    let tampered = mutate(&in_body, |v| v["group_cipher_object"]["private_message_b64u"] = json!("dGFtcGVyZWQ"));
    assert!(origin::verify_incoming(&in_meta, &tampered, &auth, &alice.doc, None).is_err());
    // and one that claims another sender
    let other_sender = mutate(&in_meta, |v| v["sender_device_id"] = json!("dev-x"));
    assert!(origin::verify_incoming(&other_sender, &in_body, &auth, &alice.doc, None).is_err());
}

// ── for the official SDKs: what this project produced, and what it makes of theirs ───────────────────────

/// With ANP_GROUP_FIXTURE_OUT set, write a binding and origin proofs made here, for the SDKs to verify (scripts/interop).
#[test]
fn dump_group_fixture() {
    let Ok(path) = std::env::var("ANP_GROUP_FIXTURE_OUT") else { return };
    let f = fx();
    let d = device(1, "member.example", "bob", true);
    let leaf = b64(&[7u8; 32]);
    let b = signed_binding(&d, &leaf);
    let alice = device(10, "owner.example", "alice", true);
    let keyid = alice.doc["authentication"][0].as_str().unwrap().to_string();
    let (meta, body, _) = wire::parse_request(METHOD_SEND, &f["send_request"]).unwrap();
    let proof = origin::generate(METHOD_SEND, &meta, &body, &alice.sk, &keyid, 1784419200, None, "n-sdk").unwrap();
    let auth = json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": proof, "origin_context": { "created_at": meta["created_at"], "extra_meta": { "anp_version": meta["anp_version"] } } });
    let in_meta = json!({
        "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": meta["sender_did"], "sender_device_id": meta["sender_device_id"],
        "target": { "kind": "agent", "did": "did:wba:member.example:agents:bob:e1_fixture" }, "recipient_device_id": "dev-b-1",
        "operation_id": meta["operation_id"], "message_id": meta["message_id"], "content_type": CIPHER_CONTENT_TYPE, "created_at": "2026-07-19T00:00:02Z",
    });
    let in_body = json!({ "group_did": meta["target"]["did"], "group_state_version": body["group_state_ref"]["group_state_version"], "group_event_seq": "101", "accepted_at": "2026-07-19T00:00:01Z", "group_receipt": { "group_event_seq": "101" }, "group_cipher_object": body });
    let reconstructed = origin::reconstruct_send_request(&in_meta, &in_body, &auth).unwrap();
    // complete requests assembled here, for the other SDKs' parsers
    let send_req = wire::request(METHOD_SEND, &meta, &body, Some(&auth_plain(&proof))).unwrap();
    let incoming_req = wire::request(METHOD_INCOMING, &in_meta, &in_body, Some(&auth)).unwrap();
    let bob_meta = json!({ "profile": PROFILE, "security_profile": TRANSPORT_PROFILE, "sender_did": d.did, "sender_device_id": "dev-bob", "target": { "kind": "service", "did": "did:wba:groups.example:services:keys" }, "operation_id": "op-pub-1", "created_at": "2026-11-15T00:00:00Z" });
    let publish_req = wire::request(METHOD_PUBLISH_KEY_PACKAGE, &bob_meta, &json!({ "group_key_package": { "key_package_id": "kp-1", "owner_did": d.did, "owner_device_id": "dev-bob", "suite": MTI_SUITE, "mls_key_package_b64u": b64(b"mls-key-package"), "did_wba_binding": mutate(&b, |x| x["device_id"] = json!("dev-bob")) } }), None);
    let out = json!({
        "requests": { "send": send_req, "incoming": incoming_req, "publish": publish_req.ok() },
        "expected_send_ad": String::from_utf8(aad::send_authenticated_data(&meta, &body).unwrap()).unwrap(),
        "now": NOW, "leaf_key": leaf, "binding": b, "binding_doc": d.doc, "binding_did": d.did,
        "signer_doc": alice.doc, "signer_did": alice.did,
        "method": METHOD_SEND, "meta": meta, "body": body, "proof": proof,
        "incoming": { "meta": in_meta, "body": in_body, "auth": auth, "reconstructed": reconstructed },
    });
    std::fs::write(path, out.to_string()).unwrap();
}

/// With ANP_GROUP_SDK_FIXTURE set to a file the SDK wrote ({signer_doc, signer_did, method, meta, body, proof}), verify it here.
#[test]
fn an_origin_proof_made_by_the_sdk_verifies_here() {
    let Ok(path) = std::env::var("ANP_GROUP_SDK_FIXTURE") else { return };
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    origin::verify(&v["proof"], v["method"].as_str().unwrap(), &v["meta"], &v["body"], &v["signer_doc"], v["signer_did"].as_str()).unwrap();
    let bad = mutate(&v["body"], |b| b["epoch"] = json!("99"));
    assert!(origin::verify(&v["proof"], v["method"].as_str().unwrap(), &v["meta"], &bad, &v["signer_doc"], None).is_err());
}

fn auth_plain(proof: &Value) -> Value {
    json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": proof })
}

/// With ANP_GROUP_GO_FIXTURE set to a file the Go SDK wrote ({name: request}), parse each of those requests here.
#[test]
fn requests_built_by_the_go_sdk_are_read_here() {
    let Ok(path) = std::env::var("ANP_GROUP_GO_FIXTURE") else { return };
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for (name, method) in [("publish", METHOD_PUBLISH_KEY_PACKAGE), ("get", METHOD_GET_KEY_PACKAGE), ("create", METHOD_CREATE), ("add", METHOD_ADD), ("remove", METHOD_REMOVE), ("send", METHOD_SEND), ("notice", METHOD_NOTICE), ("incoming", METHOD_INCOMING)] {
        wire::parse_request(method, &v[name]).unwrap_or_else(|e| panic!("the Go SDK's {name}: {e}"));
    }
}
