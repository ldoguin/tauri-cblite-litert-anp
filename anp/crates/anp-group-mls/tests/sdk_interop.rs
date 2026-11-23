//! This project as one P6 group device next to the official Rust SDK's (anp 1.0.7 with its MLS feature), a step at a time:
//! each test below does nothing unless `ANP_GROUP_STEP` names it, and works in the folder `ANP_GROUP_DIR` (files in, files out, the
//! device's state kept in `ours.state.json`). scripts/interop/run.ps1 interleaves these steps with the SDK's (rust-sdk-group).

use anp_did::SigningKey;
use anp_group::binding::{self, LeafEvidence};
use anp_group::{aad, wire, *};
use anp_group_mls::Member;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;

const NOW: &str = "2026-11-20T00:00:00Z";
const ISSUED: &str = "2026-11-15T00:00:00Z";
const EXPIRES: &str = "2026-12-15T00:00:00Z";
const SEED: u8 = 21;

fn step() -> Option<String> {
    std::env::var("ANP_GROUP_STEP").ok()
}
fn dir() -> PathBuf {
    PathBuf::from(std::env::var("ANP_GROUP_DIR").expect("ANP_GROUP_DIR"))
}
fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))).unwrap()
}
fn write(name: &str, v: &Value) {
    std::fs::write(dir().join(name), serde_json::to_string_pretty(v).unwrap()).unwrap();
}
fn b64(b: &[u8]) -> String {
    B64U.encode(b)
}
fn unb64(v: &Value) -> Vec<u8> {
    B64U.decode(v.as_str().unwrap()).unwrap()
}

struct Dev {
    sk: SigningKey,
    did: String,
    doc: Value,
    vm: String,
    device_id: String,
    mls: Member,
}

fn new_dev() -> Dev {
    let sk = SigningKey::from_bytes(&[SEED; 32]);
    let did = anp_did::did_for_key("ours.example", None, &["agents", "ours"], &sk.verifying_key().to_bytes());
    let device_id = "dev-ours".to_string();
    let mut doc = anp_did::build_document_full(&did, &sk, &[], ISSUED, Some(&[SEED.wrapping_add(100); 32]), Some(&device_id)).unwrap();
    let vm = doc["deviceManifest"]["devices"][0]["signing_key_id"].as_str().unwrap().to_string();
    doc["deviceManifest"]["devices"][0]["profiles"] = json!(binding::P6_PROFILES);
    doc.as_object_mut().unwrap().remove("proof");
    anp_did::add_proof_legacy(&mut doc, &sk, &format!("{did}#{}", anp_did::thumbprint(&sk.verifying_key().to_bytes())), "assertionMethod", ISSUED, &Default::default()).unwrap();
    let mls = Member::new(&did, &device_id).unwrap();
    Dev { sk, did, doc, vm, device_id, mls }
}

fn load_dev() -> Dev {
    let mut d = new_dev();
    d.mls = Member::import_state(&read("ours.state.json")).unwrap();
    d
}

fn save_dev(d: &Dev) {
    write("ours.state.json", &d.mls.export_state());
}

impl Dev {
    fn binding(&self) -> Value {
        let u = binding::unsigned_binding(&self.did, &self.device_id, &self.vm, &self.mls.leaf_signature_key_b64u(), ISSUED, EXPIRES).unwrap();
        binding::sign(&u, &self.sk, ISSUED).unwrap()
    }
}

fn state_ref(group_did: &str, v: u64) -> Value {
    json!({ "group_did": group_did, "group_state_version": v.to_string() })
}

fn send_meta(d: &Dev, group_did: &str, msg: &str) -> Value {
    json!({ "anp_version": "2.0", "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": d.did, "sender_device_id": d.device_id, "target": { "kind": "group", "did": group_did }, "operation_id": format!("op-{msg}"), "message_id": msg, "content_type": CIPHER_CONTENT_TYPE, "created_at": NOW })
}

/// Every leaf must verify against the DID document of the DID it names.
fn check_leaves(d: &Dev, gid: &[u8], docs: &[Value]) {
    let required = d.mls.required_extensions(gid);
    binding::check_group_required_capabilities(&required).unwrap();
    let mut ids = vec![];
    for l in d.mls.leaves(gid).unwrap() {
        let b = l.binding().expect("a leaf without exactly one binding");
        let doc = docs.iter().find(|x| x["id"] == b["agent_did"]).expect("a leaf of an unknown DID");
        binding::verify(&b, doc, &l.evidence, &required, NOW, true).unwrap_or_else(|e| panic!("leaf {}: {e}", l.leaf_index));
        ids.push(binding::LeafIdentity { agent_did: b["agent_did"].as_str().unwrap().into(), device_id: b["device_id"].as_str().unwrap().into(), leaf_signature_key_b64u: b["leaf_signature_key_b64u"].as_str().unwrap().into() });
    }
    binding::check_leaf_identity_set(&ids).unwrap();
}

/// A message `{meta, body}` from the SDK (or us): decrypt it with the authenticated data of its own context, and check the sender's leaf.
fn read_message(d: &mut Dev, gid: &[u8], m: &Value, docs: &[Value]) -> String {
    let ad = aad::send_authenticated_data(&m["meta"], &m["body"]).expect("the SDK's send context");
    let (plain, leaf) = d.mls.decrypt(gid, &unb64(&m["body"]["private_message_b64u"]), &ad).expect("decrypt");
    let b = leaf.binding().unwrap();
    assert_eq!(b["agent_did"], m["meta"]["sender_did"]);
    assert_eq!(b["device_id"], m["meta"]["sender_device_id"]);
    let owner = docs.iter().find(|x| x["id"] == b["agent_did"]).unwrap();
    binding::verify(&b, owner, &leaf.evidence, &d.mls.required_extensions(gid), NOW, true).unwrap();
    aad::parse_application_plaintext(&plain).unwrap()["text"].as_str().unwrap().to_string()
}

fn write_message(d: &mut Dev, gid: &[u8], group_did: &str, text: &str, msg: &str, version: u64, out: &str) {
    let meta = send_meta(d, group_did, msg);
    let plaintext = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": text })).unwrap();
    let mut body = json!({ "crypto_group_id_b64u": b64(gid), "epoch": d.mls.epoch(gid).unwrap().to_string(), "private_message_b64u": "AA", "group_state_ref": state_ref(group_did, version), "epoch_authenticator": b64(&d.mls.epoch_authenticator(gid).unwrap()) });
    let ad = aad::send_authenticated_data(&meta, &body).unwrap();
    body["private_message_b64u"] = json!(b64(&d.mls.encrypt(gid, &plaintext, &ad).unwrap()));
    let proof_less = json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": { "contentDigest": "x", "signatureInput": "x", "signature": "x" } });
    wire::request(METHOD_SEND, &meta, &body, Some(&proof_less)).expect("a valid P6 send");
    write(out, &json!({ "meta": meta, "body": body }));
}

// ── direction A: the SDK creates the group and adds this project ────────────────────────────────────────

/// A device, its DID document and a key package for the SDK to add.
#[test]
fn a_ours_key_package() {
    if step().as_deref() != Some("a-kp") {
        return;
    }
    let mut d = new_dev();
    let b = d.binding();
    let kp = d.mls.key_package(&b).unwrap();
    let obj = json!({ "key_package_id": "kp-ours", "owner_did": d.did, "owner_device_id": d.device_id, "suite": MTI_SUITE, "mls_key_package_b64u": b64(&kp), "did_wba_binding": b, "expires_at": EXPIRES });
    wire::check_key_package(&obj).unwrap();
    write("ours.did.json", &d.doc);
    write("ours.kp.json", &obj);
    save_dev(&d);
}

/// Join from the SDK's welcome (its commit's authenticated data is the add binding), validate every leaf, read its message.
#[test]
fn a_ours_join_and_read() {
    if step().as_deref() != Some("a-join") {
        return;
    }
    let mut d = load_dev();
    let add = read("add.json");
    let sdk_doc = read("sdk.did.json");
    let (gid, epoch) = d.mls.join(&unb64(&add["body"]["welcome_b64u"]), &unb64(&add["body"]["ratchet_tree_b64u"])).expect("join from the SDK's welcome");
    assert_eq!(b64(&gid), add["body"]["crypto_group_id_b64u"]);
    assert_eq!(epoch.to_string(), add["body"]["epoch"]);
    check_leaves(&d, &gid, &[d.doc.clone(), sdk_doc.clone()]);
    // the SDK's request is a valid P6 object, with the binding the commit was made with
    wire::check_add_body(&add["body"]).expect("the SDK's add body is valid P6");
    let expected = aad::add_submission_binding(&add["meta"], &add["body"]).unwrap();
    assert!(!expected.is_empty());
    let docs = [d.doc.clone(), sdk_doc.clone()];
    let text = read_message(&mut d, &gid, &read("msg1.json"), &docs);
    assert_eq!(text, "hello from the SDK");
    let group_did = add["body"]["group_state_ref"]["group_did"].as_str().unwrap().to_string();
    write_message(&mut d, &gid, &group_did, "hello from this project", "msg-ours-1", 2, "reply.json");
    save_dev(&d);
}

// ── direction B: this project creates the group and adds the SDK ────────────────────────────────────────

#[test]
fn b_ours_create_and_add() {
    if step().as_deref() != Some("b-create") {
        return;
    }
    let mut d = new_dev();
    let group_did = "did:wba:groups.example:teams:blue:e1_group";
    let gid = d.mls.create_group(&d.binding()).unwrap();
    write("group.json", &json!({ "group_did": group_did }));
    write("ours.did.json", &d.doc);
    let sdk_kp = read("sdk.kp.json");
    let sdk_doc = read("sdk.did.json");
    // the SDK's key package must pass this project's checks
    wire::check_key_package(&sdk_kp).expect("the SDK's key package object is valid P6");
    let kp_bytes = unb64(&sdk_kp["mls_key_package_b64u"]);
    let ev: LeafEvidence = anp_group_mls::inspect_key_package(&kp_bytes).unwrap();
    binding::verify(&sdk_kp["did_wba_binding"], &sdk_doc, &ev, &d.mls.required_extensions(&gid), NOW, true).expect("the SDK's binding verifies against its DID document and its MLS leaf");
    let (sdk_did, sdk_device) = (sdk_kp["owner_did"].as_str().unwrap(), sdk_kp["owner_device_id"].as_str().unwrap());
    let meta = json!({ "anp_version": "2.0", "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": d.did, "sender_device_id": d.device_id, "target": { "kind": "group", "did": group_did }, "operation_id": "op-add", "created_at": NOW });
    let sref = state_ref(group_did, 2);
    let gid_b64 = b64(&gid);
    let aad_bytes = aad::add_submission_binding_for(&meta, sdk_did, sdk_device, &sref, &gid_b64, "1").unwrap();
    let out = d.mls.add_member(&gid, &kp_bytes, &aad_bytes).unwrap();
    let body = json!({ "member_did": sdk_did, "member_device_id": sdk_device, "group_state_ref": sref, "group_key_package": sdk_kp, "crypto_group_id_b64u": gid_b64, "epoch": "1", "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
    wire::check_add_body(&body).unwrap();
    assert_eq!(aad::add_submission_binding(&meta, &body).unwrap(), aad_bytes);
    write("add.json", &json!({ "meta": meta, "body": body }));
    d.mls.finalize_commit(&gid).unwrap();
    check_leaves(&d, &gid, &[d.doc.clone(), sdk_doc]);
    write_message(&mut d, &gid, group_did, "welcome to the group, SDK", "msg-ours-b1", 2, "msgB.json");
    save_dev(&d);
}

#[test]
fn b_ours_read_reply() {
    if step().as_deref() != Some("b-read") {
        return;
    }
    let mut d = load_dev();
    let add = read("add.json");
    let gid = unb64(&add["body"]["crypto_group_id_b64u"]);
    let docs = [d.doc.clone(), read("sdk.did.json")];
    let text = read_message(&mut d, &gid, &read("replyB.json"), &docs);
    assert_eq!(text, "reply from the SDK");
    save_dev(&d);
}