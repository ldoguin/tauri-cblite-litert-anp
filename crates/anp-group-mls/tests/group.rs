//! Whole groups: DIDs, bindings, MLS key packages, create, add (commit, welcome, tree), send, receive, remove, all with the P6 wire
//! objects of `anp-group` around them and every binding checked.

use anp_did::SigningKey;
use anp_group::binding::{self, LeafEvidence};
use anp_group::{aad, origin, wire, *};
use anp_group_mls::Member;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};

const NOW: &str = "2026-11-20T00:00:00Z";
const GROUP_DID: &str = "did:wba:groups.example:teams:blue:e1_group";

/// A device: its DID document (P6-eligible), its DID signing key, its MLS member.
struct Dev {
    sk: SigningKey,
    did: String,
    doc: Value,
    vm: String,
    device_id: String,
    mls: Member,
}

fn b64(b: &[u8]) -> String {
    B64U.encode(b)
}

fn dev(seed: u8, name: &str) -> Dev {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = anp_did::did_for_key(&format!("{name}.example"), None, &["agents", name], &sk.verifying_key().to_bytes());
    let device_id = format!("dev-{name}");
    let mut doc = anp_did::build_document_full(&did, &sk, &[], "2026-11-15T10:00:00Z", Some(&[seed.wrapping_add(100); 32]), Some(&device_id)).unwrap();
    let vm = doc["deviceManifest"]["devices"][0]["signing_key_id"].as_str().unwrap().to_string();
    doc["deviceManifest"]["devices"][0]["profiles"] = json!(binding::P6_PROFILES);
    doc.as_object_mut().unwrap().remove("proof");
    anp_did::add_proof_legacy(&mut doc, &sk, &format!("{did}#{}", anp_did::thumbprint(&sk.verifying_key().to_bytes())), "assertionMethod", "2026-11-15T10:00:00Z", &Default::default()).unwrap();
    let mls = Member::new(&did, &device_id).unwrap();
    Dev { sk, did, doc, vm, device_id, mls }
}

impl Dev {
    fn binding(&self) -> Value {
        let u = binding::unsigned_binding(&self.did, &self.device_id, &self.vm, &self.mls.leaf_signature_key_b64u(), "2026-11-15T00:00:00Z", "2026-12-15T00:00:00Z").unwrap();
        binding::sign(&u, &self.sk, "2026-11-15T00:00:00Z").unwrap()
    }
    /// The P6 key package object (the MLS key package inside, the binding around it).
    fn key_package(&mut self) -> (Value, Vec<u8>) {
        let b = self.binding();
        let bytes = self.mls.key_package(&b).unwrap();
        let kp = json!({ "key_package_id": format!("kp-{}", self.device_id), "owner_did": self.did, "owner_device_id": self.device_id, "suite": MTI_SUITE, "mls_key_package_b64u": b64(&bytes), "did_wba_binding": b, "expires_at": "2026-12-15T00:00:00Z" });
        wire::check_key_package(&kp).unwrap();
        (kp, bytes)
    }
    fn auth(&self, method: &str, meta: &Value, body: &Value) -> Value {
        let keyid = self.doc["authentication"][0].as_str().unwrap();
        json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": origin::generate(method, meta, body, &self.sk, keyid, 1784419200, None, "n").unwrap() })
    }
}

fn state_ref(v: u64) -> Value {
    json!({ "group_did": GROUP_DID, "group_state_version": v.to_string(), "policy_hash": "sha-256:policy" })
}

fn control_meta(d: &Dev, op: &str) -> Value {
    json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": d.did, "sender_device_id": d.device_id, "target": { "kind": "group", "did": GROUP_DID }, "operation_id": op, "created_at": "2026-11-20T00:00:00Z" })
}

fn send_meta(d: &Dev, op: &str, msg: &str) -> Value {
    let mut m = control_meta(d, op);
    m["message_id"] = json!(msg);
    m["content_type"] = json!(CIPHER_CONTENT_TYPE);
    m
}

/// Every leaf of the group must verify against its own DID document, and the group must require the extension.
fn check_all_leaves(viewer: &Dev, gid: &[u8], docs: &[&Dev]) {
    let required = viewer.mls.required_extensions(gid);
    binding::check_group_required_capabilities(&required).unwrap();
    let leaves = viewer.mls.leaves(gid).unwrap();
    let mut ids = vec![];
    for l in &leaves {
        let b = l.binding().expect("a leaf without exactly one binding");
        let owner = docs.iter().find(|d| d.did == b["agent_did"]).expect("a leaf of an unknown DID");
        binding::verify(&b, &owner.doc, &l.evidence, &required, NOW, true).unwrap_or_else(|e| panic!("leaf {} of {}: {e}", l.leaf_index, owner.did));
        ids.push(binding::LeafIdentity { agent_did: b["agent_did"].as_str().unwrap().into(), device_id: b["device_id"].as_str().unwrap().into(), leaf_signature_key_b64u: b["leaf_signature_key_b64u"].as_str().unwrap().into() });
    }
    binding::check_leaf_identity_set(&ids).unwrap();
}

struct Added {
    commit: Vec<u8>,
    meta: Value,
    body: Value,
    epoch: u64,
}

/// `adder` adds `new` (whose key package is `kp`) to group `gid`: the P6 `group.e2ee.add` body, built and checked, with the commit
/// pending in the adder's group (finalize it afterwards).
fn add(adder: &mut Dev, gid: &[u8], new: &Dev, kp_obj: &Value, kp: &[u8], op: &str, version: u64) -> Added {
    let meta = control_meta(adder, op);
    let epoch_now = adder.mls.epoch(gid).unwrap();
    let next = (epoch_now + 1).to_string();
    let gid_b64 = b64(gid);
    let aad_bytes = aad::add_submission_binding_for(&meta, &new.did, &new.device_id, &state_ref(version), &gid_b64, &next).unwrap();
    let out = adder.mls.add_member(gid, kp, &aad_bytes).unwrap();
    assert_eq!(out.next_epoch.to_string(), next);
    let body = json!({
        "member_did": new.did, "member_device_id": new.device_id, "group_state_ref": state_ref(version), "group_key_package": kp_obj,
        "crypto_group_id_b64u": gid_b64, "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree),
    });
    let auth = adder.auth(METHOD_ADD, &meta, &body);
    let request = wire::request(METHOD_ADD, &meta, &body, Some(&auth)).expect("the add request is valid P6");
    assert_eq!(aad::add_submission_binding(&meta, &body).unwrap(), aad_bytes, "the binding of the finished body is the one the commit carries");
    origin::verify(&auth["origin_proof"], METHOD_ADD, &meta, &body, &adder.doc, Some(&adder.did)).unwrap();
    let _ = request;
    Added { commit: out.commit, meta, body, epoch: out.next_epoch }
}

fn welcome_for(new: &mut Dev, a: &Added) -> Vec<u8> {
    let w = B64U.decode(a.body["welcome_b64u"].as_str().unwrap()).unwrap();
    let t = B64U.decode(a.body["ratchet_tree_b64u"].as_str().unwrap()).unwrap();
    let (gid, epoch) = new.mls.join(&w, &t).unwrap();
    assert_eq!(epoch, a.epoch);
    gid
}

/// A send from `from` in group `gid`: the cipher object, with the authenticated data bound.
fn send(from: &mut Dev, gid: &[u8], text: &str, op: &str, msg: &str, version: u64) -> (Value, Value, Value) {
    let meta = send_meta(from, op, msg);
    let plaintext = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": text })).unwrap();
    let mut body = json!({
        "crypto_group_id_b64u": b64(gid), "epoch": from.mls.epoch(gid).unwrap().to_string(), "private_message_b64u": "AA",
        "group_state_ref": state_ref(version), "epoch_authenticator": b64(&from.mls.epoch_authenticator(gid).unwrap()),
    });
    let ad = aad::send_authenticated_data(&meta, &body).unwrap();
    let pm = from.mls.encrypt(gid, &plaintext, &ad).unwrap();
    body["private_message_b64u"] = json!(b64(&pm));
    assert_eq!(aad::send_authenticated_data(&meta, &body).unwrap(), ad, "the ciphertext is not part of its own authenticated data");
    let auth = from.auth(METHOD_SEND, &meta, &body);
    wire::request(METHOD_SEND, &meta, &body, Some(&auth)).expect("the send request is valid P6");
    (meta, body, auth)
}

/// What a recipient does with a delivered send: the authenticated data from the originating meta, the decryption, and the leaf of the
/// sender checked against its DID document.
/// DID documents by DID: what a receiver looks the sender up in (cloned, so that the receiver itself can be borrowed mutably).
type Docs = Vec<(String, Value)>;

fn docs(devs: &[&Dev]) -> Docs {
    devs.iter().map(|d| (d.did.clone(), d.doc.clone())).collect()
}

fn receive(to: &mut Dev, gid: &[u8], meta: &Value, body: &Value, docs: &Docs) -> Result<Value, String> {
    let ad = aad::send_authenticated_data(meta, body).map_err(|e| e.0)?;
    let pm = B64U.decode(body["private_message_b64u"].as_str().unwrap()).unwrap();
    let (plain, leaf) = to.mls.decrypt(gid, &pm, &ad).map_err(|e| e.0)?;
    let b = leaf.binding().ok_or("the sender's leaf has no binding")?;
    if b["agent_did"] != meta["sender_did"] || b["device_id"] != meta["sender_device_id"] {
        return Err("the MLS sender is not the device the submission names".into());
    }
    let owner = docs.iter().find(|(did, _)| b["agent_did"] == did.as_str()).ok_or("unknown sender")?;
    binding::verify(&b, &owner.1, &leaf.evidence, &to.mls.required_extensions(gid), NOW, true).map_err(|e| e.0)?;
    aad::parse_application_plaintext(&plain).map_err(|e| e.0)
}

#[test]
fn a_group_of_three_is_created_grown_used_and_shrunk() {
    let (mut alice, mut bob, mut carol) = (dev(1, "alice"), dev(2, "bob"), dev(3, "carol"));
    let (d2, d3) = (docs(&[&alice, &bob]), docs(&[&alice, &bob, &carol]));

    // alice creates the group: her key package is the creator's, her binding is in her own leaf
    let (alice_kp, _) = alice.key_package();
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let create_meta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": alice.did, "sender_device_id": alice.device_id, "target": { "kind": "service", "did": "did:wba:groups.example:services:host" }, "operation_id": "op-create" });
    let create_body = json!({ "group_did": GROUP_DID, "group_state_ref": state_ref(1), "suite": MTI_SUITE, "creator_key_package": alice_kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &create_meta, &create_body);
    wire::request(METHOD_CREATE, &create_meta, &create_body, Some(&auth)).expect("a valid create");
    assert_eq!(alice.mls.epoch(&gid), Some(0));
    assert_eq!(gid.len(), 32);
    assert_eq!(alice.mls.required_extensions(&gid), vec![DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT]);
    check_all_leaves(&alice, &gid, &[&alice]);

    // alice adds bob
    let (bob_kp_obj, bob_kp) = bob.key_package();
    let ev: LeafEvidence = anp_group_mls::inspect_key_package(&bob_kp).unwrap();
    binding::verify(&bob_kp_obj["did_wba_binding"], &bob.doc, &ev, &alice.mls.required_extensions(&gid), NOW, true).expect("the key package's leaf matches its binding");
    let add1 = add(&mut alice, &gid, &bob, &bob_kp_obj, &bob_kp, "op-add-bob", 2);
    assert_eq!(alice.mls.finalize_commit(&gid).unwrap(), 1);
    let bob_gid = welcome_for(&mut bob, &add1);
    assert_eq!(bob_gid, gid);
    check_all_leaves(&bob, &gid, &[&alice, &bob]);
    assert_eq!(alice.mls.epoch_authenticator(&gid), bob.mls.epoch_authenticator(&gid), "both are in the same epoch");

    // alice writes, bob reads
    let (m1, b1, _) = send(&mut alice, &gid, "hello bob", "op-s1", "msg-1", 2);
    let got = receive(&mut bob, &gid, &m1, &b1, &d2).unwrap();
    assert_eq!(got["text"], "hello bob");

    // and the other way
    let (m2, b2, _) = send(&mut bob, &gid, "hello alice", "op-s2", "msg-2", 2);
    assert_eq!(receive(&mut alice, &gid, &m2, &b2, &d2).unwrap()["text"], "hello alice");

    // bob adds carol; alice processes the commit with the binding as its authenticated data
    let (carol_kp_obj, carol_kp) = carol.key_package();
    let add2 = add(&mut bob, &gid, &carol, &carol_kp_obj, &carol_kp, "op-add-carol", 3);
    let expected = aad::add_submission_binding(&add2.meta, &add2.body).unwrap();
    assert!(alice.mls.process_commit(&gid, &add2.commit, b"not the binding").is_err(), "a commit whose authenticated data is not the submission binding is refused");
    assert_eq!(alice.mls.process_commit(&gid, &add2.commit, &expected).unwrap(), 2);
    bob.mls.finalize_commit(&gid).unwrap();
    welcome_for(&mut carol, &add2);
    check_all_leaves(&carol, &gid, &[&alice, &bob, &carol]);
    assert_eq!(carol.mls.leaves(&gid).unwrap().len(), 3);
    let (m3, b3, _) = send(&mut carol, &gid, "carol here", "op-s3", "msg-3", 3);
    assert_eq!(receive(&mut alice, &gid, &m3, &b3, &d3).unwrap()["text"], "carol here");
    // bob has a copy of m3 too, and so would anyone in the epoch; a message decrypts once
    assert_eq!(receive(&mut bob, &gid, &m3, &b3, &d3).unwrap()["text"], "carol here");
    assert!(receive(&mut bob, &gid, &m3, &b3, &d3).is_err(), "the same message is not accepted twice");

    // what a host or a stranger could try. A wrong context is refused before anything is decrypted, so it costs nothing ...
    let (m4, b4, _) = send(&mut alice, &gid, "to everyone", "op-s4", "msg-4", 3);
    let wrong_msg = mutate(&m4, |m| m["message_id"] = json!("msg-other"));
    assert!(receive(&mut bob, &gid, &wrong_msg, &b4, &d3).is_err(), "the message id is bound into the ciphertext");
    let wrong_ref = mutate(&b4, |b| b["group_state_ref"]["group_state_version"] = json!("99"));
    assert!(receive(&mut bob, &gid, &m4, &wrong_ref, &d3).is_err(), "so is the group state");
    let wrong_sender = mutate(&m4, |m| m["sender_device_id"] = json!("dev-carol"));
    assert!(receive(&mut bob, &gid, &wrong_sender, &b4, &d3).is_err(), "and the sender");
    assert_eq!(receive(&mut bob, &gid, &m4, &b4, &d3).unwrap()["text"], "to everyone", "the real one still opens after those");
    assert_eq!(receive(&mut carol, &gid, &m4, &b4, &d3).unwrap()["text"], "to everyone");
    // ... but a damaged ciphertext reaches the decryption, which uses up the key (that is what forward secrecy means), and the next message is unaffected
    let (m4b, b4b, _) = send(&mut alice, &gid, "second", "op-s4b", "msg-4b", 3);
    let mut damaged = B64U.decode(b4b["private_message_b64u"].as_str().unwrap()).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let tampered = mutate(&b4b, |b| b["private_message_b64u"] = json!(b64(&damaged)));
    assert!(receive(&mut bob, &gid, &m4b, &tampered, &d3).is_err(), "a damaged ciphertext does not open");
    assert!(receive(&mut bob, &gid, &m4b, &b4b, &d3).is_err(), "and it has cost that message its key");
    let (m4c, b4c, _) = send(&mut alice, &gid, "third", "op-s4c", "msg-4c", 3);
    assert_eq!(receive(&mut bob, &gid, &m4c, &b4c, &d3).unwrap()["text"], "third", "later messages are fine");
    assert_eq!(receive(&mut carol, &gid, &m4b, &b4b, &d3).unwrap()["text"], "second", "and the message is intact for everyone else");
    assert_eq!(receive(&mut carol, &gid, &m4c, &b4c, &d3).unwrap()["text"], "third");

    // alice removes carol
    let rm_meta = control_meta(&alice, "op-rm-carol");
    let next = (alice.mls.epoch(&gid).unwrap() + 1).to_string();
    let rm_aad = aad::remove_submission_binding_for(&rm_meta, &carol.did, &carol.device_id, &state_ref(4), &b64(&gid), &next).unwrap();
    let commit = alice.mls.remove_member(&gid, &carol.did, &carol.device_id, &rm_aad).unwrap();
    let rm_body = json!({ "member_did": carol.did, "member_device_id": carol.device_id, "group_state_ref": state_ref(4), "crypto_group_id_b64u": b64(&gid), "epoch": next, "commit_b64u": b64(&commit) });
    let rm_auth = alice.auth(METHOD_REMOVE, &rm_meta, &rm_body);
    wire::request(METHOD_REMOVE, &rm_meta, &rm_body, Some(&rm_auth)).expect("a valid remove");
    assert_eq!(aad::remove_submission_binding(&rm_meta, &rm_body).unwrap(), rm_aad);
    alice.mls.finalize_commit(&gid).unwrap();
    assert_eq!(bob.mls.process_commit(&gid, &commit, &rm_aad).unwrap(), 3);
    assert_eq!(alice.mls.leaves(&gid).unwrap().len(), 2);
    assert_eq!(bob.mls.leaves(&gid).unwrap().len(), 2);
    let (m5, b5, _) = send(&mut alice, &gid, "carol is gone", "op-s5", "msg-5", 4);
    assert_eq!(receive(&mut bob, &gid, &m5, &b5, &d3).unwrap()["text"], "carol is gone");
    assert!(receive(&mut carol, &gid, &m5, &b5, &d3).is_err(), "a removed device cannot read what is sent after it");
    assert!(alice.mls.remove_member(&gid, &carol.did, &carol.device_id, &rm_aad).is_err(), "a device that is not in the group cannot be removed again");
}

fn mutate(v: &Value, f: impl Fn(&mut Value)) -> Value {
    let mut c = v.clone();
    f(&mut c);
    c
}

#[test]
fn a_key_package_is_only_as_good_as_its_binding() {
    let (mut alice, mallory) = (dev(1, "alice"), dev(4, "mallory"));
    // a binding that names somebody else's leaf key is refused when the key package is made
    let theirs = mallory.binding();
    assert!(alice.mls.key_package(&theirs).is_err(), "a binding for another device's MLS key");
    // a key package whose binding is a copy of another device's does not verify against that device's leaf evidence
    let (kp_obj, kp) = alice.key_package();
    let ev = anp_group_mls::inspect_key_package(&kp).unwrap();
    let required = [DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT];
    binding::verify(&kp_obj["did_wba_binding"], &alice.doc, &ev, &required, NOW, true).unwrap();
    assert!(binding::verify(&kp_obj["did_wba_binding"], &mallory.doc, &ev, &required, NOW, true).is_err(), "another DID's document");
    assert!(binding::verify(&kp_obj["did_wba_binding"], &alice.doc, &ev, &required, "2027-02-01T00:00:00Z", true).is_err(), "after the binding expired");
    let mut bad = ev.clone();
    bad.credential_identity = b"did:wba:mallory.example:agents:mallory".to_vec();
    assert!(binding::verify(&kp_obj["did_wba_binding"], &alice.doc, &bad, &required, NOW, true).is_err(), "a credential that names another DID");
    // bytes that are not a key package
    assert!(anp_group_mls::inspect_key_package(b"nonsense").is_err());
}

#[test]
fn a_device_keeps_its_state_across_a_restart() {
    let (mut alice, mut bob) = (dev(1, "alice"), dev(2, "bob"));
    let d2 = docs(&[&alice, &bob]);
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let (kp_obj, kp) = bob.key_package();
    let a = add(&mut alice, &gid, &bob, &kp_obj, &kp, "op-add", 2);
    alice.mls.finalize_commit(&gid).unwrap();
    welcome_for(&mut bob, &a);
    let (m1, b1, _) = send(&mut alice, &gid, "before", "op-1", "m-1", 2);
    // both are saved and loaded again (through JSON, as a process would)
    let (sa, sb) = (alice.mls.export_state().to_string(), bob.mls.export_state().to_string());
    alice.mls = Member::import_state(&serde_json::from_str(&sa).unwrap()).unwrap();
    bob.mls = Member::import_state(&serde_json::from_str(&sb).unwrap()).unwrap();
    assert_eq!(receive(&mut bob, &gid, &m1, &b1, &d2).unwrap()["text"], "before", "a message sent before the restart is read after it");
    let (m2, b2, _) = send(&mut bob, &gid, "after", "op-2", "m-2", 2);
    assert_eq!(receive(&mut alice, &gid, &m2, &b2, &d2).unwrap()["text"], "after");
    assert_eq!(alice.mls.epoch(&gid), Some(1));
    assert!(Member::import_state(&json!({ "storage": {}, "signer_public": "AAAA", "groups": [] })).is_err());
}

#[test]
fn a_refused_commit_can_be_dropped() {
    let (mut alice, mut bob) = (dev(1, "alice"), dev(2, "bob"));
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let (kp_obj, kp) = bob.key_package();
    let _ = add(&mut alice, &gid, &bob, &kp_obj, &kp, "op-add", 2);
    assert_eq!(alice.mls.epoch(&gid), Some(0), "nothing changes until the commit is finalized");
    alice.mls.abort_commit(&gid).unwrap();
    assert_eq!(alice.mls.leaves(&gid).unwrap().len(), 1);
    // and the group goes on in epoch 0
    let (m, b, _) = send(&mut alice, &gid, "alone", "op-x", "m-x", 1);
    assert!(!m.is_null() && !b.is_null());
}

#[test]
fn the_framing_of_a_commit_can_be_read_without_being_a_member() {
    let (mut alice, mut bob) = (dev(1, "alice"), dev(2, "bob"));
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let (kp_obj, kp) = bob.key_package();
    let a = add(&mut alice, &gid, &bob, &kp_obj, &kp, "op-add", 2);
    let info = anp_group_mls::inspect_commit(&a.commit).unwrap();
    assert_eq!(info.group_id, gid);
    assert_eq!(info.epoch, 0, "a commit is framed in the epoch it was made in");
    assert_eq!(info.sender_leaf, 0);
    assert!(info.is_commit);
    assert_eq!(info.authenticated_data, aad::add_submission_binding(&a.meta, &a.body).unwrap(), "the host can compare the submission binding with what the commit carries");
    assert!(anp_group_mls::inspect_commit(&kp).is_err(), "a key package is not a public message");
    assert!(anp_group_mls::inspect_commit(&a.commit[..10]).is_err());
    assert!(anp_group_mls::inspect_commit(b"").is_err());
}
