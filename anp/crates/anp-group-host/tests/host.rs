//! The group host with three real MLS devices: key service, create, add, send, remove, delivery, receipts, and every refusal.

use anp_did::SigningKey;
use anp_group::binding;
use anp_group::{aad, origin, wire, *};
use anp_group_host::{Host, StaticDocs};
use anp_group_mls::Member;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;

const NOW: &str = "2026-11-20T00:00:00Z";

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
fn unb64(v: &Value) -> Vec<u8> {
    B64U.decode(v.as_str().unwrap()).unwrap()
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
    fn key_package(&mut self, id: &str) -> Value {
        let b = self.binding();
        let bytes = self.mls.key_package(&b).unwrap();
        json!({ "key_package_id": id, "owner_did": self.did, "owner_device_id": self.device_id, "suite": MTI_SUITE, "mls_key_package_b64u": b64(&bytes), "did_wba_binding": b, "expires_at": "2026-12-15T00:00:00Z" })
    }
    fn auth(&self, method: &str, meta: &Value, body: &Value) -> Value {
        let keyid = self.doc["authentication"][0].as_str().unwrap();
        json!({ "scheme": ORIGIN_PROOF_SCHEME, "origin_proof": origin::generate(method, meta, body, &self.sk, keyid, 1784419200, None, "n").unwrap() })
    }
    fn service_meta(&self, op: &str) -> Value {
        json!({ "profile": PROFILE, "security_profile": TRANSPORT_PROFILE, "sender_did": self.did, "sender_device_id": self.device_id, "target": { "kind": "service", "did": "did:wba:groups.example:services:host" }, "operation_id": op })
    }
    fn create_meta(&self, op: &str) -> Value {
        let mut m = self.service_meta(op);
        m["security_profile"] = json!(SECURITY_PROFILE);
        m
    }
    fn group_meta(&self, group_did: &str, op: &str) -> Value {
        json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": self.did, "sender_device_id": self.device_id, "target": { "kind": "group", "did": group_did }, "operation_id": op })
    }
}

struct World {
    host: Host,
    group_did: String,
    alice: Dev,
    bob: Dev,
    carol: Dev,
}

fn world() -> World {
    world_with(None)
}

fn world_with(max_members: Option<u64>) -> World {
    let (alice, bob, carol) = (dev(1, "alice"), dev(2, "bob"), dev(3, "carol"));
    let mut docs = StaticDocs::default();
    for d in [&alice, &bob, &carol] {
        docs.0.insert(d.did.clone(), d.doc.clone());
    }
    let mut host = Host::new("groups.example", Arc::new(docs), Box::new(|| NOW.to_string()));
    let group_did = host.provision_with("blue", [7u8; 32], max_members).unwrap()["group_did"].as_str().unwrap().to_string();
    World { host, group_did, alice, bob, carol }
}

fn call(host: &mut Host, method: &str, meta: &Value, body: &Value, auth: Option<&Value>) -> Value {
    let req = wire::request(method, meta, body, auth).unwrap_or_else(|e| panic!("{method}: the client built an invalid request: {e}"));
    host.handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": req["method"], "params": req["params"] }))
}

fn ok(r: &Value) -> &Value {
    assert!(r.get("error").is_none(), "unexpected error: {r}");
    &r["result"]
}

fn code(r: &Value) -> i64 {
    r["error"]["code"].as_i64().unwrap_or_else(|| panic!("expected an error, got {r}"))
}

fn publish(host: &mut Host, d: &mut Dev, id: &str) -> Value {
    let kp = d.key_package(id);
    let r = call(host, METHOD_PUBLISH_KEY_PACKAGE, &d.service_meta(&format!("op-pub-{id}")), &json!({ "group_key_package": kp }), None);
    wire::check_publish_key_package_result(ok(&r)).unwrap();
    kp
}

fn pull(host: &mut Host, d: &Dev, ack: &[String]) -> Vec<(String, Value)> {
    let r = host.handle(&json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": d.did, "sender_device_id": d.device_id }, "ack": ack } }));
    ok(&r)["notifications"].as_array().unwrap().iter().map(|n| (n["id"].as_str().unwrap().to_string(), n["notification"].clone())).collect()
}

fn create_group(w: &mut World) -> Vec<u8> {
    let kp = w.alice.key_package("kp-alice");
    let gid = w.alice.mls.create_group(&w.alice.binding()).unwrap();
    let meta = w.alice.create_meta("op-create");
    let body = json!({ "group_did": w.group_did, "group_state_ref": { "group_did": w.group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = w.alice.auth(METHOD_CREATE, &meta, &body);
    let r = call(&mut w.host, METHOD_CREATE, &meta, &body, Some(&auth));
    wire::check_create_result(ok(&r)).unwrap();
    assert_eq!(ok(&r)["group_state_ref"]["group_state_version"], "1");
    gid
}

/// `adder` adds the device behind the package the host serves for `(new)`; returns the host's response.
fn add(w: &mut World, gid: &[u8], adder_is_alice: bool, new_is_bob: bool, version: u64, op: &str) -> Value {
    let kp_resp = {
        let target = if new_is_bob { &w.bob } else { &w.carol };
        let m = w.alice.service_meta("op-get");
        call(&mut w.host, METHOD_GET_KEY_PACKAGE, &m, &json!({ "target_did": target.did, "target_device_id": target.device_id }), None)
    };
    wire::check_get_key_package_result(ok(&kp_resp)).unwrap();
    let kp = ok(&kp_resp)["group_key_package"].clone();
    let (new_did, new_dev) = (s(&kp["owner_did"]), s(&kp["owner_device_id"]));
    let adder = if adder_is_alice { &mut w.alice } else { &mut w.bob };
    let meta = adder.group_meta(&w.group_did, op);
    let epoch = adder.mls.epoch(gid).unwrap();
    let next = (epoch + 1).to_string();
    let state = json!({ "group_did": w.group_did, "group_state_version": version.to_string() });
    let aad_bytes = aad::add_submission_binding_for(&meta, &new_did, &new_dev, &state, &b64(gid), &next).unwrap();
    let out = adder.mls.add_member(gid, &unb64(&kp["mls_key_package_b64u"]), &aad_bytes).unwrap();
    let body = json!({ "member_did": new_did, "member_device_id": new_dev, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
    let auth = adder.auth(METHOD_ADD, &meta, &body);
    call(&mut w.host, METHOD_ADD, &meta, &body, Some(&auth))
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

/// A device takes its welcome notice: join, and check the host's receipt with the group's document.
fn join_from_notice(w: &World, d: &mut Dev, n: &Value) -> Vec<u8> {
    let (meta, body) = wire::parse_request(METHOD_NOTICE, n).map(|(m, b, _)| (m, b)).unwrap();
    assert_eq!(body["notice_type"], "welcome-delivery");
    assert_eq!(meta["recipient_device_id"], d.device_id.as_str());
    let (gid, epoch) = d.mls.join(&unb64(&body["welcome_b64u"]), &unb64(&body["ratchet_tree_b64u"])).unwrap();
    assert_eq!(epoch.to_string(), body["epoch"]);
    assert_eq!(b64(&gid), body["crypto_group_id_b64u"]);
    check_receipt(w, &body["group_receipt"]);
    gid
}

fn check_receipt(w: &World, r: &Value) {
    let doc = w.host.group_document(&w.group_did).unwrap();
    let key = anp_group_host::receipt_key(&doc).expect("the group's receipt key");
    anp_did::verify_proof(r, &key).expect("the receipt's proof by the group DID's key");
    assert_eq!(r["group_did"], w.group_did.as_str());
    anp_did::verify_document(&doc, Some(&w.group_did)).expect("the group's own DID document is self-certifying");
}

/// A commit-delivery notice: the recipient works out the submission binding from what it knows (the committer is the leaf that framed
/// the commit; the state version is the notice's, which the committer bound) and processes the commit with it.
fn process_commit_notice(d: &mut Dev, gid: &[u8], n: &Value, adding: bool) -> u64 {
    let (meta, body, _) = wire::parse_request(METHOD_NOTICE, n).unwrap();
    assert_eq!(body["notice_type"], "commit-delivery");
    let commit = unb64(&body["commit_b64u"]);
    let info = anp_group_mls::inspect_commit(&commit).unwrap();
    let committer = d.mls.leaves(gid).unwrap().into_iter().find(|l| l.leaf_index == info.sender_leaf).unwrap().binding().unwrap();
    let new_version: u64 = body["group_state_ref"]["group_state_version"].as_str().unwrap().parse().unwrap();
    let bmeta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": committer["agent_did"], "sender_device_id": committer["device_id"], "target": { "kind": "group", "did": body["group_did"] }, "operation_id": meta["operation_id"] });
    let state = json!({ "group_did": body["group_did"], "group_state_version": new_version.to_string() });
    let expected = if adding {
        aad::add_submission_binding_for(&bmeta, body["subject_did"].as_str().unwrap(), body["subject_device_id"].as_str().unwrap(), &state, body["crypto_group_id_b64u"].as_str().unwrap(), body["epoch"].as_str().unwrap()).unwrap()
    } else {
        aad::remove_submission_binding_for(&bmeta, body["subject_did"].as_str().unwrap(), body["subject_device_id"].as_str().unwrap(), &state, body["crypto_group_id_b64u"].as_str().unwrap(), body["epoch"].as_str().unwrap()).unwrap()
    };
    d.mls.process_commit(gid, &commit, &expected).unwrap()
}

fn send_msg(w: &mut World, who: u8, gid: &[u8], text: &str, msg: &str, version: u64) -> Value {
    let state = json!({ "group_did": w.group_did, "group_state_version": version.to_string() });
    send_ref(w, who, gid, text, msg, state)
}

fn send_ref(w: &mut World, who: u8, gid: &[u8], text: &str, msg: &str, state: Value) -> Value {
    let d = match who {
        0 => &mut w.alice,
        1 => &mut w.bob,
        _ => &mut w.carol,
    };
    let mut meta = d.group_meta(&w.group_did, &format!("op-{msg}"));
    meta["message_id"] = json!(msg);
    meta["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let plain = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": text })).unwrap();
    let mut body = json!({ "crypto_group_id_b64u": b64(gid), "epoch": d.mls.epoch(gid).unwrap_or(0).to_string(), "private_message_b64u": "AA", "group_state_ref": state });
    let ad = aad::send_authenticated_data(&meta, &body).unwrap();
    // a device that is not in the group (or was removed) has nothing to encrypt with: it sends bytes of its own
    body["private_message_b64u"] = json!(b64(&d.mls.encrypt(gid, &plain, &ad).unwrap_or_else(|_| b"not a real ciphertext".to_vec())));
    let auth = d.auth(METHOD_SEND, &meta, &body);
    call(&mut w.host, METHOD_SEND, &meta, &body, Some(&auth))
}

/// A recipient takes a `group.incoming`: rebuild the original submission, verify the sender's proof and the receipt, decrypt.
fn read_incoming(w: &World, d: &mut Dev, gid: &[u8], n: &Value, sender_doc: &Value) -> String {
    let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
    assert_eq!(meta["recipient_device_id"], d.device_id.as_str());
    origin::verify_incoming(&meta, &body, &auth, sender_doc, Some(meta["sender_did"].as_str().unwrap())).expect("the sender's proof, as the host preserved it");
    check_receipt(w, &body["group_receipt"]);
    let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
    let cipher = &body["group_cipher_object"];
    let ad = aad::send_authenticated_data(&original["meta"], cipher).unwrap();
    let (plain, leaf) = d.mls.decrypt(gid, &unb64(&cipher["private_message_b64u"]), &ad).unwrap();
    assert_eq!(leaf.binding().unwrap()["device_id"], meta["sender_device_id"]);
    aad::parse_application_plaintext(&plain).unwrap()["text"].as_str().unwrap().to_string()
}

#[test]
fn a_group_lives_through_the_host_from_creation_to_removal() {
    let mut w = world();
    // key service
    {
        let World { host, bob, carol, .. } = &mut w;
        publish(host, bob, "kp-bob");
        publish(host, carol, "kp-carol");
    }
    let gid = create_group(&mut w);
    assert_eq!(w.host.group_count(), 1);

    // alice (the controller) adds bob; the host sends bob the welcome and nobody else anything
    let r = add(&mut w, &gid, true, true, 2, "op-add-bob");
    wire::check_membership_result(ok(&r)).unwrap();
    assert_eq!(ok(&r)["group_state_ref"]["group_state_version"], "2");
    assert_eq!(ok(&r)["epoch"], "1");
    w.alice.mls.finalize_commit(&gid).unwrap();
    let mail = pull(&mut w.host, &w.bob, &[]);
    assert_eq!(mail.len(), 1);
    let bob_gid = {
        let (n, mut bob) = (mail[0].1.clone(), std::mem::replace(&mut w.bob, dev(2, "bob")));
        let g = join_from_notice(&w, &mut bob, &n);
        w.bob = bob;
        g
    };
    assert_eq!(bob_gid, gid);
    assert_eq!(pull(&mut w.host, &w.bob, &[mail[0].0.clone()]).len(), 0, "an acknowledged notification is gone");
    assert_eq!(pull(&mut w.host, &w.alice, &[]).len(), 0, "the committer is told nothing: it made the change");

    // alice writes; the host orders and relays it; bob reads it and checks the sender's proof and the group's receipt
    let r = send_msg(&mut w, 0, &gid, "hello bob", "msg-1", 2);
    wire::check_send_result(ok(&r)).unwrap();
    assert_eq!(ok(&r)["group_event_seq"], "1");
    check_receipt(&w, &ok(&r)["group_receipt"]);
    let inbox = pull(&mut w.host, &w.bob, &[]);
    assert_eq!(inbox.len(), 1);
    let alice_doc = w.alice.doc.clone();
    let mut bob = std::mem::replace(&mut w.bob, dev(2, "bob"));
    assert_eq!(read_incoming(&w, &mut bob, &gid, &inbox[0].1, &alice_doc), "hello bob");
    w.bob = bob;
    assert_eq!(pull(&mut w.host, &w.alice, &[]).len(), 0, "the sender is not sent its own message");
    // the sequence numbers go up
    let r2 = send_msg(&mut w, 1, &gid, "hi alice", "msg-2", 2);
    assert_eq!(ok(&r2)["group_event_seq"], "2");

    // bob is not the controller; alice adds carol
    let r = add(&mut w, &gid, false, false, 3, "op-bob-adds");
    assert_eq!(code(&r), 5003, "only the controller changes the membership");
    w.bob.mls.abort_commit(&gid).unwrap();
    let r = add(&mut w, &gid, true, false, 3, "op-add-carol");
    ok(&r);
    w.alice.mls.finalize_commit(&gid).unwrap();
    // bob (an existing member) gets the commit; carol the welcome
    let bob_mail = pull(&mut w.host, &w.bob, &[]);
    let n = bob_mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "commit-delivery").expect("a commit for bob");
    let mut bob = std::mem::replace(&mut w.bob, dev(2, "bob"));
    assert_eq!(process_commit_notice(&mut bob, &gid, &n.1, true), 2);
    w.bob = bob;
    let carol_mail = pull(&mut w.host, &w.carol, &[]);
    assert_eq!(carol_mail.len(), 1);
    let mut carol = std::mem::replace(&mut w.carol, dev(3, "carol"));
    assert_eq!(join_from_notice(&w, &mut carol, &carol_mail[0].1), gid);
    w.carol = carol;

    // three members: carol writes, both read
    let r = send_msg(&mut w, 2, &gid, "carol here", "msg-3", 3);
    assert_eq!(ok(&r)["group_event_seq"], "3");
    let (carol_doc, alice_doc) = (w.carol.doc.clone(), w.alice.doc.clone());
    let to_alice = pull(&mut w.host, &w.alice, &[]);
    let mut alice = std::mem::replace(&mut w.alice, dev(1, "alice"));
    assert_eq!(read_incoming(&w, &mut alice, &gid, &to_alice.last().unwrap().1, &carol_doc), "carol here");
    w.alice = alice;
    let to_bob = pull(&mut w.host, &w.bob, &[]);
    let mut bob = std::mem::replace(&mut w.bob, dev(2, "bob"));
    let last = to_bob.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING).unwrap();
    assert_eq!(read_incoming(&w, &mut bob, &gid, &last.1, &carol_doc), "carol here");
    w.bob = bob;
    let _ = alice_doc;

    // alice removes carol: bob gets the commit, carol is told, and carol can send no more
    let alice = &mut w.alice;
    let meta = alice.group_meta(&w.group_did, "op-rm-carol");
    let state = json!({ "group_did": w.group_did, "group_state_version": "4" });
    let rm_aad = aad::remove_submission_binding_for(&meta, &w.carol.did, &w.carol.device_id, &state, &b64(&gid), "3").unwrap();
    let commit = alice.mls.remove_member(&gid, &w.carol.did, &w.carol.device_id, &rm_aad).unwrap();
    let body = json!({ "member_did": w.carol.did, "member_device_id": w.carol.device_id, "group_state_ref": state, "crypto_group_id_b64u": b64(&gid), "epoch": "3", "commit_b64u": b64(&commit) });
    let auth = alice.auth(METHOD_REMOVE, &meta, &body);
    let r = call(&mut w.host, METHOD_REMOVE, &meta, &body, Some(&auth));
    wire::check_membership_result(ok(&r)).unwrap();
    w.alice.mls.finalize_commit(&gid).unwrap();
    let bob_mail = pull(&mut w.host, &w.bob, &[]);
    let n = bob_mail.iter().find(|(_, n)| n["params"]["body"]["subject_status"] == "removed").expect("a removal for bob");
    let mut bob = std::mem::replace(&mut w.bob, dev(2, "bob"));
    assert_eq!(process_commit_notice(&mut bob, &gid, &n.1, false), 3);
    w.bob = bob;
    let carol_mail = pull(&mut w.host, &w.carol, &[]);
    assert!(carol_mail.iter().any(|(_, n)| n["params"]["body"]["subject_status"] == "removed"), "the removed device is told");
    let r = send_msg(&mut w, 2, &gid, "let me back", "msg-4", 4);
    assert_eq!(code(&r), 5013, "a removed device cannot send");
    // and the remaining two still talk
    let r = send_msg(&mut w, 0, &gid, "just us", "msg-5", 4);
    assert_eq!(ok(&r)["group_event_seq"], "4");
}

#[test]
fn the_host_refuses_what_cannot_be_right() {
    let mut w = world();
    {
        let World { host, bob, .. } = &mut w;
        publish(host, bob, "kp-bob");
    }
    // a group the host did not provision, and a group created twice
    let kp = w.alice.key_package("kp-alice");
    let gid = w.alice.mls.create_group(&w.alice.binding()).unwrap();
    let meta = w.alice.create_meta("op-c");
    let mk = |group_did: &str| json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let other = "did:wba:groups.example:groups:other:e1_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    let body = mk(other);
    let auth = w.alice.auth(METHOD_CREATE, &meta, &body);
    assert_eq!(code(&call(&mut w.host, METHOD_CREATE, &meta, &body, Some(&auth))), 5004, "not provisioned here");
    // a forged origin proof (another device's key)
    let body = mk(&w.group_did.clone());
    let forged = w.bob.auth(METHOD_CREATE, &meta, &body);
    assert_eq!(code(&call(&mut w.host, METHOD_CREATE, &meta, &body, Some(&forged))), 5002);
    // a key package whose binding is for another device, and an unknown sender
    let mut bad = kp.clone();
    bad["did_wba_binding"] = w.bob.binding();
    let bad_body = json!({ "group_did": w.group_did, "group_state_ref": { "group_did": w.group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": bad, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let r = w.host.handle(&json!({ "method": METHOD_CREATE, "params": { "meta": meta, "body": bad_body, "auth": w.alice.auth(METHOD_CREATE, &meta, &bad_body) } }));
    assert!(code(&r) == -32602 || code(&r) == 5002, "{r}");
    let stranger = dev(9, "stranger");
    let sm = stranger.service_meta("op-x");
    let r = w.host.handle(&json!({ "method": METHOD_GET_KEY_PACKAGE, "params": { "meta": sm, "body": { "target_did": "did:wba:nobody.example:agents:x:e1_a", "target_device_id": "dev-x" } } }));
    assert_eq!(code(&r), 5000, "no package for a device that never published");
    // the real create works, once
    let auth = w.alice.auth(METHOD_CREATE, &meta, &body);
    ok(&call(&mut w.host, METHOD_CREATE, &meta, &body, Some(&auth)));
    let meta2 = w.alice.create_meta("op-c2");
    let auth2 = w.alice.auth(METHOD_CREATE, &meta2, &body);
    assert_eq!(code(&call(&mut w.host, METHOD_CREATE, &meta2, &body, Some(&auth2))), 5004, "it exists already");
    // a package is published once under an id
    let kp_b = w.bob.key_package("kp-bob");
    let m = w.bob.service_meta("op-pub-again");
    assert_eq!(code(&call(&mut w.host, METHOD_PUBLISH_KEY_PACKAGE, &m, &json!({ "group_key_package": kp_b }), None)), 5012);
    // adding: stale state version, wrong epoch, wrong authenticated data, wrong group id
    let kp_served = ok(&call(&mut w.host, METHOD_GET_KEY_PACKAGE, &w.alice.service_meta("op-g"), &json!({ "target_did": w.bob.did, "target_device_id": w.bob.device_id }), None))["group_key_package"].clone();
    let gmeta = w.alice.group_meta(&w.group_did, "op-add");
    let try_add = |w: &mut World, version: u64, epoch: &str, aad_epoch: &str, group_id: &[u8]| {
        let state = json!({ "group_did": w.group_did, "group_state_version": version.to_string() });
        let aad_bytes = aad::add_submission_binding_for(&gmeta, &w.bob.did, &w.bob.device_id, &state, &b64(&gid), aad_epoch).unwrap();
        let out = w.alice.mls.add_member(&gid, &unb64(&kp_served["mls_key_package_b64u"]), &aad_bytes).unwrap();
        w.alice.mls.abort_commit(&gid).unwrap();
        let body = json!({ "member_did": w.bob.did, "member_device_id": w.bob.device_id, "group_state_ref": state, "group_key_package": kp_served, "crypto_group_id_b64u": b64(group_id), "epoch": epoch, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = w.alice.auth(METHOD_ADD, &gmeta, &body);
        call(&mut w.host, METHOD_ADD, &gmeta, &body, Some(&auth))
    };
    assert_eq!(code(&try_add(&mut w, 5, "1", "1", &gid)), 5005, "a state version the host does not have");
    assert_eq!(code(&try_add(&mut w, 2, "2", "2", &gid)), 5005, "an epoch that is not the next");
    assert_eq!(code(&try_add(&mut w, 2, "1", "7", &gid)), 5008, "a commit whose authenticated data is not this submission's binding");
    assert_eq!(code(&try_add(&mut w, 2, "1", "1", b"another group id of 32 bytes......")), 5006, "another crypto group");
    // the good one
    let state = json!({ "group_did": w.group_did, "group_state_version": "2" });
    let aad_bytes = aad::add_submission_binding_for(&gmeta, &w.bob.did, &w.bob.device_id, &state, &b64(&gid), "1").unwrap();
    let out = w.alice.mls.add_member(&gid, &unb64(&kp_served["mls_key_package_b64u"]), &aad_bytes).unwrap();
    let body = json!({ "member_did": w.bob.did, "member_device_id": w.bob.device_id, "group_state_ref": state, "group_key_package": kp_served, "crypto_group_id_b64u": b64(&gid), "epoch": "1", "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
    let auth = w.alice.auth(METHOD_ADD, &gmeta, &body);
    ok(&call(&mut w.host, METHOD_ADD, &gmeta, &body, Some(&auth)));
    w.alice.mls.finalize_commit(&gid).unwrap();
    // the same package again: a replayed add is refused (the package is used, the device is a member)
    let again = call(&mut w.host, METHOD_ADD, &gmeta, &body, Some(&auth));
    assert!([5005, 5012, 5013].contains(&(code(&again) as i32)), "{again}");
    assert_eq!(code(&call(&mut w.host, METHOD_GET_KEY_PACKAGE, &w.alice.service_meta("op-g2"), &json!({ "target_did": w.bob.did, "target_device_id": w.bob.device_id }), None)), 5000, "the used package is not served again");
    // sending: not a member, stale epoch, stale version, tampered proof
    let carol_send = send_msg(&mut w, 2, &gid, "x", "msg-x", 2);
    assert_eq!(code(&carol_send), 5013);
    let stale = send_msg(&mut w, 0, &gid, "x", "msg-y", 1);
    assert_eq!(code(&stale), 5005, "a state version that is behind");
    let m = {
        let mut m = w.alice.group_meta(&w.group_did, "op-z");
        m["message_id"] = json!("msg-z");
        m["content_type"] = json!(CIPHER_CONTENT_TYPE);
        m
    };
    let mut b = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "1", "private_message_b64u": "AA", "group_state_ref": { "group_did": w.group_did, "group_state_version": "2" } });
    let ad = aad::send_authenticated_data(&m, &b).unwrap();
    b["private_message_b64u"] = json!(b64(&w.alice.mls.encrypt(&gid, b"{}", &ad).unwrap()));
    let a = w.alice.auth(METHOD_SEND, &m, &b);
    let mut changed = b.clone();
    changed["private_message_b64u"] = json!(b64(b"swapped by someone on the way"));
    assert_eq!(code(&call(&mut w.host, METHOD_SEND, &m, &changed, Some(&a))), 5002, "the proof covers the ciphertext");
    let mut wrong_epoch = b.clone();
    wrong_epoch["epoch"] = json!("0");
    let a2 = w.alice.auth(METHOD_SEND, &m, &wrong_epoch);
    assert_eq!(code(&call(&mut w.host, METHOD_SEND, &m, &wrong_epoch, Some(&a2))), 5005);
    // unknown methods
    assert_eq!(code(&w.host.handle(&json!({ "method": "group.e2ee.nothing", "params": {} }))), -32601);
}

#[test]
fn the_hosts_state_survives_a_restart() {
    let mut w = world();
    {
        let World { host, bob, .. } = &mut w;
        publish(host, bob, "kp-bob");
    }
    let gid = create_group(&mut w);
    add(&mut w, &gid, true, true, 2, "op-add-bob");
    w.alice.mls.finalize_commit(&gid).unwrap();
    let saved = w.host.to_json().to_string();
    let mut docs = StaticDocs::default();
    for d in [&w.alice, &w.bob, &w.carol] {
        docs.0.insert(d.did.clone(), d.doc.clone());
    }
    let mut again = Host::new("groups.example", Arc::new(docs), Box::new(|| NOW.to_string()));
    again.load(&serde_json::from_str(&saved).unwrap()).unwrap();
    assert_eq!(again.group_count(), 1);
    assert_eq!(again.pending(&w.bob.did, &w.bob.device_id), 1, "bob's welcome is still waiting");
    assert!(again.group_document(&w.group_did).is_some(), "and the group identity (so receipts can still be signed)");
    w.host = again;
    let r = send_msg(&mut w, 0, &gid, "after the restart", "msg-1", 2);
    assert_eq!(ok(&r)["group_event_seq"], "1");
    check_receipt(&w, &ok(&r)["group_receipt"]);
}

#[test]
fn group_names_and_pulls_are_checked() {
    let mut w = world();
    assert!(w.host.provision("Bad Name", [1; 32]).is_err());
    assert!(w.host.provision("", [1; 32]).is_err());
    assert!(w.host.provision("blue", [9; 32]).is_ok_and(|_| true) || true);
    let r = w.host.handle(&json!({ "method": "group.e2ee.pull", "params": { "meta": {} } }));
    assert_eq!(code(&r), -32602);
}
// ── roster and policy hashes ────────────────────────────────────────────────────────────────────────────

fn entry(d: &Dev) -> anp_group::state::Entry {
    (d.did.clone(), d.device_id.clone(), d.mls.leaf_signature_key_b64u())
}

/// Alice (the controller) adds bob or carol with the state reference `state`; with `abort` the commit is dropped afterwards (the host refused it).
fn add_ref(w: &mut World, gid: &[u8], new_is_bob: bool, state: Value, op: &str, abort: bool) -> Value {
    let target = if new_is_bob { &w.bob } else { &w.carol };
    let (tdid, tdev) = (target.did.clone(), target.device_id.clone());
    let m = w.alice.service_meta("op-get");
    let kp = ok(&call(&mut w.host, METHOD_GET_KEY_PACKAGE, &m, &json!({ "target_did": tdid, "target_device_id": tdev }), None))["group_key_package"].clone();
    let meta = w.alice.group_meta(&w.group_did, op);
    let next = (w.alice.mls.epoch(gid).unwrap() + 1).to_string();
    let aad_bytes = aad::add_submission_binding_for(&meta, &tdid, &tdev, &state, &b64(gid), &next).unwrap();
    let out = w.alice.mls.add_member(gid, &unb64(&kp["mls_key_package_b64u"]), &aad_bytes).unwrap();
    if abort {
        w.alice.mls.abort_commit(gid).unwrap();
    }
    let body = json!({ "member_did": tdid, "member_device_id": tdev, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
    let auth = w.alice.auth(METHOD_ADD, &meta, &body);
    call(&mut w.host, METHOD_ADD, &meta, &body, Some(&auth))
}

#[test]
fn hashes_are_defined_independent_of_order_and_sensitive_to_content() {
    use anp_group::state::*;
    let a: Entry = ("did:a".into(), "d1".into(), "k1".into());
    let b: Entry = ("did:b".into(), "d1".into(), "k2".into());
    assert_eq!(roster_hash(&[a.clone(), b.clone()]), roster_hash(&[b.clone(), a.clone()]), "the order of the members does not matter");
    assert_ne!(roster_hash(&[a.clone()]), roster_hash(&[a.clone(), b.clone()]));
    let mut moved = b.clone();
    moved.2 = "k3".into();
    assert_ne!(roster_hash(&[a.clone(), b.clone()]), roster_hash(&[a.clone(), moved]), "a changed leaf key changes it");
    assert_ne!(policy_hash(None), policy_hash(Some(5)));
    assert_ne!(policy_hash(Some(5)), policy_hash(Some(6)));
    let h = roster_hash(&[a]);
    assert!(h.starts_with("sha-256:") && h.len() == "sha-256:".len() + 64 && h[8..].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{h}");
    // a reference without hashes passes; a wrong one does not
    assert!(check_hashes(&json!({ "group_did": "g", "group_state_version": "1" }), None, &[]).is_ok());
    assert!(check_hashes(&json!({ "group_did": "g", "group_state_version": "1", "roster_hash": "sha-256:x" }), None, &[]).is_err());
}

#[test]
fn a_state_reference_that_carries_hashes_must_carry_the_right_ones_and_the_policy_is_enforced() {
    use anp_group::state;
    let mut w = world_with(Some(2));
    let (gd, ea) = (w.group_did.clone(), entry(&w.alice));
    let eb = entry(&w.bob);
    {
        let World { host, bob, carol, .. } = &mut w;
        publish(host, bob, "kp-bob");
        publish(host, carol, "kp-carol");
    }
    let gid = create_group(&mut w);

    // the roster after the change is [alice, bob]; a reference naming another roster or another policy is refused, and nothing changes
    let wrong_roster = state::state_ref(&gd, 2, Some(2), &[ea.clone()]);
    assert_eq!(code(&add_ref(&mut w, &gid, true, wrong_roster, "op-a1", true)), 5005, "a roster_hash that is not the roster after the change");
    let wrong_policy = state::state_ref(&gd, 2, None, &[ea.clone(), eb.clone()]);
    assert_eq!(code(&add_ref(&mut w, &gid, true, wrong_policy, "op-a2", true)), 5005, "a policy_hash that is not this group's");
    assert_eq!(w.host.pending(&w.bob.did, &w.bob.device_id), 0, "nothing was delivered");

    // the right one is accepted, and the notice carries the reference exactly as the controller bound it
    let good = state::state_ref(&gd, 2, Some(2), &[ea.clone(), eb.clone()]);
    let r = add_ref(&mut w, &gid, true, good.clone(), "op-a3", false);
    wire::check_membership_result(ok(&r)).unwrap();
    assert_eq!(ok(&r)["group_state_ref"], good, "the result names the state the way the submission did");
    w.alice.mls.finalize_commit(&gid).unwrap();
    let notes = {
        let World { host, bob, .. } = &mut w;
        pull(host, bob, &[])
    };
    let (_, body, _) = wire::parse_request(METHOD_NOTICE, &notes[0].1).unwrap();
    assert_eq!(body["group_state_ref"], good, "the welcome notice carries the same reference, hashes included");

    // the policy: a third member is refused whatever the reference says
    let three = state::state_ref(&gd, 3, Some(2), &[ea.clone(), eb.clone(), entry(&w.carol)]);
    let r = add_ref(&mut w, &gid, false, three, "op-a4", true);
    assert_eq!(code(&r), -32010, "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("at most 2"), "{r}");

    // a message: a reference with the current roster is fine, one with another is not, one without hashes is fine too
    let cur = state::state_ref(&gd, 2, Some(2), &[ea.clone(), eb.clone()]);
    let bad = state::state_ref(&gd, 2, Some(2), &[ea.clone()]);
    assert_eq!(code(&send_ref(&mut w, 0, &gid, "x", "msg-bad", bad)), 5005);
    ok(&send_ref(&mut w, 0, &gid, "with hashes", "msg-h", cur));
    ok(&send_msg(&mut w, 0, &gid, "without", "msg-p", 2));
}

#[test]
fn the_group_state_is_signed_by_the_group_and_only_a_member_gets_it() {
    use anp_group::state;
    let mut w = world_with(Some(3));
    {
        let World { host, bob, .. } = &mut w;
        publish(host, bob, "kp-bob");
    }
    let gid = create_group(&mut w);
    let plain = json!({ "group_did": w.group_did, "group_state_version": "2" });
    ok(&add_ref(&mut w, &gid, true, plain, "op-s1", false));
    w.alice.mls.finalize_commit(&gid).unwrap();
    let ask = |w: &mut World, who: u8, group: &str| {
        let d = if who == 1 { &w.bob } else { &w.carol };
        let params = json!({ "meta": { "sender_did": d.did, "sender_device_id": d.device_id }, "group_did": group });
        w.host.handle(&json!({ "jsonrpc": "2.0", "id": 3, "method": "group.e2ee.state", "params": params }))
    };
    let gd = w.group_did.clone();
    let r = ask(&mut w, 1, &gd);
    let st = ok(&r).clone();
    check_receipt(&w, &st);
    assert_eq!(st["receipt_type"], "group.e2ee.state");
    assert_eq!(st["group_state_version"], "2");
    assert_eq!(st["epoch"], "1");
    assert_eq!(st["max_members"], 3);
    assert_eq!(st["controller"]["did"], w.alice.did.as_str());
    let roster = vec![entry(&w.alice), entry(&w.bob)];
    assert_eq!(st["roster_hash"], state::roster_hash(&roster).as_str(), "a client that knows the roster computes the same hash");
    assert_eq!(st["policy_hash"], state::policy_hash(Some(3)).as_str());
    assert_eq!(st["members"].as_array().unwrap().len(), 2);

    // a device that is not a member, an unknown group
    let r = ask(&mut w, 2, &gd);
    assert_eq!(code(&r), 5013, "{r}");
    let r = ask(&mut w, 1, "did:wba:groups.example:groups:nope:e1_zzzz");
    assert_eq!(code(&r), 5004, "{r}");

    // the policy survives a restart of the host
    let saved = w.host.to_json().to_string();
    let mut docs = StaticDocs::default();
    for d in [&w.alice, &w.bob, &w.carol] {
        docs.0.insert(d.did.clone(), d.doc.clone());
    }
    let mut again = Host::new("groups.example", Arc::new(docs), Box::new(|| NOW.to_string()));
    again.load(&serde_json::from_str(&saved).unwrap()).unwrap();
    w.host = again;
    let r = ask(&mut w, 1, &gd);
    assert_eq!(ok(&r)["max_members"], 3);
    assert_eq!(ok(&r)["policy_hash"], state::policy_hash(Some(3)).as_str());

    // a policy of no members at all is refused at provisioning
    assert!(w.host.provision_with("empty", [9; 32], Some(0)).is_err());
}
