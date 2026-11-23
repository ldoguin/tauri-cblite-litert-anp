//! The group host with three real MLS devices: key service, create, add, send, remove, delivery, receipts, and every refusal.

use anp_did::SigningKey;
use anp_group::binding;
use anp_group::{aad, origin, wire, *};
use anp_group_mls::Member;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};


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

/// One DID with two devices, each with its own signing key and key-agreement key in the document (the SDK refuses a key id shared by two devices).
fn dana_pair() -> (Dev, Dev) {
    let (sk1, sk2) = (SigningKey::from_bytes(&[7; 32]), SigningKey::from_bytes(&[8; 32]));
    let did = anp_did::did_for_key("dana.example", None, &["agents", "dana"], &sk1.verifying_key().to_bytes());
    let mut doc = anp_did::build_document_full(&did, &sk1, &[], "2026-11-15T10:00:00Z", Some(&[107; 32]), Some("dev-dana")).unwrap();
    let vm1 = doc["deviceManifest"]["devices"][0]["signing_key_id"].as_str().unwrap().to_string();
    let vm2 = format!("{did}#{}", anp_did::thumbprint(&sk2.verifying_key().to_bytes()));
    let ka2 = format!("{did}#key-agreement-2");
    doc["verificationMethod"].as_array_mut().unwrap().push(json!({ "id": vm2, "type": "Multikey", "controller": did, "publicKeyMultibase": anp_did::multibase(&sk2.verifying_key().to_bytes()) }));
    doc["verificationMethod"].as_array_mut().unwrap().push(json!({ "id": ka2, "type": "X25519KeyAgreementKey2019", "controller": did, "publicKeyMultibase": format!("z{}", bs58::encode(&[108u8; 32]).into_string()) }));
    for k in ["authentication", "assertionMethod", "keyAgreement"] {
        let id = if k == "keyAgreement" { &ka2 } else { &vm2 };
        doc[k].as_array_mut().unwrap().push(json!(id));
    }
    doc["deviceManifest"]["devices"].as_array_mut().unwrap().push(json!({ "device_id": "dev-dana2", "signing_key_id": vm2, "e2ee_key_id": ka2, "profiles": binding::P6_PROFILES }));
    doc["deviceManifest"]["devices"][0]["profiles"] = json!(binding::P6_PROFILES);
    doc.as_object_mut().unwrap().remove("proof");
    anp_did::add_proof_legacy(&mut doc, &sk1, &format!("{did}#{}", anp_did::thumbprint(&sk1.verifying_key().to_bytes())), "assertionMethod", "2026-11-15T10:00:00Z", &Default::default()).unwrap();
    let d1 = Dev { sk: sk1, did: did.clone(), doc: doc.clone(), vm: vm1, device_id: "dev-dana".into(), mls: Member::new(&did, "dev-dana").unwrap() };
    let d2 = Dev { sk: sk2, did: did.clone(), doc, vm: vm2, device_id: "dev-dana2".into(), mls: Member::new(&did, "dev-dana2").unwrap() };
    (d1, d2)
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
        let keyid = self.vm.as_str();
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

// ── the node over HTTP ──────────────────────────────────────────────────────────────────────────────────

/// Nothing happens unless ANP_P6_STEP is `run`; ANP_P6_URL is the node's base URL (also what it was told is its public origin, so that
/// its HTTP signature checks pass), ANP_P6_DIR a folder. ANP_P6_STEP=docs writes the devices' DID documents there for the node to be started with.
fn step() -> Option<String> {
    std::env::var("ANP_P6_STEP").ok()
}

fn devices() -> (Dev, Dev, Dev) {
    (dev(1, "alice"), dev(2, "bob"), dev(3, "carol"))
}

fn push_devices() -> (Dev, Dev, Dev) {
    (dev(4, "dave"), dev(5, "erin"), dev(6, "frank"))
}

#[test]
fn live_docs() {
    if step().as_deref() != Some("docs") {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var("ANP_P6_DIR").unwrap());
    let (a, b, c) = devices();
    let (d1, _) = dana_pair();
    // the push test has devices of its own: the other tests leave key packages behind on the node under alice, bob and carol
    let (pa, pb, pc) = push_devices();
    for d in [&a, &b, &c, &d1, &pa, &pb, &pc] {
        std::fs::write(dir.join(format!("{}.did.json", d.device_id.trim_start_matches("dev-"))), d.doc.to_string()).unwrap();
    }
}

struct Net {
    url: String,
    /// Sign requests with the device's DID key (ANP-02) as whichever device is acting; the origin is the node's public origin.
    sign: bool,
}

impl Net {
    fn post(&self, path: &str, body: &Value, signer: Option<&Dev>) -> (u16, Value) {
        let url = format!("{}{path}", self.url);
        let text = body.to_string();
        let mut req = ureq::post(&url).set("content-type", "application/json");
        if let (true, Some(d)) = (self.sign, signer) {
            let key_id = d.vm.as_str();
            let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let nonce = format!("n-{}-{created}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
            for (k, v) in anp_httpauth::sign(&d.sk, key_id, "POST", &url, text.as_bytes(), created, &nonce).unwrap() {
                req = req.set(&k, &v);
            }
        }
        match req.send_string(&text) {
            Ok(r) => (r.status(), serde_json::from_str(&r.into_string().unwrap()).unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
            Err(e) => panic!("POST {url}: {e}"),
        }
    }

    fn rpc(&self, method: &str, meta: &Value, body: &Value, auth: Option<&Value>, signer: Option<&Dev>) -> Value {
        let req = wire::request(method, meta, body, auth).unwrap_or_else(|e| panic!("{method}: invalid request: {e}"));
        let (status, v) = self.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 1, "method": req["method"], "params": req["params"] }), signer);
        assert_eq!(status, 200, "{method}: HTTP {status}: {v}");
        v
    }

    fn pull(&self, d: &Dev, ack: &[String]) -> (u16, Value) {
        self.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": d.did, "sender_device_id": d.device_id }, "ack": ack } }), Some(d))
    }

    fn notes(&self, d: &Dev, ack: &[String]) -> Vec<(String, Value)> {
        let (status, v) = self.pull(d, ack);
        assert_eq!(status, 200, "{v}");
        ok(&v)["notifications"].as_array().unwrap().iter().map(|n| (n["id"].as_str().unwrap().to_string(), n["notification"].clone())).collect()
    }
}

fn ok(r: &Value) -> &Value {
    assert!(r.get("error").is_none(), "unexpected error: {r}");
    &r["result"]
}

fn code(r: &Value) -> i64 {
    r["error"]["code"].as_i64().unwrap_or_else(|| panic!("expected an error, got {r}"))
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

#[test]
fn live_a_group_over_http() {
    if step().as_deref() != Some("run") {
        return;
    }
    let sign = std::env::var("ANP_P6_SIGN").is_ok();
    let net = Net { url: std::env::var("ANP_P6_URL").unwrap(), sign };
    let (mut alice, mut bob, mut carol) = devices();

    // the host makes a group DID, and serves its document
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("blue{}", std::process::id() % 1000) }), Some(&alice));
    assert_eq!(status, 200, "{v}");
    let group_did = s(&v["group_did"]);
    let path = format!("/{}/did.json", group_did.split(':').skip(3).collect::<Vec<_>>().join("/"));
    let served = ureq::get(&format!("{}{path}", net.url)).call().expect("the group's DID document is public").into_string().unwrap();
    let group_doc: Value = serde_json::from_str(&served).unwrap();
    anp_did::verify_document(&group_doc, Some(&group_did)).expect("the group's document is self-certifying");
    let receipt_key = anp_group_host::receipt_key(&group_doc).unwrap();
    let check_receipt = |r: &Value| anp_did::verify_proof(r, &receipt_key).expect("the receipt's proof by the group's key");

    // key service
    let pub_kp = |net: &Net, d: &mut Dev, id: &str| {
        let kp = d.key_package(id);
        let r = net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &d.service_meta(&format!("op-pub-{id}")), &json!({ "group_key_package": kp }), None, Some(d));
        wire::check_publish_key_package_result(ok(&r)).unwrap();
    };
    pub_kp(&net, &mut bob, "kp-bob");
    pub_kp(&net, &mut carol, "kp-carol");

    // create
    let kp = alice.key_package("kp-alice");
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create");
    let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    wire::check_create_result(ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), Some(&alice)))).unwrap();

    // add: alice adds bob, then carol
    let add = |net: &Net, adder: &mut Dev, target: &Dev, version: u64, op: &str| -> Value {
        let m = adder.service_meta("op-get");
        let kp = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &m, &json!({ "target_did": target.did, "target_device_id": target.device_id }), None, Some(adder)))["group_key_package"].clone();
        let meta = adder.group_meta(&group_did, op);
        let next = (adder.mls.epoch(&gid).unwrap() + 1).to_string();
        let state = json!({ "group_did": group_did, "group_state_version": version.to_string() });
        let ad = aad::add_submission_binding_for(&meta, &target.did, &target.device_id, &state, &b64(&gid), &next).unwrap();
        let out = adder.mls.add_member(&gid, &unb64(&kp["mls_key_package_b64u"]), &ad).unwrap();
        let body = json!({ "member_did": target.did, "member_device_id": target.device_id, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = adder.auth(METHOD_ADD, &meta, &body);
        net.rpc(METHOD_ADD, &meta, &body, Some(&auth), Some(adder))
    };
    let r = add(&net, &mut alice, &bob, 2, "op-add-bob");
    wire::check_membership_result(ok(&r)).unwrap();
    alice.mls.finalize_commit(&gid).unwrap();
    let welcome = |net: &Net, d: &mut Dev| -> Vec<u8> {
        let mail = net.notes(d, &[]);
        let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "welcome-delivery").expect("a welcome").clone();
        let (_, body, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
        check_receipt(&body["group_receipt"]);
        let (g, _) = d.mls.join(&unb64(&body["welcome_b64u"]), &unb64(&body["ratchet_tree_b64u"])).unwrap();
        net.notes(d, &[id]);
        g
    };
    assert_eq!(welcome(&net, &mut bob), gid);

    // a non-controller cannot add
    let r = add(&net, &mut bob, &carol, 3, "op-bob-adds");
    assert_eq!(code(&r), 5003);
    bob.mls.abort_commit(&gid).unwrap();
    ok(&add(&net, &mut alice, &carol, 3, "op-add-carol"));
    alice.mls.finalize_commit(&gid).unwrap();
    assert_eq!(welcome(&net, &mut carol), gid);
    // bob processes the commit that added carol
    let mail = net.notes(&bob, &[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "commit-delivery").expect("a commit for bob").clone();
    let (nmeta, nbody, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
    let commit = unb64(&nbody["commit_b64u"]);
    let info = anp_group_mls::inspect_commit(&commit).unwrap();
    let committer = bob.mls.leaves(&gid).unwrap().into_iter().find(|l| l.leaf_index == info.sender_leaf).unwrap().binding().unwrap();
    let bmeta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": committer["agent_did"], "sender_device_id": committer["device_id"], "target": { "kind": "group", "did": group_did }, "operation_id": nmeta["operation_id"] });
    let prev = json!({ "group_did": group_did, "group_state_version": "3" });
    let expected = aad::add_submission_binding_for(&bmeta, &nbody["subject_did"].as_str().unwrap(), &nbody["subject_device_id"].as_str().unwrap(), &prev, &b64(&gid), &nbody["epoch"].as_str().unwrap()).unwrap();
    assert_eq!(bob.mls.process_commit(&gid, &commit, &expected).unwrap(), 2);
    net.notes(&bob, &[id]);

    // carol writes, alice and bob read
    let mut m = carol.group_meta(&group_did, "op-m1");
    m["message_id"] = json!("msg-1");
    m["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let plain = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": "carol over HTTP" })).unwrap();
    let mut cipher = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "2", "private_message_b64u": "AA", "group_state_ref": { "group_did": group_did, "group_state_version": "3" } });
    let ad = aad::send_authenticated_data(&m, &cipher).unwrap();
    cipher["private_message_b64u"] = json!(b64(&carol.mls.encrypt(&gid, &plain, &ad).unwrap()));
    let auth = carol.auth(METHOD_SEND, &m, &cipher);
    let r = net.rpc(METHOD_SEND, &m, &cipher, Some(&auth), Some(&carol));
    wire::check_send_result(ok(&r)).unwrap();
    check_receipt(&ok(&r)["group_receipt"]);
    for (reader, sender_doc) in [(&mut alice, carol.doc.clone()), (&mut bob, carol.doc.clone())] {
        let mail = net.notes(reader, &[]);
        let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING).expect("an incoming message").clone();
        let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
        origin::verify_incoming(&meta, &body, &auth, &sender_doc, Some(&s(&meta["sender_did"]))).unwrap();
        check_receipt(&body["group_receipt"]);
        let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
        let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
        let (plain, _) = reader.mls.decrypt(&gid, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
        assert_eq!(aad::parse_application_plaintext(&plain).unwrap()["text"], "carol over HTTP");
        net.notes(reader, &[id]);
    }

    // a mailbox is the device's own (with signed requests): alice cannot collect bob's
    if sign {
        let (status, _) = net.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": bob.did, "sender_device_id": bob.device_id } } }), Some(&alice));
        assert_eq!(status, 200);
        let (_, v) = net.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": bob.did, "sender_device_id": bob.device_id } } }), Some(&alice));
        assert_eq!(code(&v), -32001, "{v}");
        let unsigned = Net { url: net.url.clone(), sign: false };
        let (status, _) = unsigned.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": bob.did, "sender_device_id": bob.device_id } } }), None);
        assert_eq!(status, 401, "an unsigned request to a node that requires signatures");
    }

    // remove carol
    let meta = alice.group_meta(&group_did, "op-rm");
    let state = json!({ "group_did": group_did, "group_state_version": "4" });
    let rm_aad = aad::remove_submission_binding_for(&meta, &carol.did, &carol.device_id, &state, &b64(&gid), "3").unwrap();
    let commit = alice.mls.remove_member(&gid, &carol.did, &carol.device_id, &rm_aad).unwrap();
    let body = json!({ "member_did": carol.did, "member_device_id": carol.device_id, "group_state_ref": state, "crypto_group_id_b64u": b64(&gid), "epoch": "3", "commit_b64u": b64(&commit) });
    let auth = alice.auth(METHOD_REMOVE, &meta, &body);
    wire::check_membership_result(ok(&net.rpc(METHOD_REMOVE, &meta, &body, Some(&auth), Some(&alice)))).unwrap();
    alice.mls.finalize_commit(&gid).unwrap();
    assert!(net.notes(&carol, &[]).iter().any(|(_, n)| n["params"]["body"]["subject_status"] == "removed"), "the removed device is told");
}

// ── the official Rust SDK as one of three devices, through the node ─────────────────────────────────────

/// Runs the SDK driver (scripts/interop/rust-sdk-group-build.sh builds it in WSL) on files in ANP_P6_SDK_WDIR (the WSL path of ANP_P6_DIR).
fn sdk(args: &str, ver: u64) -> String {
    let wdir = std::env::var("ANP_P6_SDK_WDIR").unwrap();
    let cmd = format!("cd ~/anp-interop/rust-sdk-group && ANP_VER={ver} ./target/debug/anp-rust-group-interop {}", args.replace("{W}", &wdir));
    let out = std::process::Command::new("wsl.exe").args(["-d", "Ubuntu", "--", "bash", "-c", &cmd]).output().expect("wsl");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && !text.contains("FAIL") && !text.contains("panicked"), "sdk {args}: {text}");
    for l in text.lines().filter(|l| l.starts_with("PASS") || l.starts_with("the SDK")) {
        println!("    sdk : {l}");
    }
    text
}

fn write_json(dir: &std::path::Path, name: &str, v: &Value) {
    std::fs::write(dir.join(name), serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn read_json(dir: &std::path::Path, name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
}

#[test]
fn live_sdk_as_third_device() {
    if step().as_deref() != Some("sdk") {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var("ANP_P6_DIR").unwrap());
    let net = Net { url: std::env::var("ANP_P6_URL").unwrap(), sign: false };
    let (mut alice, mut bob, _) = devices();
    let sdk_doc = read_json(&dir, "sdk.did.json");
    let sdk_did = s(&sdk_doc["id"]);
    let sdk_dev = "dev-sdk".to_string();
    let docs = "{W}/alice.did.json {W}/bob.did.json {W}/sdk.did.json";
    let sdk_mailbox = |ack: &[String]| -> Vec<(String, Value)> {
        let (status, v) = net.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": sdk_did, "sender_device_id": sdk_dev }, "ack": ack } }), None);
        assert_eq!(status, 200, "{v}");
        ok(&v)["notifications"].as_array().unwrap().iter().map(|n| (n["id"].as_str().unwrap().to_string(), n["notification"].clone())).collect()
    };

    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("mixed{}", std::process::id() % 1000) }), None);
    assert_eq!(status, 200, "{v}");
    let group_did = s(&v["group_did"]);
    write_json(&dir, "group.json", &json!({ "group_did": group_did }));
    let path = format!("/{}/did.json", group_did.split(':').skip(3).collect::<Vec<_>>().join("/"));
    let group_doc: Value = serde_json::from_str(&ureq::get(&format!("{}{path}", net.url)).call().unwrap().into_string().unwrap()).unwrap();
    let receipt_key = anp_group_host::receipt_key(&group_doc).unwrap();

    // key service: the SDK's key package (made by the SDK, with its binding) and bob's
    let sdk_kp = read_json(&dir, "sdk.kp.json");
    let sdk_meta = |op: &str| json!({ "profile": PROFILE, "security_profile": TRANSPORT_PROFILE, "sender_did": sdk_did, "sender_device_id": sdk_dev, "target": { "kind": "service", "did": "did:wba:groups.example:services:host" }, "operation_id": op });
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &sdk_meta("op-pub-sdk"), &json!({ "group_key_package": sdk_kp }), None, None))).unwrap();
    let kpb = bob.key_package("kp-bob");
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &bob.service_meta("op-pub-bob"), &json!({ "group_key_package": kpb }), None, None))).unwrap();

    // alice (this project) creates the group
    let kp = alice.key_package("kp-alice");
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create");
    let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    wire::check_create_result(ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), None))).unwrap();

    let add = |adder: &mut Dev, target_did: &str, target_dev: &str, version: u64, op: &str| {
        let kp = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &adder.service_meta("op-get"), &json!({ "target_did": target_did, "target_device_id": target_dev }), None, None))["group_key_package"].clone();
        let meta = adder.group_meta(&group_did, op);
        let next = (adder.mls.epoch(&gid).unwrap() + 1).to_string();
        let state = json!({ "group_did": group_did, "group_state_version": version.to_string() });
        let ad = aad::add_submission_binding_for(&meta, target_did, target_dev, &state, &b64(&gid), &next).unwrap();
        let out = adder.mls.add_member(&gid, &unb64(&kp["mls_key_package_b64u"]), &ad).unwrap();
        let body = json!({ "member_did": target_did, "member_device_id": target_dev, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = adder.auth(METHOD_ADD, &meta, &body);
        ok(&net.rpc(METHOD_ADD, &meta, &body, Some(&auth), None));
        adder.mls.finalize_commit(&gid).unwrap();
    };

    // 1. alice adds the SDK; the SDK takes its welcome from its mailbox
    add(&mut alice, &sdk_did, &sdk_dev, 2, "op-add-sdk");
    let mail = sdk_mailbox(&[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "welcome-delivery").expect("the SDK's welcome").clone();
    write_json(&dir, "notice-welcome.json", &json!({ "meta": n["params"]["meta"], "body": n["params"]["body"] }));
    sdk(&format!("notice {{W}} sdk {{W}}/notice-welcome.json {docs}"), 0);
    sdk_mailbox(&[id]);

    // 2. alice adds bob (also this project); the SDK processes the commit of that add, made by this project
    add(&mut alice, &bob.did, &bob.device_id, 3, "op-add-bob");
    let mail = sdk_mailbox(&[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "commit-delivery").expect("the commit for the SDK").clone();
    write_json(&dir, "notice-commit.json", &json!({ "meta": n["params"]["meta"], "body": n["params"]["body"] }));
    sdk(&format!("notice {{W}} sdk {{W}}/notice-commit.json {docs}"), 0);
    sdk_mailbox(&[id]);
    let mail = net.notes(&bob, &[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "welcome-delivery").expect("bob's welcome").clone();
    let (_, nb, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
    let (g, _) = bob.mls.join(&unb64(&nb["welcome_b64u"]), &unb64(&nb["ratchet_tree_b64u"])).unwrap();
    assert_eq!(g, gid);
    net.notes(&bob, &[id]);

    // 3. the SDK writes (state version 3); its origin proof is made by the SDK; alice and bob read it
    sdk("encrypt {W} sdk 'hello from the SDK, through the host' msg-sdk-1 {W}/send.json", 3);
    let sent = read_json(&dir, "send.json");
    write_json(&dir, "send-req.json", &json!({ "scheme": ORIGIN_PROOF_SCHEME, "method": METHOD_SEND, "meta": sent["meta"], "body": sent["body"] }));
    sdk("proof {W} sdk {W}/send-req.json {W}/send-auth.json", 0);
    let auth = read_json(&dir, "send-auth.json");
    let r = net.rpc(METHOD_SEND, &sent["meta"], &sent["body"], Some(&auth), None);
    wire::check_send_result(ok(&r)).unwrap();
    let check_receipt = |r: &Value| anp_did::verify_proof(r, &receipt_key).expect("the receipt's proof by the group's key");
    check_receipt(&ok(&r)["group_receipt"]);
    for reader in [&mut alice, &mut bob] {
        let mail = net.notes(reader, &[]);
        let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING).expect("an incoming message").clone();
        let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
        origin::verify_incoming(&meta, &body, &auth, &sdk_doc, Some(&sdk_did)).expect("the SDK's origin proof, verified here");
        let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
        let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
        let (plain, _) = reader.mls.decrypt(&gid, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
        assert_eq!(aad::parse_application_plaintext(&plain).unwrap()["text"], "hello from the SDK, through the host");
        net.notes(reader, &[id]);
    }

    // 4. bob writes; the SDK verifies the origin proof of the delivered message and decrypts it
    let mut m = bob.group_meta(&group_did, "op-m2");
    m["message_id"] = json!("msg-2");
    m["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let plain = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": "bob to the SDK" })).unwrap();
    let mut cipher = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "2", "private_message_b64u": "AA", "group_state_ref": { "group_did": group_did, "group_state_version": "3" } });
    let ad = aad::send_authenticated_data(&m, &cipher).unwrap();
    cipher["private_message_b64u"] = json!(b64(&bob.mls.encrypt(&gid, &plain, &ad).unwrap()));
    let auth = bob.auth(METHOD_SEND, &m, &cipher);
    ok(&net.rpc(METHOD_SEND, &m, &cipher, Some(&auth), None));
    let mail = sdk_mailbox(&[]);
    let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING).expect("an incoming message for the SDK").clone();
    write_json(&dir, "incoming.json", &n["params"]);
    let text = sdk("incoming {W} sdk {W}/incoming.json {W}/bob.did.json", 0);
    assert!(text.contains("TEXT bob to the SDK"), "{text}");
    sdk_mailbox(&[id]);

    // 4b. alice removes the SDK (state 4, epoch 3): the SDK is told and processes its own removal; the host then refuses its messages
    let meta = alice.group_meta(&group_did, "op-rm-sdk");
    let state = json!({ "group_did": group_did, "group_state_version": "4" });
    let rm_aad = aad::remove_submission_binding_for(&meta, &sdk_did, &sdk_dev, &state, &b64(&gid), "3").unwrap();
    let commit = alice.mls.remove_member(&gid, &sdk_did, &sdk_dev, &rm_aad).unwrap();
    let body = json!({ "member_did": sdk_did, "member_device_id": sdk_dev, "group_state_ref": state, "crypto_group_id_b64u": b64(&gid), "epoch": "3", "commit_b64u": b64(&commit) });
    let auth = alice.auth(METHOD_REMOVE, &meta, &body);
    wire::check_membership_result(ok(&net.rpc(METHOD_REMOVE, &meta, &body, Some(&auth), None))).unwrap();
    alice.mls.finalize_commit(&gid).unwrap();
    let mail = sdk_mailbox(&[]);
    let (id, n) = mail.iter().rev().find(|(_, n)| n["params"]["body"]["subject_status"] == "removed" && n["params"]["body"]["group_did"] == group_did.as_str()).expect("the SDK is told it was removed").clone();
    write_json(&dir, "notice-removed.json", &json!({ "meta": n["params"]["meta"], "body": n["params"]["body"] }));
    let text = sdk(&format!("notice {{W}} sdk {{W}}/notice-removed.json {docs}"), 0);
    assert!(text.contains("it was removed"), "{text}");
    sdk_mailbox(&[id]);
    // the SDK itself no longer encrypts for a group it was removed from
    let wdir = std::env::var("ANP_P6_SDK_WDIR").unwrap();
    let cmd = format!("cd ~/anp-interop/rust-sdk-group && ANP_VER=4 ./target/debug/anp-rust-group-interop encrypt {wdir} sdk 'still here?' msg-sdk-late {wdir}/late.json");
    let out = std::process::Command::new("wsl.exe").args(["-d", "Ubuntu", "--", "bash", "-c", &cmd]).output().unwrap();
    assert!(!out.status.success(), "the SDK should refuse to encrypt after its removal");
    println!("    sdk : refuses to encrypt for the group it was removed from");
    // and the host refuses a message from a device that is no longer a member (a stale submission this project makes in the SDK's name is not possible: the proof is the SDK's)
    let mut stale = bob.group_meta(&group_did, "op-late-bob");
    stale["sender_did"] = json!(sdk_did);
    stale["sender_device_id"] = json!(sdk_dev);
    stale["message_id"] = json!("msg-late");
    stale["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let cipher = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "3", "private_message_b64u": "AA", "group_state_ref": { "group_did": group_did, "group_state_version": "4" } });
    write_json(&dir, "late-req.json", &json!({ "scheme": ORIGIN_PROOF_SCHEME, "method": METHOD_SEND, "meta": stale, "body": cipher }));
    sdk("proof {W} sdk {W}/late-req.json {W}/late-auth.json", 0);
    let r = net.rpc(METHOD_SEND, &stale, &cipher, Some(&read_json(&dir, "late-auth.json")), None);
    println!("    host: a send signed by the removed SDK is refused with code {}", code(&r));

    // 4c. two SDK devices of one DID (own signing and key-agreement keys in the one document) in a group controlled by alice
    let mail_of = |dev: &str, ack: &[String]| -> Vec<(String, Value)> {
        let (status, v) = net.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": sdk_did, "sender_device_id": dev }, "ack": ack } }), None);
        assert_eq!(status, 200, "{v}");
        ok(&v)["notifications"].as_array().unwrap().iter().map(|n| (n["id"].as_str().unwrap().to_string(), n["notification"].clone())).collect()
    };
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("pair{}", std::process::id() % 1000) }), None);
    assert_eq!(status, 200, "{v}");
    let group3 = s(&v["group_did"]);
    sdk("kpmore {W} sdk kp-sdk-g3", 0);
    let sdk_kp3 = read_json(&dir, "sdk.kp2.json");
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &sdk_meta("op-pub-sdk-g3"), &json!({ "group_key_package": sdk_kp3 }), None, None))).unwrap();
    let kpb2 = read_json(&dir, "sdkb.kp.json");
    let mut meta_b = sdk_meta("op-pub-sdkb");
    meta_b["sender_device_id"] = json!("dev-sdkb");
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &meta_b, &json!({ "group_key_package": kpb2 }), None, None))).unwrap();
    let kp = alice.key_package("kp-alice-g3");
    let gid3 = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create-g3");
    let body = json!({ "group_did": group3, "group_state_ref": { "group_did": group3, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid3), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    wire::check_create_result(ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), None))).unwrap();
    let add3 = |adder: &mut Dev, target_dev: &str, version: u64, op: &str| {
        let kp = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &adder.service_meta("op-get"), &json!({ "target_did": sdk_did, "target_device_id": target_dev }), None, None))["group_key_package"].clone();
        let meta = adder.group_meta(&group3, op);
        let next = (adder.mls.epoch(&gid3).unwrap() + 1).to_string();
        let state = json!({ "group_did": group3, "group_state_version": version.to_string() });
        let ad = aad::add_submission_binding_for(&meta, &sdk_did, target_dev, &state, &b64(&gid3), &next).unwrap();
        let out = adder.mls.add_member(&gid3, &unb64(&kp["mls_key_package_b64u"]), &ad).unwrap();
        let body = json!({ "member_did": sdk_did, "member_device_id": target_dev, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(&gid3), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = adder.auth(METHOD_ADD, &meta, &body);
        ok(&net.rpc(METHOD_ADD, &meta, &body, Some(&auth), None));
        adder.mls.finalize_commit(&gid3).unwrap();
    };
    let welcome_for = |dev: &str, name: &str, file: &str| {
        let mail = mail_of(dev, &[]);
        let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "welcome-delivery" && n["params"]["body"]["group_did"] == group3.as_str()).expect("a welcome").clone();
        write_json(&dir, file, &json!({ "meta": n["params"]["meta"], "body": n["params"]["body"] }));
        sdk(&format!("notice {{W}} {name} {{W}}/{file} {docs}"), 0);
        mail_of(dev, &[id]);
    };
    add3(&mut alice, "dev-sdk", 2, "op-add-sdk-g3");
    welcome_for("dev-sdk", "sdk", "w-sdk.json");
    add3(&mut alice, "dev-sdkb", 3, "op-add-sdkb-g3");
    welcome_for("dev-sdkb", "sdkb", "w-sdkb.json");
    // the first SDK device processes the commit that added its sibling
    let mail = mail_of("dev-sdk", &[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "commit-delivery" && n["params"]["body"]["group_did"] == group3.as_str()).expect("the commit for the first SDK device").clone();
    write_json(&dir, "c-sdk.json", &json!({ "meta": n["params"]["meta"], "body": n["params"]["body"] }));
    sdk(&format!("notice {{W}} sdk {{W}}/c-sdk.json {docs}"), 0);
    mail_of("dev-sdk", &[id]);
    // the second SDK device writes (its own key in the origin proof); alice and its sibling read it
    write_json(&dir, "group.json", &json!({ "group_did": group3 }));
    sdk("encrypt {W} sdkb 'from the SDK second device' msg-sdkb-1 {W}/sendb.json", 3);
    let sb = read_json(&dir, "sendb.json");
    write_json(&dir, "sendb-req.json", &json!({ "scheme": ORIGIN_PROOF_SCHEME, "method": METHOD_SEND, "meta": sb["meta"], "body": sb["body"] }));
    sdk("proof {W} sdkb {W}/sendb-req.json {W}/sendb-auth.json", 0);
    ok(&net.rpc(METHOD_SEND, &sb["meta"], &sb["body"], Some(&read_json(&dir, "sendb-auth.json")), None));
    let mail = net.notes(&alice, &[]);
    let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING && n["params"]["body"]["group_did"] == group3.as_str()).expect("alice gets the second device's message").clone();
    let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
    assert_eq!(meta["sender_device_id"], "dev-sdkb");
    origin::verify_incoming(&meta, &body, &auth, &read_json(&dir, "sdk.did.json"), Some(&sdk_did)).expect("the origin proof by the second device's own key");
    let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
    let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
    let (plain, _) = alice.mls.decrypt(&gid3, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
    assert_eq!(aad::parse_application_plaintext(&plain).unwrap()["text"], "from the SDK second device");
    net.notes(&alice, &[id]);
    let mail = mail_of("dev-sdk", &[]);
    let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING && n["params"]["body"]["group_did"] == group3.as_str()).expect("the first SDK device gets it too").clone();
    write_json(&dir, "incoming-sib.json", &n["params"]);
    let text = sdk("incoming {W} sdk {W}/incoming-sib.json {W}/sdkb.did.json", 0);
    assert!(text.contains("TEXT from the SDK second device"), "{text}");
    mail_of("dev-sdk", &[id]);
    // 5. the other direction: a second SDK device creates and controls a group (create, add, send, all signed by the SDK) and adds this project
    let sdk2_doc = read_json(&dir, "sdk2.did.json");
    let sdk2_did = s(&sdk2_doc["id"]);
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("sdkled{}", std::process::id() % 1000) }), None);
    assert_eq!(status, 200, "{v}");
    let group2 = s(&v["group_did"]);
    write_json(&dir, "group.json", &json!({ "group_did": group2 }));
    let submit = |method: &str, file: &str, ver: u64| -> Value {
        let req = read_json(&dir, file);
        write_json(&dir, "req.json", &json!({ "scheme": ORIGIN_PROOF_SCHEME, "method": method, "meta": req["meta"], "body": req["body"] }));
        sdk("proof {W} sdk2 {W}/req.json {W}/auth.json", ver);
        let auth = read_json(&dir, "auth.json");
        net.rpc(method, &req["meta"], &req["body"], Some(&auth), None)
    };
    sdk(&format!("create {{W}} sdk2 {group2}"), 0);
    wire::check_create_result(ok(&submit(METHOD_CREATE, "create.json", 0))).unwrap();
    let kp2 = alice.key_package("kp-alice-2");
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &alice.service_meta("op-pub-alice2"), &json!({ "group_key_package": kp2 }), None, None))).unwrap();
    let got = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &sdk_meta("op-get-alice"), &json!({ "target_did": alice.did, "target_device_id": alice.device_id }), None, None))["group_key_package"].clone();
    write_json(&dir, "alice2.kp.json", &got);
    sdk("add {W} sdk2 {W}/alice2.kp.json {W}/alice.did.json", 2);
    let r = submit(METHOD_ADD, "add.json", 0);
    wire::check_membership_result(ok(&r)).unwrap();
    let mail = net.notes(&alice, &[]);
    let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["group_did"] == group2.as_str() && n["params"]["body"]["notice_type"] == "welcome-delivery").expect("alice's welcome into the SDK's group").clone();
    let (_, nb, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
    let (gid2, _) = alice.mls.join(&unb64(&nb["welcome_b64u"]), &unb64(&nb["ratchet_tree_b64u"])).unwrap();
    net.notes(&alice, &[id]);
    sdk("encrypt {W} sdk2 'the SDK leads this group' msg-sdk2-1 {W}/send2.json", 2);
    wire::check_send_result(ok(&submit(METHOD_SEND, "send2.json", 0))).unwrap();
    let mail = net.notes(&alice, &[]);
    let (id, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING).expect("a message in the SDK's group").clone();
    let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
    origin::verify_incoming(&meta, &body, &auth, &sdk2_doc, Some(&sdk2_did)).expect("the SDK's origin proof, verified here");
    let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
    let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
    let (plain, _) = alice.mls.decrypt(&gid2, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
    assert_eq!(aad::parse_application_plaintext(&plain).unwrap()["text"], "the SDK leads this group");
    net.notes(&alice, &[id]);
}
#[test]
fn live_two_devices_of_one_did() {
    if step().as_deref() != Some("run") {
        return;
    }
    let net = Net { url: std::env::var("ANP_P6_URL").unwrap(), sign: std::env::var("ANP_P6_SIGN").is_ok() };
    let (_, mut bob, mut carol) = devices();
    let (mut alice, mut alice2) = dana_pair();
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("multi{}", std::process::id() % 1000) }), Some(&alice));
    assert_eq!(status, 200, "{v}");
    let group_did = s(&v["group_did"]);
    for (d, id) in [(&mut bob, "kp-bob-m"), (&mut alice2, "kp-alice2-m"), (&mut carol, "kp-carol-m")] {
        let kp = d.key_package(id);
        wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &d.service_meta(&format!("op-pub-{id}")), &json!({ "group_key_package": kp }), None, Some(d)))).unwrap();
    }
    let kp = alice.key_package("kp-alice-m");
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create-m");
    let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    wire::check_create_result(ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), Some(&alice)))).unwrap();
    let add = |adder: &mut Dev, target: &Dev, version: u64, op: &str| -> Value {
        let kp = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &adder.service_meta("op-get"), &json!({ "target_did": target.did, "target_device_id": target.device_id }), None, Some(adder)))["group_key_package"].clone();
        let meta = adder.group_meta(&group_did, op);
        let next = (adder.mls.epoch(&gid).unwrap() + 1).to_string();
        let state = json!({ "group_did": group_did, "group_state_version": version.to_string() });
        let ad = aad::add_submission_binding_for(&meta, &target.did, &target.device_id, &state, &b64(&gid), &next).unwrap();
        let out = adder.mls.add_member(&gid, &unb64(&kp["mls_key_package_b64u"]), &ad).unwrap();
        let body = json!({ "member_did": target.did, "member_device_id": target.device_id, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = adder.auth(METHOD_ADD, &meta, &body);
        net.rpc(METHOD_ADD, &meta, &body, Some(&auth), Some(adder))
    };
    // alice adds bob, then her own second device
    ok(&add(&mut alice, &bob, 2, "op-add-bob-m"));
    alice.mls.finalize_commit(&gid).unwrap();
    let take_welcome = |d: &mut Dev| {
        let mail = net.notes(d, &[]);
        let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "welcome-delivery" && n["params"]["body"]["group_did"] == group_did.as_str() && n["params"]["meta"]["recipient_device_id"] == d.device_id.as_str()).expect("a welcome for this device").clone();
        let (_, nb, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
        let (g, _) = d.mls.join(&unb64(&nb["welcome_b64u"]), &unb64(&nb["ratchet_tree_b64u"])).unwrap();
        assert_eq!(g, gid);
        net.notes(d, &[id]);
    };
    take_welcome(&mut bob);
    ok(&add(&mut alice, &alice2, 3, "op-add-alice2"));
    alice.mls.finalize_commit(&gid).unwrap();
    take_welcome(&mut alice2);
    // the leaves of one DID differ in device and key, and every leaf checks against the one document
    let leaves = alice2.mls.leaves(&gid).unwrap();
    assert_eq!(leaves.len(), 3);
    let evs: Vec<anp_group::binding::LeafIdentity> = leaves.iter().map(|l| { let b = l.binding().unwrap(); anp_group::binding::LeafIdentity { agent_did: s(&b["agent_did"]), device_id: s(&b["device_id"]), leaf_signature_key_b64u: s(&b["leaf_signature_key_b64u"]) } }).collect();
    anp_group::binding::check_leaf_identity_set(&evs).expect("devices of one DID differ in device and key");
    // the second device is a member, not the controller
    let r = add(&mut alice2, &carol, 4, "op-alice2-adds");
    assert_eq!(code(&r), 5003, "{r}");
    alice2.mls.abort_commit(&gid).unwrap();
    // alice2 writes (state 3, epoch 2): bob reads it, and so does alice's first device (same DID, own mailbox entry)
    let mut m = alice2.group_meta(&group_did, "op-m-a2");
    m["message_id"] = json!("msg-a2");
    m["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let plain = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": "from dana's second device" })).unwrap();
    let mut cipher = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "2", "private_message_b64u": "AA", "group_state_ref": { "group_did": group_did, "group_state_version": "3" } });
    let ad = aad::send_authenticated_data(&m, &cipher).unwrap();
    cipher["private_message_b64u"] = json!(b64(&alice2.mls.encrypt(&gid, &plain, &ad).unwrap()));
    let auth = alice2.auth(METHOD_SEND, &m, &cipher);
    wire::check_send_result(ok(&net.rpc(METHOD_SEND, &m, &cipher, Some(&auth), Some(&alice2)))).unwrap();
    // bob processes the commit that added dana's second device (made by dana's first), as a recipient works it out from the notice
    {
        let mail = net.notes(&bob, &[]);
        let (id, n) = mail.iter().find(|(_, n)| n["params"]["body"]["notice_type"] == "commit-delivery" && n["params"]["body"]["group_did"] == group_did.as_str()).expect("a commit for bob").clone();
        let (nmeta, nbody, _) = wire::parse_request(METHOD_NOTICE, &n).unwrap();
        let commit = unb64(&nbody["commit_b64u"]);
        let info = anp_group_mls::inspect_commit(&commit).unwrap();
        let committer = bob.mls.leaves(&gid).unwrap().into_iter().find(|l| l.leaf_index == info.sender_leaf).unwrap().binding().unwrap();
        let bmeta = json!({ "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": committer["agent_did"], "sender_device_id": committer["device_id"], "target": { "kind": "group", "did": group_did }, "operation_id": nmeta["operation_id"] });
        let expected = aad::add_submission_binding_for(&bmeta, nbody["subject_did"].as_str().unwrap(), nbody["subject_device_id"].as_str().unwrap(), &nbody["group_state_ref"], &b64(&gid), nbody["epoch"].as_str().unwrap()).unwrap();
        assert_eq!(bob.mls.process_commit(&gid, &commit, &expected).unwrap(), 2);
        net.notes(&bob, &[id]);
    }
    let (adoc, adid) = (alice.doc.clone(), alice.did.clone());
    for reader in [&mut bob, &mut alice] {
        let rid = reader.device_id.clone();
        let mail = net.notes(reader, &[]);
        let (_, n) = mail.iter().rev().find(|(_, n)| n["method"] == METHOD_INCOMING && n["params"]["meta"]["recipient_device_id"] == rid.as_str() && n["params"]["body"]["group_did"] == group_did.as_str()).expect("an incoming message for this device").clone();
        let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &n).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
        assert_eq!(meta["sender_device_id"], "dev-dana2");
        origin::verify_incoming(&meta, &body, &auth, &adoc, Some(&adid)).unwrap();
        let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
        let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
        let (plain, _) = reader.mls.decrypt(&gid, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
        assert_eq!(aad::parse_application_plaintext(&plain).unwrap()["text"], "from dana's second device");
    }
}

#[test]
fn live_a_held_pull_returns_on_delivery() {
    if step().as_deref() != Some("run") {
        return;
    }
    let url = std::env::var("ANP_P6_URL").unwrap();
    let sign = std::env::var("ANP_P6_SIGN").is_ok();
    let net = Net { url: url.clone(), sign };
    let (mut alice, mut bob, _) = devices();
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("held{}", std::process::id() % 1000) }), Some(&alice));
    assert_eq!(status, 200, "{v}");
    let group_did = s(&v["group_did"]);
    let kpb = bob.key_package("kp-bob-held");
    wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &bob.service_meta("op-pub-held"), &json!({ "group_key_package": kpb }), None, Some(&bob)))).unwrap();
    let kp = alice.key_package("kp-alice-held");
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create-held");
    let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), Some(&alice)));
    // an empty mailbox, so that the held pull has something to wait for
    let old: Vec<String> = net.notes(&bob, &[]).into_iter().map(|(id, _)| id).collect();
    net.notes(&bob, &old);
    // bob holds a pull open (up to 20 s); a nothing-yet mailbox would otherwise answer at once
    let waiter = {
        let (url, did, dev, bobsk, bobvm) = (url.clone(), bob.did.clone(), bob.device_id.clone(), bob.sk.clone(), bob.vm.clone());
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let body = json!({ "jsonrpc": "2.0", "id": 9, "method": "group.e2ee.pull", "params": { "meta": { "sender_did": did, "sender_device_id": dev }, "wait_ms": 20000 } });
            let text = body.to_string();
            let full = format!("{url}/anp/groups");
            let mut req = ureq::post(&full).set("content-type", "application/json");
            if sign {
                let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                for (k, v) in anp_httpauth::sign(&bobsk, &bobvm, "POST", &full, text.as_bytes(), created, &format!("held-{created}")).unwrap() {
                    req = req.set(&k, &v);
                }
            }
            let r: Value = serde_json::from_str(&req.timeout(std::time::Duration::from_secs(40)).send_string(&text).unwrap().into_string().unwrap()).unwrap();
            (started.elapsed(), r)
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let kpr = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &alice.service_meta("op-get-held"), &json!({ "target_did": bob.did, "target_device_id": bob.device_id }), None, Some(&alice)))["group_key_package"].clone();
    let meta = alice.group_meta(&group_did, "op-add-held");
    let state = json!({ "group_did": group_did, "group_state_version": "2" });
    let ad = aad::add_submission_binding_for(&meta, &bob.did, &bob.device_id, &state, &b64(&gid), "1").unwrap();
    let out = alice.mls.add_member(&gid, &unb64(&kpr["mls_key_package_b64u"]), &ad).unwrap();
    let body = json!({ "member_did": bob.did, "member_device_id": bob.device_id, "group_state_ref": state, "group_key_package": kpr, "crypto_group_id_b64u": b64(&gid), "epoch": "1", "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
    let auth = alice.auth(METHOD_ADD, &meta, &body);
    ok(&net.rpc(METHOD_ADD, &meta, &body, Some(&auth), Some(&alice)));
    let (took, r) = waiter.join().unwrap();
    let notes = ok(&r)["notifications"].as_array().unwrap();
    assert!(notes.iter().any(|n| n["notification"]["params"]["body"]["notice_type"] == "welcome-delivery"), "{r}");
    assert!(took >= std::time::Duration::from_millis(1400) && took < std::time::Duration::from_secs(10), "the held pull returned after {took:?}");
}
// ── the push channel (a WebSocket per device) and the group state, through the node ─────────────────────

use tungstenite::{stream::MaybeTlsStream, Message};

type Sock = tungstenite::WebSocket<MaybeTlsStream<std::net::TcpStream>>;

/// Open `GET /anp/groups/ws` for `d`'s mailbox, signed (ANP-02) by `signer` when the node requires it. Reads time out after a second.
fn ws_open(net: &Net, d: &Dev, signer: Option<&Dev>) -> Result<Sock, tungstenite::Error> {
    let http = format!("{}/anp/groups/ws?did={}&device={}", net.url, d.did, d.device_id);
    let mut req = tungstenite::client::IntoClientRequest::into_client_request(http.replacen("http://", "ws://", 1)).unwrap();
    if let (true, Some(sg)) = (net.sign, signer) {
        let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        for (k, v) in anp_httpauth::sign(&sg.sk, &sg.vm, "GET", &http, b"", created, &format!("ws-{}-{created}", std::process::id())).unwrap() {
            req.headers_mut().insert(tungstenite::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), tungstenite::http::HeaderValue::from_str(&v).unwrap());
        }
    }
    let (mut sock, _) = tungstenite::connect(req)?;
    if let MaybeTlsStream::Plain(s) = sock.get_mut() {
        s.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
    }
    Ok(sock)
}

/// The next pushed frame within `secs` seconds (as the parsed `{id, notification}`), or `None`.
fn ws_next(sock: &mut Sock, secs: u32) -> Option<Value> {
    for _ in 0..secs {
        match sock.read() {
            Ok(Message::Text(t)) => return Some(serde_json::from_str(&t).unwrap()),
            Ok(Message::Close(_)) => return None,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => panic!("the push channel failed: {e}"),
        }
    }
    None
}

#[test]
fn live_push_channel_hashes_and_policy() {
    if step().as_deref() != Some("run") {
        return;
    }
    use anp_group::state;
    let net = Net { url: std::env::var("ANP_P6_URL").unwrap(), sign: std::env::var("ANP_P6_SIGN").is_ok() };
    // dave, erin and frank play the parts of alice (the controller), bob and carol
    let (mut alice, mut bob, mut carol) = push_devices();
    let entry = |d: &Dev| (d.did.clone(), d.device_id.clone(), d.mls.leaf_signature_key_b64u());

    // a group with a policy of at most two members
    let (status, v) = net.post("/anp/groups/provision", &json!({ "name": format!("push{}", std::process::id() % 1000), "max_members": 2 }), Some(&alice));
    assert_eq!(status, 200, "{v}");
    let group_did = s(&v["group_did"]);
    assert_eq!(v["policy_hash"], state::policy_hash(Some(2)).as_str(), "the host says which policy it holds");
    let served = ureq::get(&format!("{}/{}/did.json", net.url, group_did.split(':').skip(3).collect::<Vec<_>>().join("/"))).call().unwrap().into_string().unwrap();
    let group_doc: Value = serde_json::from_str(&served).unwrap();
    let receipt_key = anp_group_host::receipt_key(&group_doc).unwrap();
    for (d, id) in [(&mut bob, "kp-bob-push"), (&mut carol, "kp-carol-push")] {
        let kp = d.key_package(id);
        wire::check_publish_key_package_result(ok(&net.rpc(METHOD_PUBLISH_KEY_PACKAGE, &d.service_meta(&format!("op-pub-{id}")), &json!({ "group_key_package": kp }), None, Some(d)))).unwrap();
    }
    let kp = alice.key_package("kp-alice-push");
    let gid = alice.mls.create_group(&alice.binding()).unwrap();
    let meta = alice.create_meta("op-create-push");
    let body = json!({ "group_did": group_did, "group_state_ref": { "group_did": group_did, "group_state_version": "1" }, "suite": MTI_SUITE, "creator_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": "0" });
    let auth = alice.auth(METHOD_CREATE, &meta, &body);
    ok(&net.rpc(METHOD_CREATE, &meta, &body, Some(&auth), Some(&alice)));

    // who may listen: only the device's own DID (signed), and nobody unsigned
    if net.sign {
        match ws_open(&net, &bob, Some(&alice)) {
            Err(tungstenite::Error::Http(r)) => assert_eq!(r.status().as_u16(), 401, "alice cannot listen to bob's mailbox"),
            other => panic!("alice listening to bob's mailbox: {:?}", other.map(|_| "connected")),
        }
        match ws_open(&net, &bob, None) {
            Err(tungstenite::Error::Http(r)) => assert_eq!(r.status().as_u16(), 401, "an unsigned upgrade"),
            other => panic!("an unsigned upgrade: {:?}", other.map(|_| "connected")),
        }
    }

    // bob listens; nothing waits for him
    let mut sock = ws_open(&net, &bob, Some(&bob)).expect("bob opens his own channel");
    assert!(ws_next(&mut sock, 2).is_none(), "an empty mailbox pushes nothing");

    // alice adds bob with a state reference that carries both hashes; the welcome is pushed to bob, the reference intact
    let add = |net: &Net, adder: &mut Dev, target: &Dev, state: &Value, op: &str| -> Value {
        let m = adder.service_meta("op-get");
        let kp = ok(&net.rpc(METHOD_GET_KEY_PACKAGE, &m, &json!({ "target_did": target.did, "target_device_id": target.device_id }), None, Some(adder)))["group_key_package"].clone();
        let meta = adder.group_meta(&group_did, op);
        let next = (adder.mls.epoch(&gid).unwrap() + 1).to_string();
        let ad = aad::add_submission_binding_for(&meta, &target.did, &target.device_id, state, &b64(&gid), &next).unwrap();
        let out = adder.mls.add_member(&gid, &unb64(&kp["mls_key_package_b64u"]), &ad).unwrap();
        let body = json!({ "member_did": target.did, "member_device_id": target.device_id, "group_state_ref": state, "group_key_package": kp, "crypto_group_id_b64u": b64(&gid), "epoch": next, "commit_b64u": b64(&out.commit), "welcome_b64u": b64(&out.welcome), "ratchet_tree_b64u": b64(&out.ratchet_tree) });
        let auth = adder.auth(METHOD_ADD, &meta, &body);
        net.rpc(METHOD_ADD, &meta, &body, Some(&auth), Some(adder))
    };
    let two = state::state_ref(&group_did, 2, Some(2), &[entry(&alice), entry(&bob)]);
    ok(&add(&net, &mut alice, &bob, &two, "op-push-add"));
    alice.mls.finalize_commit(&gid).unwrap();
    let frame = ws_next(&mut sock, 10).expect("the welcome is pushed to bob");
    let (_, nbody, _) = wire::parse_request(METHOD_NOTICE, &frame["notification"]).unwrap();
    assert_eq!(nbody["notice_type"], "welcome-delivery");
    assert_eq!(nbody["group_state_ref"], two, "the notice carries the reference with the hashes, as bound");
    bob.mls.join(&unb64(&nbody["welcome_b64u"]), &unb64(&nbody["ratchet_tree_b64u"])).unwrap();
    sock.send(Message::Text(json!({ "ack": [frame["id"]] }).to_string())).unwrap();
    // acknowledged on the channel: the mailbox is empty (a pull agrees)
    let mut left = 1;
    for _ in 0..10 {
        left = net.notes(&bob, &[]).len();
        if left == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert_eq!(left, 0, "what the device acknowledges on the channel is dropped");

    // a message alice sends is pushed too
    let mut m = alice.group_meta(&group_did, "op-push-m");
    m["message_id"] = json!("msg-push");
    m["content_type"] = json!(CIPHER_CONTENT_TYPE);
    let plain = aad::canonical_application_plaintext(&json!({ "application_content_type": "text/plain", "text": "pushed" })).unwrap();
    let mut cipher = json!({ "crypto_group_id_b64u": b64(&gid), "epoch": "1", "private_message_b64u": "AA", "group_state_ref": two });
    let ad = aad::send_authenticated_data(&m, &cipher).unwrap();
    cipher["private_message_b64u"] = json!(b64(&alice.mls.encrypt(&gid, &plain, &ad).unwrap()));
    let auth = alice.auth(METHOD_SEND, &m, &cipher);
    ok(&net.rpc(METHOD_SEND, &m, &cipher, Some(&auth), Some(&alice)));
    let frame = ws_next(&mut sock, 10).expect("the message is pushed to bob");
    assert_eq!(frame["notification"]["method"], METHOD_INCOMING);
    let (meta, body, auth) = wire::parse_request(METHOD_INCOMING, &frame["notification"]).map(|(m, b, a)| (m, b, a.unwrap())).unwrap();
    let original = origin::reconstruct_send_request(&meta, &body, &auth).unwrap();
    let ad = aad::send_authenticated_data(&original["meta"], &body["group_cipher_object"]).unwrap();
    let (got, _) = bob.mls.decrypt(&gid, &unb64(&body["group_cipher_object"]["private_message_b64u"]), &ad).unwrap();
    assert_eq!(aad::parse_application_plaintext(&got).unwrap()["text"], "pushed");
    sock.send(Message::Text(json!({ "ack": [frame["id"]] }).to_string())).unwrap();

    // the policy keeps a third device out (a wrong hash is refused too, see the host tests: the cap is looked at first)
    let three = state::state_ref(&group_did, 3, Some(2), &[entry(&alice), entry(&bob), entry(&carol)]);
    let r = add(&net, &mut alice, &carol, &three, "op-push-three");
    assert_eq!(code(&r), -32010, "{r}");
    alice.mls.abort_commit(&gid).unwrap();

    // the group's state, signed by the group: a member gets it, the roster hash matches what a client computes, and only the device's own DID may ask
    let ask = |who: &Dev, signer: &Dev| net.post("/anp/groups", &json!({ "jsonrpc": "2.0", "id": 4, "method": "group.e2ee.state", "params": { "meta": { "sender_did": who.did, "sender_device_id": who.device_id }, "group_did": group_did } }), Some(signer)).1;
    let st = ok(&ask(&bob, &bob)).clone();
    anp_did::verify_proof(&st, &receipt_key).expect("the state is signed by the group's key");
    assert_eq!(st["roster_hash"], state::roster_hash(&[entry(&alice), entry(&bob)]).as_str());
    assert_eq!(st["policy_hash"], state::policy_hash(Some(2)).as_str());
    assert_eq!(st["group_state_version"], "2");
    assert_eq!(code(&ask(&carol, &carol)), 5013, "carol is not a member");
    if net.sign {
        assert_eq!(code(&ask(&bob, &alice)), -32001, "alice cannot ask in bob's name");
    }
    let _ = sock.close(None);
}
