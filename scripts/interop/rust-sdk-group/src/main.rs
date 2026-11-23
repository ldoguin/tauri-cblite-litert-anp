// The official ANP Rust SDK (anp 1.0.7, Apache-2.0, its `mls` feature) as one P6 v2 group device, driven through its typed operations
// with JSON files for everything that crosses to this project. Built in an isolated folder by scripts/interop/rust-sdk-group-build.sh.
//
//   kp DIR NAME                              a device (DID document with a P6 manifest, signing key) and its key package
//   create DIR NAME GROUP_DID                create a group (and finalize it)
//   add DIR NAME MEMBER.kp.json MEMBER.did.json   add a device (commit, welcome, tree) and finalize; writes DIR/add.json
//   welcome DIR NAME ADD.json DOC.json...    join from the welcome of an add
//   commit DIR NAME ADD.json                 process the commit of an add made by somebody else
//   encrypt DIR NAME TEXT MSG_ID OUT.json    send a message; writes {meta, body}
//   decrypt DIR NAME IN.json SENDER.did.json read a message; prints its text
//   kpmore DIR NAME KPID                     another key package for an existing device
//   kpextra DIR NAME EXTRA                   a second device EXTRA of NAME's DID (own signing and key-agreement key in the document); writes EXTRA.kp.json
//   notice DIR NAME NOTE.json DOC.json...    process a delivered group.e2ee.notice ({meta, body}: welcome or commit)
//   proof DIR NAME REQ.json OUT.json         RFC 9421 origin proof for {scheme, method, meta, body}; writes the uth object
//   incoming DIR NAME NOTE.json SENDER.did.json  verify a delivered group.e2ee.incoming (origin proof) and decrypt it
// ANP_VER sets the group state version the operation is made against (default: add 2, encrypt 2).
use anp::authentication::{create_did_wba_document, validate_device_manifest, DidDocumentOptions, DidProfile};
use anp::group_e2ee::operations::v2::*;
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::group_e2ee::{V2GroupApplicationPlaintext, V2GroupCipherObject, V2GroupControlMetadata, V2GroupSendMetadata, V2GroupStateRef, V2ServiceMetadata};
use anp::proof::{generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY};
use anp::PrivateKeyMaterial;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const NOW: &str = "2026-11-20T00:00:00Z";
const ISSUED_AT: &str = "2026-11-15T00:00:00Z";
const EXPIRES_AT: &str = "2026-12-15T00:00:00Z";

fn read(p: impl AsRef<Path>) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", p.as_ref().display()))).unwrap()
}
fn write(p: impl AsRef<Path>, v: &Value) {
    std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).unwrap();
}
fn ok(name: &str, good: bool, detail: impl std::fmt::Display) {
    if good {
        println!("PASS  {name}");
    } else {
        println!("FAIL  {name}  {detail}");
        std::process::exit(1);
    }
}

fn store(dir: &Path, name: &str) -> ImCoreSqliteGroupMlsStore {
    let doc = read(dir.join(format!("{name}.did.json")));
    ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(dir.join(name).join("local_state.sqlite"), format!("identity-{name}"), doc["id"].as_str().unwrap().to_owned(), format!("dev-{name}")).expect("device-scoped MLS store")
}

fn did_of(dir: &Path, name: &str) -> (String, Value, String) {
    let doc = read(dir.join(format!("{name}.did.json")));
    (doc["id"].as_str().unwrap().to_owned(), doc.clone(), format!("dev-{name}"))
}

fn key(dir: &Path, name: &str) -> PrivateKeyMaterial {
    PrivateKeyMaterial::from_pem(&std::fs::read_to_string(dir.join(format!("{name}.key.pem"))).unwrap()).unwrap()
}

fn ver(default: u64) -> u64 {
    std::env::var("ANP_VER").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn state_ref(group_did: &str, version: u64) -> V2GroupStateRef {
    serde_json::from_value(json!({ "group_did": group_did, "group_state_version": version.to_string() })).unwrap()
}

fn control_meta(did: &str, device: &str, group_did: &str, op: &str) -> V2GroupControlMetadata {
    serde_json::from_value(json!({ "anp_version": "2.0", "profile": "anp.group.e2ee.v2", "security_profile": "group-e2ee", "sender_did": did, "sender_device_id": device, "target": { "kind": "group", "did": group_did }, "operation_id": op, "created_at": NOW })).unwrap()
}

fn service_meta(did: &str, device: &str, op: &str) -> V2ServiceMetadata {
    serde_json::from_value(json!({ "anp_version": "2.0", "profile": "anp.group.e2ee.v2", "security_profile": "group-e2ee", "sender_did": did, "sender_device_id": device, "target": { "kind": "service", "did": "did:wba:groups.example:services:host" }, "operation_id": op, "created_at": NOW })).unwrap()
}

fn send_meta(did: &str, device: &str, group_did: &str, msg: &str) -> V2GroupSendMetadata {
    serde_json::from_value(json!({ "anp_version": "2.0", "profile": "anp.group.e2ee.v2", "security_profile": "group-e2ee", "sender_did": did, "sender_device_id": device, "target": { "kind": "group", "did": group_did }, "operation_id": format!("op-{msg}"), "message_id": msg, "content_type": "application/anp-group-cipher+json", "created_at": NOW })).unwrap()
}

fn vm_of(dir: &Path, name: &str, did: &str) -> String {
    std::fs::read_to_string(dir.join(format!("{name}.vm"))).map(|s| s.trim().to_owned()).unwrap_or_else(|_| format!("{did}#key-1"))
}

fn docs(paths: &[String]) -> Vec<V2DidDocument> {
    paths.iter().map(|p| { let d = read(p); V2DidDocument { did: d["id"].as_str().unwrap().to_owned(), document: d } }).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(&a[1]);
    let name = a[2].clone();
    match a[0].as_str() {
        "kp" => {
            let primary = create_did_wba_document("p6-sdk.example", DidDocumentOptions { path_segments: vec!["agents".to_owned(), name.clone()], did_profile: DidProfile::E1, created: Some(ISSUED_AT.to_owned()), ..Default::default() }).expect("DID document");
            let did = primary.did().expect("DID").to_owned();
            let root = PrivateKeyMaterial::from_pem(&primary.keys["key-1"].private_key_pem).unwrap();
            let mut doc = primary.did_document.clone();
            doc.as_object_mut().unwrap().remove("proof");
            doc["deviceManifest"] = json!({ "type": "ANPDeviceManifest", "devices": [{ "device_id": format!("dev-{name}"), "signing_key_id": format!("{did}#key-1"), "e2ee_key_id": format!("{did}#key-3"), "profiles": ["anp.core.binding.v1", "anp.identity.discovery.v1", "anp.group.base.v2", "anp.group.e2ee.v2"] }] });
            let doc = generate_w3c_proof(&doc, &root, &format!("{did}#key-1"), ProofGenerationOptions { proof_purpose: Some("assertionMethod".to_owned()), proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()), cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()), created: Some(ISSUED_AT.to_owned()), ..Default::default() }).expect("signed DID document");
            validate_device_manifest(&doc).expect("valid manifest");
            std::fs::create_dir_all(&dir).unwrap();
            write(dir.join(format!("{name}.did.json")), &doc);
            std::fs::write(dir.join(format!("{name}.key.pem")), &primary.keys["key-1"].private_key_pem).unwrap();
            let st = store(&dir, &name);
            let kp = generate_key_package_v2(&st, V2GenerateKeyPackageInput { owner_did: did.clone(), owner_device_id: format!("dev-{name}"), verification_method: format!("{did}#key-1"), key_package_id: format!("kp-{name}"), issued_at: ISSUED_AT.to_owned(), expires_at: EXPIRES_AT.to_owned(), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-kp".to_owned() }, &doc, &root).expect("the SDK makes its key package");
            write(dir.join(format!("{name}.kp.json")), &serde_json::to_value(&kp).unwrap());
            println!("the SDK device {did} has a key package");
        }
        "create" => {
            let group_did = a[3].clone();
            let (did, doc, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let kp = serde_json::from_value(read(dir.join(format!("{name}.kp.json")))).unwrap();
            let prepared = create_group_prepare_v2(&st, V2CreateGroupInput { meta: service_meta(&did, &device, "op-create"), group_state_ref: state_ref(&group_did, 1), creator_key_package: kp, creator_did_document: doc, now: NOW.to_owned(), draft_extension_negotiated: true, pending_commit_id: "pending-create".to_owned(), request_id: "req-create".to_owned() }).expect("the SDK prepares the group");
            let fin = finalize_commit_v2(&st, V2FinalizeInput { pending_commit_id: prepared.pending_commit_id, request_id: "req-fin".to_owned() }).expect("finalize");
            write(dir.join("create.json"), &json!({ "meta": serde_json::to_value(&service_meta(&did, &device, "op-create")).unwrap(), "body": serde_json::to_value(&prepared.body).unwrap() }));
            println!("the SDK created group {} at epoch {}", prepared.body.crypto_group_id_b64u, fin.epoch);
        }
        "add" => {
            let (did, doc, device) = did_of(&dir, &name);
            let _ = doc;
            let st = store(&dir, &name);
            let kp: anp::group_e2ee::V2GroupKeyPackage = serde_json::from_value(read(&a[3])).unwrap();
            let member_doc = read(&a[4]);
            let group_did = read(dir.join("group.json"))["group_did"].as_str().unwrap().to_owned();
            let meta = control_meta(&did, &device, &group_did, "op-add");
            let prepared = add_member_prepare_v2(&st, V2AddMemberInput { meta: meta.clone(), group_state_ref: state_ref(&group_did, ver(2)), group_key_package: kp, member_did_document: member_doc, now: NOW.to_owned(), draft_extension_negotiated: true, pending_commit_id: "pending-add".to_owned(), request_id: "req-add".to_owned() }).expect("the SDK prepares the add");
            let fin = finalize_commit_v2(&st, V2FinalizeInput { pending_commit_id: prepared.pending_commit_id.clone(), request_id: "req-fin-add".to_owned() }).expect("finalize");
            write(dir.join("add.json"), &json!({ "meta": serde_json::to_value(&meta).unwrap(), "body": serde_json::to_value(&prepared.body).unwrap() }));
            println!("the SDK added a device; the group is at epoch {}", fin.epoch);
        }
        "welcome" => {
            let (did, _, device) = did_of(&dir, &name);
            let add = read(&a[3]);
            let st = store(&dir, &name);
            let body = &add["body"];
            let group_did = body["group_state_ref"]["group_did"].as_str().unwrap().to_owned();
            let out = process_welcome_v2(&st, V2ProcessWelcomeInput { recipient_did: did, recipient_device_id: device, group_did: group_did.clone(), group_state_ref: serde_json::from_value(body["group_state_ref"].clone()).unwrap(), crypto_group_id_b64u: body["crypto_group_id_b64u"].as_str().unwrap().to_owned(), epoch: body["epoch"].as_str().unwrap().to_owned(), welcome_b64u: body["welcome_b64u"].as_str().unwrap().to_owned(), ratchet_tree_b64u: body["ratchet_tree_b64u"].as_str().unwrap().to_owned(), member_documents: docs(&a[4..]), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-welcome".to_owned() });
            ok("the SDK processes the welcome (every leaf's binding validated against its DID document)", out.is_ok(), out.as_ref().err().map(|e| format!("{e:?}")).unwrap_or_default());
        }
        "commit" => {
            let _ = (&dir, &name, &a);
            println!("(the SDK processes the commits of others through process_notice_v2; not exercised here)");
        }
        "encrypt" => {
            let (did, doc, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let group = read(dir.join("group.json"));
            let group_did = group["group_did"].as_str().unwrap().to_owned();
            let meta = send_meta(&did, &device, &group_did, &a[4]);
            let plaintext: V2GroupApplicationPlaintext = serde_json::from_value(json!({ "application_content_type": "text/plain", "text": a[3] })).unwrap();
            let body = encrypt_v2(&st, V2EncryptInput { meta: meta.clone(), group_state_ref: state_ref(&group_did, ver(2)), application_plaintext: plaintext, sender_did_document: doc, now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-enc".to_owned() }).expect("the SDK encrypts");
            write(&a[5], &json!({ "meta": serde_json::to_value(&meta).unwrap(), "body": serde_json::to_value(&body).unwrap() }));
            println!("the SDK sent {:?}", a[3]);
        }
        "decrypt" => {
            let (did, _, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let m = read(&a[3]);
            let body: V2GroupCipherObject = serde_json::from_value(m["body"].clone()).unwrap();
            let out = decrypt_v2(&st, V2DecryptInput { recipient_did: did, recipient_device_id: device, originating_meta: serde_json::from_value(m["meta"].clone()).unwrap(), group_cipher_object: body, sender_did_document: read(&a[4]), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-dec".to_owned() });
            match out {
                Ok(o) => {
                    let v = serde_json::to_value(&o.application_plaintext).unwrap();
                    println!("PASS  the SDK decrypts the message and validates its sender's leaf: {:?}", v["text"]);
                    println!("TEXT {}", v["text"].as_str().unwrap_or(""));
                }
                Err(e) => ok("the SDK decrypts the message", false, format!("{e:?}")),
            }
        }
        "kpmore" => {
            let (did, doc, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let vm = vm_of(&dir, &name, &did);
            let k = key(&dir, &name);
            let kp = generate_key_package_v2(&st, V2GenerateKeyPackageInput { owner_did: did.clone(), owner_device_id: device, verification_method: vm, key_package_id: a[3].clone(), issued_at: ISSUED_AT.to_owned(), expires_at: EXPIRES_AT.to_owned(), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-kp".to_owned() }, &doc, &k).expect("another key package");
            write(dir.join(format!("{name}.kp2.json")), &serde_json::to_value(&kp).unwrap());
            println!("the SDK device {name} has another key package");
        }
        "kpextra" => {
            let extra = a[3].clone();
            let (did, mut doc, _) = did_of(&dir, &name);
            let root = key(&dir, &name);
            let tmp = create_did_wba_document("p6-sdk-tmp.example", DidDocumentOptions { path_segments: vec!["agents".to_owned(), extra.clone()], did_profile: DidProfile::E1, created: Some(ISSUED_AT.to_owned()), ..Default::default() }).expect("key material");
            let find = |suffix: &str| tmp.did_document["verificationMethod"].as_array().unwrap().iter().find(|v| v["id"].as_str().unwrap().ends_with(suffix)).cloned().expect("verification method");
            let (mut sign_vm, mut ka_vm) = (find("#key-1"), find("#key-3"));
            sign_vm["id"] = json!(format!("{did}#key-4"));
            sign_vm["controller"] = json!(did);
            ka_vm["id"] = json!(format!("{did}#key-5"));
            ka_vm["controller"] = json!(did);
            doc.as_object_mut().unwrap().remove("proof");
            doc["verificationMethod"].as_array_mut().unwrap().push(sign_vm);
            doc["verificationMethod"].as_array_mut().unwrap().push(ka_vm);
            doc["authentication"].as_array_mut().unwrap().push(json!(format!("{did}#key-4")));
            doc["assertionMethod"].as_array_mut().unwrap().push(json!(format!("{did}#key-4")));
            doc["keyAgreement"].as_array_mut().unwrap().push(json!(format!("{did}#key-5")));
            doc["deviceManifest"]["devices"].as_array_mut().unwrap().push(json!({ "device_id": format!("dev-{extra}"), "signing_key_id": format!("{did}#key-4"), "e2ee_key_id": format!("{did}#key-5"), "profiles": ["anp.core.binding.v1", "anp.identity.discovery.v1", "anp.group.base.v2", "anp.group.e2ee.v2"] }));
            let doc = generate_w3c_proof(&doc, &root, &format!("{did}#key-1"), ProofGenerationOptions { proof_purpose: Some("assertionMethod".to_owned()), proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()), cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()), created: Some(ISSUED_AT.to_owned()), ..Default::default() }).expect("signed DID document");
            validate_device_manifest(&doc).expect("valid manifest with two devices");
            write(dir.join(format!("{name}.did.json")), &doc);
            write(dir.join(format!("{extra}.did.json")), &doc);
            std::fs::write(dir.join(format!("{extra}.key.pem")), &tmp.keys["key-1"].private_key_pem).unwrap();
            std::fs::write(dir.join(format!("{extra}.vm")), format!("{did}#key-4")).unwrap();
            let st = store(&dir, &extra);
            let k = key(&dir, &extra);
            let kp = generate_key_package_v2(&st, V2GenerateKeyPackageInput { owner_did: did.clone(), owner_device_id: format!("dev-{extra}"), verification_method: format!("{did}#key-4"), key_package_id: format!("kp-{extra}"), issued_at: ISSUED_AT.to_owned(), expires_at: EXPIRES_AT.to_owned(), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-kp".to_owned() }, &doc, &k).expect("the second device's key package");
            write(dir.join(format!("{extra}.kp.json")), &serde_json::to_value(&kp).unwrap());
            println!("the SDK device {extra} is a second device of {did}");
        }        "notice" => {
            let (did, _, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let n = read(&a[3]);
            let out = process_notice_v2(&st, V2ProcessNoticeInput { recipient_did: did, recipient_device_id: device, meta: serde_json::from_value(n["meta"].clone()).expect("notice meta"), notice: serde_json::from_value(n["body"].clone()).expect("notice body"), member_documents: docs(&a[4..]), now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-notice".to_owned() });
            match &out {
                Ok(o) => println!("PASS  the SDK processes the {} notice: epoch {} -> {}{}", o.notice_type, o.from_epoch, o.epoch, if o.self_removed { " (it was removed)" } else { "" }),
                Err(e) => ok("the SDK processes the notice", false, format!("{e:?}")),
            }
        }
        "proof" => {
            let req = read(&a[3]);
            let k = key(&dir, &name);
            let (did, _, _) = did_of(&dir, &name);
            let proof = anp::proof::generate_rfc9421_origin_proof(req["method"].as_str().unwrap(), &req["meta"], &req["body"], &k, &vm_of(&dir, &name, &did), anp::proof::Rfc9421OriginProofGenerationOptions { created: Some(1784419200), nonce: Some("n".to_owned()), ..Default::default() }).expect("the SDK signs the submission");
            write(&a[4], &json!({ "scheme": req["scheme"], "origin_proof": { "contentDigest": proof.content_digest, "signatureInput": proof.signature_input, "signature": proof.signature } }));
            println!("the SDK signed a {} submission", req["method"].as_str().unwrap());
        }
        "incoming" => {
            let (did, _, device) = did_of(&dir, &name);
            let st = store(&dir, &name);
            let n = read(&a[3]);
            let sender_doc = read(&a[4]);
            let meta: anp::group_e2ee::V2GroupIncomingMetadata = serde_json::from_value(n["meta"].clone()).expect("incoming meta");
            let body: anp::group_e2ee::V2GroupIncomingBody = serde_json::from_value(n["body"].clone()).expect("incoming body");
            let auth: anp::group_e2ee::V2DeliveredOriginAuth = serde_json::from_value(n["auth"].clone()).expect("incoming auth");
            let verified = anp::group_e2ee::verify_group_incoming_origin_proof_v2(&meta, &body, &auth, anp::proof::Rfc9421OriginProofVerificationOptions { did_document: Some(sender_doc.clone()), verification_method: None, expected_signer_did: Some(meta.sender_did.clone()) });
            ok("the SDK verifies the sender's origin proof on the delivered message", verified.is_ok(), verified.as_ref().err().map(|e| format!("{e:?}")).unwrap_or_default());
            let original = anp::group_e2ee::reconstruct_group_send_request_v2(&meta, &body, &auth).expect("the original submission");
            let out = decrypt_v2(&st, V2DecryptInput { recipient_did: did, recipient_device_id: device, originating_meta: serde_json::from_value(original["meta"].clone()).expect("send meta"), group_cipher_object: body.group_cipher_object.clone(), sender_did_document: sender_doc, now: NOW.to_owned(), draft_extension_negotiated: true, request_id: "req-in".to_owned() });
            match out {
                Ok(o) => {
                    let v = serde_json::to_value(&o.application_plaintext).unwrap();
                    println!("PASS  the SDK decrypts the delivered message: {:?}", v["text"]);
                    println!("TEXT {}", v["text"].as_str().unwrap_or(""));
                }
                Err(e) => ok("the SDK decrypts the delivered message", false, format!("{e:?}")),
            }
        }        o => {
            println!("unknown command {o}");
            std::process::exit(2);
        }
    }
}