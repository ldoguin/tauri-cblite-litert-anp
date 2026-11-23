//! The official ANP Rust SDK (`anp` 1.0.7), used the way another agent stack would use it, against messages made by this
//! project.
//!
//!   anp-rust-interop open <fixture.json>              open the message this project sealed (needs the fixture's keys)
//!   anp-rust-interop seal <fixture.json> <out.json>   seal a message to this project's prekey bundle
//!   anp-rust-interop chat-init|chat-accept|chat-recv ...   one leg of a conversation (see p5_chat in anp-e2ee's examples)
//!   anp-rust-interop live <fixture> <node_url> <listen_port> <node_name> [state_out]   chat with a running node, then try to break it
//!   anp-rust-interop live-resume <fixture> <node_url> <listen_port> <state_file>       carry the session on after the node restarted
//!
//! The fixture is written by `cargo test -p anp-e2ee dump_interop_fixture` (see `scripts/interop`).

use anp::direct_e2ee::{
    verify_prekey_bundle_v2, V2ApplicationPlaintext, V2DirectCipherBody, V2DirectE2eeSession, V2DirectInitBody, V2DirectMetadata,
    V2OneTimePrekey, V2PrekeyBundle, V2SessionBinding, MTI_DIRECT_E2EE_SUITE_V2,
    direct_send_request_v2, get_prekey_bundle_request_v2, parse_direct_send_request_v2, parse_direct_send_result_v2, parse_get_prekey_bundle_request_v2,
    parse_get_prekey_bundle_result_v2, parse_publish_prekey_bundle_request_v2, parse_publish_prekey_bundle_result_v2, publish_prekey_bundle_request_v2, V2DirectBody,
    V2GetPrekeyBundleBody, V2KeyServiceMetadata, V2PublishPrekeyBundleBody,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use serde_json::{json, Value};
use x25519_dalek::StaticSecret;

fn read(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture")).expect("fixture is JSON")
}
fn key(fx: &Value, name: &str) -> [u8; 32] {
    B64U.decode(fx["keys"][name].as_str().unwrap_or_else(|| panic!("no key {name}"))).unwrap().try_into().expect("32 bytes")
}
fn s(v: &Value) -> String {
    v.as_str().expect("string").to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fx = read(&args[2]);
    let (alice_did, alice_dev) = (s(&fx["sender"]["did"]), s(&fx["sender"]["device_id"]));
    let (bob_did, bob_dev) = (s(&fx["recipient"]["did_document"]["id"]), s(&fx["recipient"]["device_id"]));
    let (alice_ka_id, bob_ka_id) = (s(&fx["keys"]["alice_ka_id"]), s(&fx["keys"]["bob_ka_id"]));
    let bundle: V2PrekeyBundle = serde_json::from_value(fx["recipient"]["bundle"].clone()).expect("a bundle the SDK can parse");
    let mut ok = true;
    let mut check = |name: &str, cond: bool, detail: String| {
        ok &= cond;
        println!("{}{}{}", if cond { "PASS  " } else { "FAIL  " }, name, if cond { String::new() } else { format!("  {detail}") });
    };

    // the SDK's own check of the bundle, against the DID document it was published with
    let now = chrono_now(&fx["now"]);
    let verified = verify_prekey_bundle_v2(&bundle, &fx["recipient"]["did_document"], now);
    check("the SDK's Rust verify_prekey_bundle_v2 accepts this project's bundle", verified.is_ok(), format!("{verified:?}"));

    match args[1].as_str() {
        "open" => {
            // bob's side: the SDK is the recipient of a message this project sealed
            let binding = V2SessionBinding {
                local_did: bob_did.clone(),
                local_device_id: bob_dev.clone(),
                peer_did: alice_did.clone(),
                peer_device_id: alice_dev.clone(),
                suite: MTI_DIRECT_E2EE_SUITE_V2.to_string(),
                local_e2ee_key_id: bob_ka_id.clone(),
                peer_e2ee_key_id: alice_ka_id.clone(),
            };
            let metadata: V2DirectMetadata = serde_json::from_value(fx["metadata"].clone()).expect("metadata");
            let body: V2DirectInitBody = serde_json::from_value(fx["init_body"].clone()).expect("an init body the SDK can parse");
            let r = V2DirectE2eeSession::accept_incoming_init(
                &binding,
                &metadata,
                &StaticSecret::from(key(&fx, "bob_ka_secret")),
                &bundle,
                &StaticSecret::from(key(&fx, "bob_spk_secret")),
                None,
                &key(&fx, "alice_ka_public"),
                &body,
            );
            match r {
                Ok((state, plaintext, _opk)) => {
                    let got = serde_json::to_value(&plaintext).unwrap();
                    check("the SDK opens the message this project sealed", true, String::new());
                    check("...and reads exactly the payload we sealed (floats included)", got["payload"] == fx["application_plaintext"]["payload"], format!("{got}"));
                    check("...and the logical message id and content type", got["logical_message_id"] == fx["application_plaintext"]["logical_message_id"] && got["application_content_type"] == fx["application_plaintext"]["application_content_type"], format!("{got}"));
                    check("...and ends in an established session", format!("{state:?}").contains("established"), format!("{state:?}").chars().take(200).collect());
                }
                Err(e) => check("the SDK opens the message this project sealed", false, format!("{e:?}")),
            }
            // tampering must make the SDK refuse it too
            let mut bad = fx["init_body"].clone();
            let ct = s(&bad["ciphertext_b64u"]);
            bad["ciphertext_b64u"] = json!(format!("{}{}", &ct[..ct.len() - 2], if ct.ends_with("AA") { "BB" } else { "AA" }));
            let bad: V2DirectInitBody = serde_json::from_value(bad).unwrap();
            let r = V2DirectE2eeSession::accept_incoming_init(&binding, &metadata, &StaticSecret::from(key(&fx, "bob_ka_secret")), &bundle, &StaticSecret::from(key(&fx, "bob_spk_secret")), None, &key(&fx, "alice_ka_public"), &bad);
            check("the SDK refuses the same message with a flipped ciphertext byte", r.is_err(), String::new());
        }
        "seal" => {
            // alice's side: the SDK is the sender, sealing to this project's bundle
            let binding = V2SessionBinding {
                local_did: alice_did.clone(),
                local_device_id: alice_dev.clone(),
                peer_did: bob_did.clone(),
                peer_device_id: bob_dev.clone(),
                suite: MTI_DIRECT_E2EE_SUITE_V2.to_string(),
                local_e2ee_key_id: alice_ka_id.clone(),
                peer_e2ee_key_id: bob_ka_id.clone(),
            };
            let message_id = "tasks/sdk-1#task";
            let metadata: V2DirectMetadata = serde_json::from_value(json!({
                "profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
                "sender_did": alice_did, "sender_device_id": alice_dev,
                "target": { "kind": "agent", "did": bob_did }, "recipient_device_id": bob_dev,
                "operation_id": message_id, "message_id": message_id,
                "content_type": "application/anp-direct-init+json",
            }))
            .unwrap();
            let plaintext_json = json!({
                "application_content_type": "application/json", "logical_message_id": "logical-sdk-1",
                "payload": { "hello": "from the official Rust SDK", "n": [1.5, 1e30, 0.000001] },
            });
            let plaintext: V2ApplicationPlaintext = serde_json::from_value(plaintext_json.clone()).unwrap();
            let r = V2DirectE2eeSession::initiate_session(
                &binding,
                &metadata,
                &StaticSecret::from(key(&fx, "alice_ka_secret")),
                &bundle,
                &key(&fx, "bob_ka_public"),
                None,
                &plaintext,
            );
            match r {
                Ok((_state, _pending, body)) => {
                    check("the SDK seals a message to this project's bundle", true, String::new());
                    let out = json!({ "metadata": serde_json::to_value(&metadata).unwrap(), "init_body": serde_json::to_value(&body).unwrap(), "plaintext": plaintext_json });
                    std::fs::write(&args[3], out.to_string()).expect("write output");
                }
                Err(e) => check("the SDK seals a message to this project's bundle", false, format!("{e:?}")),
            }
        }
        "wire" => {
            // args: wire <fixture> <mine_wire.json> <t_init> <t_cipher> <out>
            let mine = read(&args[3]);
            let (t_init, t_cipher) = (read(&args[4]), read(&args[5]));
            let ck = |name: &str, r: Result<(), String>, check: &mut dyn FnMut(&str, bool, String)| check(name, r.is_ok(), r.err().unwrap_or_default());
            ck("the SDK parses this project's direct.send init request", parse_direct_send_request_v2(&mine["direct_init"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's direct.send follow-up request", parse_direct_send_request_v2(&mine["direct_cipher"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's publish_prekey_bundle request", parse_publish_prekey_bundle_request_v2(&mine["publish"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's get_prekey_bundle request", parse_get_prekey_bundle_request_v2(&mine["get"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's direct.send result", parse_direct_send_result_v2(&mine["direct_send_result"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's publish result", parse_publish_prekey_bundle_result_v2(&mine["publish_result"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            ck("the SDK parses this project's get result", parse_get_prekey_bundle_result_v2(&mine["get_result"]).map(|_| ()).map_err(|e| e.to_string()), &mut check);
            // and build the same kinds of objects with the SDK, for this project to parse
            let (im, cm) = (&t_init["messages"][0], &t_cipher["messages"][0]);
            let build = |f: &dyn Fn() -> Result<Value, anp::direct_e2ee::DirectE2eeV2Error>| f().expect("the SDK builds it");
            let init_meta: V2DirectMetadata = serde_json::from_value(im["metadata"].clone()).unwrap();
            let init_body: V2DirectInitBody = serde_json::from_value(im["body"].clone()).unwrap();
            let cipher_meta: V2DirectMetadata = serde_json::from_value(cm["metadata"].clone()).unwrap();
            let cipher_body: V2DirectCipherBody = serde_json::from_value(cm["body"].clone()).unwrap();
            let svc = |sender: &str, dev: &str, op: &str| -> V2KeyServiceMetadata { serde_json::from_value(json!({
                "profile": "anp.direct.e2ee.v2", "security_profile": "transport-protected", "sender_did": sender, "sender_device_id": dev,
                "target": { "kind": "service", "did": "did:wba:b.example.com:services:message" }, "operation_id": op })).unwrap() };
            let opk = json!({ "key_id": "opk-interop-1", "public_key_b64u": "UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0" });
            let publish_body: V2PublishPrekeyBundleBody = serde_json::from_value(json!({ "prekey_bundle": fx["recipient"]["bundle"], "one_time_prekeys": [opk] })).unwrap();
            let get_body: V2GetPrekeyBundleBody = serde_json::from_value(json!({ "target_did": bob_did, "target_device_id": bob_dev, "preferred_suite": MTI_DIRECT_E2EE_SUITE_V2, "require_opk": true })).unwrap();
            let out = json!({
                "direct_init": build(&|| direct_send_request_v2(init_meta.clone(), V2DirectBody::Init(init_body.clone()))),
                "direct_cipher": build(&|| direct_send_request_v2(cipher_meta.clone(), V2DirectBody::Cipher(cipher_body.clone()))),
                "publish": build(&|| publish_prekey_bundle_request_v2(svc(&bob_did, &bob_dev, "op-publish-1"), publish_body.clone())),
                "get": build(&|| get_prekey_bundle_request_v2(svc(&alice_did, &alice_dev, "op-get-1"), get_body.clone())),
                "direct_send_result": serde_json::to_value(parse_direct_send_result_v2(&mine["direct_send_result"]).unwrap()).unwrap(),
                "publish_result": serde_json::to_value(parse_publish_prekey_bundle_result_v2(&mine["publish_result"]).unwrap()).unwrap(),
                "get_result": serde_json::to_value(parse_get_prekey_bundle_result_v2(&mine["get_result"]).unwrap()).unwrap(),
            });
            std::fs::write(&args[6], out.to_string()).unwrap();
        }
        "live" => {
            // args: live <fixture> <node_base_url> <listen_port> <node_name>: the SDK's side of a chat with a running node
            let base = args[3].trim_end_matches('/').to_string();
            let port: u16 = args[4].parse().expect("listen port");
            let node_name = args[5].clone();
            let get = |url: &str| -> Value { serde_json::from_str(&ureq::get(url).call().expect("GET").into_string().unwrap()).unwrap() };
            let post = |body: &Value| -> Value {
                match ureq::post(&format!("{base}/anp/p5")).set("content-type", "application/json").send_string(&body.to_string()) {
                    Ok(r) => serde_json::from_str(&r.into_string().unwrap()).unwrap(),
                    Err(ureq::Error::Status(_, r)) => serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null),
                    Err(e) => panic!("POST: {e}"),
                }
            };
            let rpc = |id: &str, req: &Value| json!({ "jsonrpc": "2.0", "id": id, "method": req["method"], "params": req["params"] });

            // where replies arrive
            let (tx, rx) = std::sync::mpsc::channel::<Value>();
            let server = tiny_http::Server::http(("0.0.0.0", port)).expect("listen");
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let mut text = String::new();
                    let _ = request.as_reader().read_to_string(&mut text);
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let signed = request.headers().iter().any(|h| h.field.as_str().as_str().eq_ignore_ascii_case("signature-input"));
                    let mid = v["params"]["meta"]["message_id"].as_str().unwrap_or("").to_string();
                    let reply = json!({ "jsonrpc": "2.0", "id": v["id"], "result": { "accepted": true, "message_id": mid, "operation_id": mid,
                        "target_did": v["params"]["meta"]["target"]["did"], "recipient_device_id": v["params"]["meta"]["recipient_device_id"], "accepted_at": "2026-11-13T12:00:00Z" } });
                    let _ = request.respond(tiny_http::Response::from_string(reply.to_string()).with_header(tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..]).unwrap()));
                    let mut v = v;
                    v["_signed"] = json!(signed);
                    let _ = tx.send(v);
                }
            });

            // the node's identity, from its own endpoints
            let sec = get(&format!("{base}/security"));
            let node_did = s(&sec["did"]);
            let node_dev = format!("dev-{node_name}");
            let e1 = node_did.rsplit(':').next().unwrap().to_string();
            let node_doc = get(&format!("{base}/agents/{node_name}/{e1}/did.json"));
            let svc = node_doc["service"].as_array().into_iter().flatten().find(|x| x["type"] == "ANPMessageService").cloned();
            check("the node's DID document advertises an ANPMessageService", svc.is_some(), format!("{node_doc}"));
            let ka_ref = s(&node_doc["keyAgreement"][0]);
            let ka_vm = node_doc["verificationMethod"].as_array().unwrap().iter().find(|v| v["id"] == ka_ref.as_str()).expect("key agreement method").clone();
            let node_ka_pub: [u8; 32] = bs58::decode(s(&ka_vm["publicKeyMultibase"]).trim_start_matches('z')).into_vec().unwrap().try_into().unwrap();

            // the key service: ask for the bundle, and a one-time prekey
            let svc_meta = |op: &str| -> V2KeyServiceMetadata { serde_json::from_value(json!({
                "profile": "anp.direct.e2ee.v2", "security_profile": "transport-protected", "sender_did": alice_did, "sender_device_id": alice_dev,
                "target": { "kind": "service", "did": "did:wba:live.example.com:services:message" }, "operation_id": op })).unwrap() };
            let get_body = |dev: &str| -> V2GetPrekeyBundleBody { serde_json::from_value(json!({ "target_did": node_did, "target_device_id": dev, "preferred_suite": MTI_DIRECT_E2EE_SUITE_V2, "require_opk": true })).unwrap() };
            let resp = post(&rpc("g1", &get_prekey_bundle_request_v2(svc_meta("op-get-1"), get_body(&node_dev)).unwrap()));
            let got = parse_get_prekey_bundle_result_v2(&resp["result"]);
            check("the node answers get_prekey_bundle with a result the SDK parses", got.is_ok(), format!("{resp}"));
            let got = serde_json::to_value(got.expect("a bundle")).unwrap();
            let node_bundle: V2PrekeyBundle = serde_json::from_value(got["prekey_bundle"].clone()).unwrap();
            let node_opk: V2OneTimePrekey = serde_json::from_value(got["one_time_prekey"].clone()).expect("an issued one-time prekey");
            let vb = verify_prekey_bundle_v2(&node_bundle, &node_doc, chrono_now(&json!(chrono::Utc::now().to_rfc3339())));
            check("the SDK verifies the node's bundle against the node's DID document", vb.is_ok(), format!("{vb:?}"));
            let wrong = post(&rpc("g2", &get_prekey_bundle_request_v2(svc_meta("op-get-2"), get_body("dev-someone-else")).unwrap()));
            check("a bundle for another device is refused (4000)", wrong["error"]["code"] == 4000, format!("{wrong}"));

            // chat: init, then follow-ups
            let a_binding = binding(&alice_did, &alice_dev, &alice_ka_id, &node_did, &node_dev, &node_bundle.static_key_agreement_id);
            let secret = StaticSecret::from(key(&fx, "alice_ka_secret"));
            let md = |mid: &str, ct: &str| -> V2DirectMetadata { serde_json::from_value(meta(&a_binding, mid, ct)).unwrap() };
            let pt = |t: &str| -> V2ApplicationPlaintext { serde_json::from_value(plain_text(t)).unwrap() };
            let init_md = md("live-init", "application/anp-direct-init+json");
            let (mut state, _pending, init_body) = V2DirectE2eeSession::initiate_session(&a_binding, &init_md, &secret, &node_bundle, &node_ka_pub, Some(&node_opk), &pt("hello node")).expect("the SDK initiates");
            let init_req = rpc("m1", &direct_send_request_v2(init_md.clone(), V2DirectBody::Init(init_body)).unwrap());
            let r = post(&init_req);
            check("the node accepts the SDK's init (direct.send result)", parse_direct_send_result_v2(&r["result"]).is_ok(), format!("{r}"));

            let mut recv = |label: &str, want: &str, state: &mut anp::direct_e2ee::V2DirectSessionState, check: &mut dyn FnMut(&str, bool, String)| {
                match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                    Ok(v) => match parse_direct_send_request_v2(&json!({ "method": v["method"], "params": v["params"] })) {
                        Ok((meta, V2DirectBody::Cipher(body))) => {
                            check(&format!("{label}: the node's reply was signed with ANP-02"), v["_signed"] == true, String::new());
                            match V2DirectE2eeSession::decrypt_follow_up(state, &a_binding, &meta, &body) {
                                Ok(p) => {
                                    let got = serde_json::to_value(&p).unwrap()["text"].as_str().unwrap_or("").to_string();
                                    check(&format!("{label}: the SDK decrypts the node's reply, and it is the agent's answer ({got:?})"), got == want, format!("wanted {want:?}"));
                                    check(&format!("{label}: the reply's ratchet header n={} pn={}", body.ratchet_header.n, body.ratchet_header.pn), true, String::new());
                                }
                                Err(e) => check(&format!("{label}: the SDK decrypts the node's reply"), false, format!("{e:?}")),
                            }
                        }
                        other => check(&format!("{label}: the node sends a follow-up"), false, format!("{other:?}")),
                    },
                    Err(_) => check(&format!("{label}: a reply arrives from the node"), false, "no reply within 30 s".into()),
                }
            };
            recv("reply 1", "hello node", &mut state, &mut check);
            let md2 = md("live-2", "application/anp-direct-cipher+json");
            let (_p2, body2) = V2DirectE2eeSession::encrypt_follow_up(&mut state, &a_binding, &md2, &pt("second message")).expect("a follow-up");
            let req2 = rpc("m2", &direct_send_request_v2(md2.clone(), V2DirectBody::Cipher(body2)).unwrap());
            let r = post(&req2);
            check("the node accepts the SDK's follow-up", parse_direct_send_result_v2(&r["result"]).is_ok(), format!("{r}"));
            recv("reply 2", "second message", &mut state, &mut check);
            let md3 = md("live-3", "application/anp-direct-cipher+json");
            let (_p3, body3) = V2DirectE2eeSession::encrypt_follow_up(&mut state, &a_binding, &md3, &pt("third")).expect("a follow-up");
            let r = post(&rpc("m3", &direct_send_request_v2(md3, V2DirectBody::Cipher(body3)).unwrap()));
            check("a third message in the same chain is accepted", parse_direct_send_result_v2(&r["result"]).is_ok(), format!("{r}"));
            recv("reply 3", "third", &mut state, &mut check);

            // what the node must refuse
            let r = post(&init_req);
            check("replaying the init is refused (4008)", r["error"]["code"] == 4008, format!("{r}"));
            let r = post(&req2);
            check("replaying a follow-up is refused (4008)", r["error"]["code"] == 4008 || r["error"]["code"] == 4009, format!("{r}"));
            let mut stranger = init_req.clone();
            stranger["params"]["meta"]["sender_did"] = json!("did:wba:stranger.example.com:agents:eve:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            let r = post(&stranger);
            check("a message from a DID the node does not know is refused (4012)", r["error"]["code"] == 4012, format!("{r}"));
            let mut elsewhere = init_req.clone();
            elsewhere["params"]["meta"]["recipient_device_id"] = json!("dev-other");
            let r = post(&elsewhere);
            check("a message addressed to another device is refused (4012)", r["error"]["code"] == 4012, format!("{r}"));
            let mut nosession = req2.clone();
            nosession["params"]["body"]["session_id"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
            let r = post(&nosession);
            check("a follow-up for a session that does not exist is refused (4005)", r["error"]["code"] == 4005, format!("{r}"));
            let r = post(&json!({ "jsonrpc": "2.0", "id": 9, "method": "direct.nothing", "params": {} }));
            check("an unknown method is a standard JSON-RPC error", r["error"]["code"] == -32601, format!("{r}"));
            if let Some(path) = args.get(6) {
                std::fs::write(path, serde_json::to_string(&state).unwrap()).unwrap();
            }
        }
        "live-resume" => {
            // args: live-resume <fixture> <node_url> <listen_port> <state_file>: carry on a session after the node restarted
            let base = args[3].trim_end_matches('/').to_string();
            let port: u16 = args[4].parse().unwrap();
            let mut state: anp::direct_e2ee::V2DirectSessionState = serde_json::from_str(&std::fs::read_to_string(&args[5]).unwrap()).unwrap();
            let local = state.binding.clone();
            let (tx, rx) = std::sync::mpsc::channel::<Value>();
            let server = tiny_http::Server::http(("0.0.0.0", port)).expect("listen");
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let mut text = String::new();
                    let _ = request.as_reader().read_to_string(&mut text);
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let mid = v["params"]["meta"]["message_id"].as_str().unwrap_or("").to_string();
                    let reply = json!({ "jsonrpc": "2.0", "id": v["id"], "result": { "accepted": true, "message_id": mid, "operation_id": mid,
                        "target_did": v["params"]["meta"]["target"]["did"], "recipient_device_id": v["params"]["meta"]["recipient_device_id"], "accepted_at": "2026-11-13T12:00:00Z" } });
                    let _ = request.respond(tiny_http::Response::from_string(reply.to_string()));
                    let _ = tx.send(v);
                }
            });
            let md: V2DirectMetadata = serde_json::from_value(meta(&local, "live-after-restart", "application/anp-direct-cipher+json")).unwrap();
            let pt: V2ApplicationPlaintext = serde_json::from_value(plain_text("after the restart")).unwrap();
            let (_p, body) = V2DirectE2eeSession::encrypt_follow_up(&mut state, &local, &md, &pt).expect("a follow-up");
            let req = direct_send_request_v2(md, V2DirectBody::Cipher(body)).unwrap();
            let rpc = json!({ "jsonrpc": "2.0", "id": "r1", "method": req["method"], "params": req["params"] });
            let resp = match ureq::post(&format!("{base}/anp/p5")).send_string(&rpc.to_string()) {
                Ok(r) => serde_json::from_str::<Value>(&r.into_string().unwrap()).unwrap(),
                Err(e) => panic!("POST: {e}"),
            };
            check("the restarted node accepts a follow-up for the session it had before", parse_direct_send_result_v2(&resp["result"]).is_ok(), format!("{resp}"));
            match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                Ok(v) => match parse_direct_send_request_v2(&json!({ "method": v["method"], "params": v["params"] })) {
                    Ok((meta, V2DirectBody::Cipher(body))) => match V2DirectE2eeSession::decrypt_follow_up(&mut state, &local, &meta, &body) {
                        Ok(p) => check("...and its reply decrypts with the SDK's session", serde_json::to_value(&p).unwrap()["text"] == "after the restart", format!("{p:?}")),
                        Err(e) => check("...and its reply decrypts with the SDK's session", false, format!("{e:?}")),
                    },
                    other => check("...and sends a follow-up", false, format!("{other:?}")),
                },
                Err(_) => check("...and answers", false, "no reply within 30 s".into()),
            }
        }
        "chat-init" | "chat-accept" | "chat-recv" => {
            let (adid, bdid) = (alice_did.clone(), bob_did.clone());
            let a_binding = binding(&adid, &alice_dev, &alice_ka_id, &bdid, &bob_dev, &bob_ka_id);
            let b_binding = binding(&bdid, &bob_dev, &bob_ka_id, &adid, &alice_dev, &alice_ka_id);
            let leg = &args[3];
            let mut out: Vec<Value> = Vec::new();
            let (state_path, t_path, texts, mut state): (String, String, Vec<String>, anp::direct_e2ee::V2DirectSessionState);
            match args[1].as_str() {
                "chat-init" => {
                    (state_path, t_path, texts) = (args[4].clone(), args[5].clone(), vec![]);
                    let mid = format!("chat-{leg}-0");
                    let md: V2DirectMetadata = serde_json::from_value(meta(&a_binding, &mid, "application/anp-direct-init+json")).unwrap();
                    let pt: V2ApplicationPlaintext = serde_json::from_value(plain_text(&args[6])).unwrap();
                    let (st, _pending, body) = V2DirectE2eeSession::initiate_session(&a_binding, &md, &StaticSecret::from(key(&fx, "alice_ka_secret")), &bundle, &key(&fx, "bob_ka_public"), opk().as_ref().map(|(o, _)| o), &pt).expect("the SDK initiates");
                    check("the SDK initiates a session", true, String::new());
                    out.push(json!({ "kind": "init", "metadata": serde_json::to_value(&md).unwrap(), "body": serde_json::to_value(&body).unwrap(), "text": args[6] }));
                    state = st;
                }
                "chat-accept" => {
                    (state_path, t_path, texts) = (args[5].clone(), args[6].clone(), args[7..].to_vec());
                    let t = read(&args[4]);
                    let m = &t["messages"][0];
                    let md: V2DirectMetadata = serde_json::from_value(m["metadata"].clone()).unwrap();
                    let body: V2DirectInitBody = serde_json::from_value(m["body"].clone()).expect("an init body the SDK can parse");
                    match V2DirectE2eeSession::accept_incoming_init(&b_binding, &md, &StaticSecret::from(key(&fx, "bob_ka_secret")), &bundle, &StaticSecret::from(key(&fx, "bob_spk_secret")), opk().as_ref().map(|(o, s)| (o, s)), &key(&fx, "alice_ka_public"), &body) {
                        Ok((st, pt, _)) => {
                            check("the SDK accepts the init", true, String::new());
                            check("...and reads the text the sender put in", serde_json::to_value(&pt).unwrap()["text"] == m["text"], format!("{pt:?}"));
                            state = st;
                        }
                        Err(e) => {
                            check("the SDK accepts the init", false, format!("{e:?}"));
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    (state_path, t_path, texts) = (args[7].clone(), args[8].clone(), args[9..].to_vec());
                    state = serde_json::from_str(&std::fs::read_to_string(&args[4]).unwrap()).expect("a saved SDK session");
                    let local = state.binding.clone();
                    let t = read(&args[5]);
                    let msgs = t["messages"].as_array().unwrap();
                    for i in args[6].split(',').filter(|x| !x.is_empty()).map(|x| x.parse::<usize>().unwrap()) {
                        let m = &msgs[i];
                        let md: V2DirectMetadata = serde_json::from_value(m["metadata"].clone()).unwrap();
                        let body: V2DirectCipherBody = serde_json::from_value(m["body"].clone()).expect("a cipher body the SDK can parse");
                        match V2DirectE2eeSession::decrypt_follow_up(&mut state, &local, &md, &body) {
                            Ok(pt) => check(&format!("the SDK decrypts message {i} (n={})", m["body"]["ratchet_header"]["n"]), serde_json::to_value(&pt).unwrap()["text"] == m["text"], format!("{pt:?}")),
                            Err(e) => check(&format!("the SDK decrypts message {i}"), false, format!("{e:?}")),
                        }
                    }
                }
            }
            for (i, txt) in texts.iter().enumerate() {
                let mid = format!("chat-{leg}-{}", i + 1);
                let local = state.binding.clone();
                let md: V2DirectMetadata = serde_json::from_value(meta(&local, &mid, "application/anp-direct-cipher+json")).unwrap();
                let pt: V2ApplicationPlaintext = serde_json::from_value(plain_text(txt)).unwrap();
                match V2DirectE2eeSession::encrypt_follow_up(&mut state, &local, &md, &pt) {
                    Ok((_pending, body)) => out.push(json!({ "kind": "cipher", "metadata": serde_json::to_value(&md).unwrap(), "body": serde_json::to_value(&body).unwrap(), "text": txt })),
                    Err(e) => check(&format!("the SDK encrypts follow-up {i}"), false, format!("{e:?}")),
                }
            }
            std::fs::write(&state_path, serde_json::to_string(&state).unwrap()).unwrap();
            std::fs::write(&t_path, json!({ "messages": out }).to_string()).unwrap();
        }
        other => panic!("unknown mode {other}"),
    }
    std::process::exit(if ok { 0 } else { 1 });
}

/// `2026-11-13T12:00:00Z` as the SDK's clock type.
fn chrono_now(v: &Value) -> chrono::DateTime<chrono::Utc> {
    s(v).parse().expect("RFC 3339 timestamp")
}

/// `P5_OPK=1`: the conversation starts with a one-time prekey (a fixed test key, the same as in the project's `p5_chat`).
fn opk() -> Option<(V2OneTimePrekey, StaticSecret)> {
    std::env::var("P5_OPK").ok()?;
    let secret = StaticSecret::from([88u8; 32]);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    Some((V2OneTimePrekey { key_id: "opk-interop-1".into(), public_key_b64u: B64U.encode(public) }, secret))
}

fn binding(local_did: &str, local_dev: &str, local_ka: &str, peer_did: &str, peer_dev: &str, peer_ka: &str) -> V2SessionBinding {
    V2SessionBinding {
        local_did: local_did.into(),
        local_device_id: local_dev.into(),
        peer_did: peer_did.into(),
        peer_device_id: peer_dev.into(),
        suite: MTI_DIRECT_E2EE_SUITE_V2.to_string(),
        local_e2ee_key_id: local_ka.into(),
        peer_e2ee_key_id: peer_ka.into(),
    }
}

fn meta(b: &V2SessionBinding, message_id: &str, content_type: &str) -> Value {
    json!({
        "profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
        "sender_did": b.local_did, "sender_device_id": b.local_device_id,
        "target": { "kind": "agent", "did": b.peer_did }, "recipient_device_id": b.peer_device_id,
        "operation_id": message_id, "message_id": message_id, "content_type": content_type,
    })
}

fn plain_text(t: &str) -> Value {
    json!({ "application_content_type": "text/plain", "text": t })
}