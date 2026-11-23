//! Wire objects made here, and wire objects made by another implementation, for checking each other. See `scripts/interop`.
//!
//!   direct_wire build <fixture> <t_init> <t_cipher> <out>   build every request and result from a conversation's first messages
//!   direct_wire check <other.json>                          parse what another implementation built (same member names)

use anp_e2ee::wire::*;
use serde_json::{json, Value};

fn read(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "build" => {
            let fx = read(&a[2]);
            let (t_init, t_cipher) = (read(&a[3]), read(&a[4]));
            let (im, cm) = (&t_init["messages"][0], &t_cipher["messages"][0]);
            let bob_did = fx["recipient"]["did_document"]["id"].as_str().unwrap();
            let bob_dev = fx["recipient"]["device_id"].as_str().unwrap();
            let svc = |sender: &str, dev: &str, op: &str| json!({
                "profile": "anp.direct.e2ee.v2", "security_profile": "transport-protected", "sender_did": sender, "sender_device_id": dev,
                "target": { "kind": "service", "did": "did:wba:b.example.com:services:message" }, "operation_id": op,
            });
            let bundle = &fx["recipient"]["bundle"];
            let opk = json!({ "key_id": "opk-interop-1", "public_key_b64u": "UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0" });
            let out = json!({
                "direct_init": direct_send_request(&im["metadata"], &im["body"]).expect("an init request"),
                "direct_cipher": direct_send_request(&cm["metadata"], &cm["body"]).expect("a follow-up request"),
                "publish": publish_prekey_bundle_request(&svc(bob_did, bob_dev, "op-publish-1"), bundle, &[opk.clone()]).expect("publish"),
                "get": get_prekey_bundle_request(&svc(im["metadata"]["sender_did"].as_str().unwrap(), im["metadata"]["sender_device_id"].as_str().unwrap(), "op-get-1"), bob_did, bob_dev, Some("ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1"), Some(true)).expect("get"),
                "direct_send_result": direct_send_result(im["metadata"]["message_id"].as_str().unwrap(), bob_did, bob_dev, "2026-11-13T12:00:01Z"),
                "publish_result": publish_prekey_bundle_result(bob_did, bob_dev, bundle["bundle_id"].as_str().unwrap(), "2026-11-13T12:00:02Z", 1),
                "get_result": get_prekey_bundle_result(bob_did, bob_dev, bundle, Some(&opk)),
            });
            std::fs::write(&a[5], out.to_string()).unwrap();
        }
        "check" => {
            let o = read(&a[2]);
            let mut ok = true;
            let mut check = |name: &str, r: Result<(), anp_e2ee::E2eeError>| {
                ok &= r.is_ok();
                println!("{}{}{}", if r.is_ok() { "PASS  " } else { "FAIL  " }, name, r.err().map(|e| format!("  {e}")).unwrap_or_default());
            };
            check("we parse the SDK's direct.send init request", parse_direct_send_request(&o["direct_init"]).and_then(|(_, _, init)| if init { Ok(()) } else { Err(anp_e2ee::E2eeError("not an init".into())) }));
            check("we parse the SDK's direct.send follow-up request", parse_direct_send_request(&o["direct_cipher"]).and_then(|(_, _, init)| if !init { Ok(()) } else { Err(anp_e2ee::E2eeError("not a follow-up".into())) }));
            check("we parse the SDK's publish_prekey_bundle request", parse_publish_prekey_bundle_request(&o["publish"]).map(|_| ()));
            check("we parse the SDK's get_prekey_bundle request", parse_get_prekey_bundle_request(&o["get"]).map(|_| ()));
            check("we parse the SDK's direct.send result", parse_direct_send_result(&o["direct_send_result"]));
            check("we parse the SDK's publish result", parse_publish_prekey_bundle_result(&o["publish_result"]));
            check("we parse the SDK's get result", parse_get_prekey_bundle_result(&o["get_result"]));
            std::process::exit(if ok { 0 } else { 1 });
        }
        other => panic!("unknown command {other}"),
    }
}