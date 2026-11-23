//! One leg of a P5 conversation with another implementation, through files. See `scripts/interop`.
//!
//!   p5_chat init   <fixture> <leg> <state_out> <t_out> <text>             start as alice, sealing the text to bob
//!   p5_chat accept <fixture> <leg> <t_in> <state_out> <t_out> <text>...   be bob: accept the init in t_in, then send the texts
//!   p5_chat recv   <fixture> <leg> <state_in> <t_in> <order> <state_out> <t_out> <text>...
//!                                                                          decrypt t_in's messages in `order` (e.g. 2,0,1), then send
//!
//! A transcript is `{"messages": [{"kind": "init"|"cipher", "metadata": …, "body": …, "text": "…"}]}`; `text` is what the
//! sender put in, so the receiver can check what it decrypted. The program exits non-zero if a check fails.

use anp_e2ee::session::{Binding, LocalBundle, OneTimePrekey, Session};
use anp_e2ee::{parse_bundle, public_of};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Value};

fn read(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}
fn key(fx: &Value, k: &str) -> [u8; 32] {
    B64U.decode(fx["keys"][k].as_str().unwrap()).unwrap().try_into().unwrap()
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}
/// `P5_OPK=1` makes the conversation start with a one-time prekey (a fixed test key: id and secret).
const OPK_ID: &str = "opk-interop-1";
const OPK_SECRET: [u8; 32] = [88u8; 32];
fn use_opk() -> bool {
    std::env::var("P5_OPK").is_ok()
}

fn text(t: &str) -> Value {
    json!({ "application_content_type": "text/plain", "text": t })
}

struct Parties {
    alice: Binding,
    bob: Binding,
}
fn parties(fx: &Value) -> Parties {
    let (adid, adev) = (s(&fx["sender"]["did"]), s(&fx["sender"]["device_id"]));
    let (bdid, bdev) = (s(&fx["recipient"]["did_document"]["id"]), s(&fx["recipient"]["device_id"]));
    let (aka, bka) = (s(&fx["keys"]["alice_ka_id"]), s(&fx["keys"]["bob_ka_id"]));
    Parties {
        alice: Binding { local_did: adid.clone(), local_device_id: adev.clone(), local_ka_id: aka.clone(), peer_did: bdid.clone(), peer_device_id: bdev.clone(), peer_ka_id: bka.clone() },
        bob: Binding { local_did: bdid, local_device_id: bdev, local_ka_id: bka, peer_did: adid, peer_device_id: adev, peer_ka_id: aka },
    }
}

fn metadata(b: &Binding, message_id: &str, content_type: &str) -> Value {
    json!({
        "profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
        "sender_did": b.local_did, "sender_device_id": b.local_device_id,
        "target": { "kind": "agent", "did": b.peer_did }, "recipient_device_id": b.peer_device_id,
        "operation_id": message_id, "message_id": message_id, "content_type": content_type,
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let fx = read(&a[2]);
    let leg = &a[3];
    let p = parties(&fx);
    let mut ok = true;
    let mut check = |name: &str, cond: bool, detail: String| {
        ok &= cond;
        println!("{}{}{}", if cond { "PASS  " } else { "FAIL  " }, name, if cond { String::new() } else { format!("  {detail}") });
    };
    let mut out_messages: Vec<Value> = Vec::new();
    // where the state and the transcript go, and which texts to send as follow-ups
    let (state_path, t_path, texts): (String, String, Vec<String>);
    let mut session: Session;
    match a[1].as_str() {
        "init" => {
            (state_path, t_path, texts) = (a[4].clone(), a[5].clone(), vec![]);
            let did = anp_did::verify_document(&fx["recipient"]["did_document"], None).unwrap();
            let bundle = parse_bundle(&fx["recipient"]["bundle"], &did, &s(&fx["now"])).expect("a bundle we accept");
            let mid = format!("chat-{leg}-0");
            let opk = use_opk().then(|| OneTimePrekey { id: OPK_ID.into(), public: public_of(&OPK_SECRET) });
            let (sess, body) = Session::initiate(&p.alice, &mid, &key(&fx, "alice_ka_secret"), &bundle, opk.as_ref(), &text(&a[6])).expect("initiate");
            session = sess;
            out_messages.push(json!({ "kind": "init", "metadata": metadata(&p.alice, &mid, "application/anp-direct-init+json"), "body": body, "text": a[6] }));
        }
        "accept" => {
            (state_path, t_path, texts) = (a[5].clone(), a[6].clone(), a[7..].to_vec());
            let t = read(&a[4]);
            let m = &t["messages"][0];
            assert_eq!(m["kind"], "init");
            let mid = s(&m["metadata"]["message_id"]);
            let did = anp_did::verify_document(&fx["recipient"]["did_document"], None).unwrap();
            let bundle = parse_bundle(&fx["recipient"]["bundle"], &did, &s(&fx["now"])).unwrap();
            let spk = key(&fx, "bob_spk_secret");
            let local = LocalBundle { bundle_id: &bundle.bundle_id, signed_prekey_id: &bundle.spk_id, signed_prekey_secret: &spk, one_time_prekey: use_opk().then_some((OPK_ID, &OPK_SECRET)) };
            match Session::accept(&p.bob, &mid, &key(&fx, "bob_ka_secret"), &local, &key(&fx, "alice_ka_public"), &m["body"]) {
                Ok((sess, plain)) => {
                    check("we accept the init", true, String::new());
                    check("...and read the text the sender put in", plain["text"] == m["text"], format!("{plain}"));
                    session = sess;
                }
                Err(e) => {
                    check("we accept the init", false, e.to_string());
                    std::process::exit(1);
                }
            }
        }
        "recv" => {
            (state_path, t_path, texts) = (a[7].clone(), a[8].clone(), a[9..].to_vec());
            session = Session::from_json(&read(&a[4])).expect("a saved session");
            let t = read(&a[5]);
            let msgs = t["messages"].as_array().unwrap();
            for i in a[6].split(',').filter(|x| !x.is_empty()).map(|x| x.parse::<usize>().unwrap()) {
                let m = &msgs[i];
                let mid = s(&m["metadata"]["message_id"]);
                match session.decrypt(&mid, &m["body"]) {
                    Ok(plain) => check(&format!("we decrypt message {i} (n={})", m["body"]["ratchet_header"]["n"]), plain["text"] == m["text"], format!("{plain}")),
                    Err(e) => check(&format!("we decrypt message {i}"), false, e.to_string()),
                }
            }
        }
        other => panic!("unknown command {other}"),
    }
    for (i, t) in texts.iter().enumerate() {
        let mid = format!("chat-{leg}-{}", i + 1);
        match session.encrypt(&mid, &text(t)) {
            Ok(body) => out_messages.push(json!({ "kind": "cipher", "metadata": metadata(&session.binding, &mid, "application/anp-direct-cipher+json"), "body": body, "text": t })),
            Err(e) => check(&format!("we encrypt follow-up {i}"), false, e.to_string()),
        }
    }
    std::fs::write(&state_path, session.to_json().to_string()).unwrap();
    std::fs::write(&t_path, json!({ "messages": out_messages }).to_string()).unwrap();
    let _ = public_of; // (kept for the fixture helpers above)
    std::process::exit(if ok { 0 } else { 1 });
}