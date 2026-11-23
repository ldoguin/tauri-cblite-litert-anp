//! The P5 double ratchet: conversations, out-of-order delivery, replays, tampering, limits, one-time prekeys, persistence.

use anp_e2ee::session::{message_aad, payload_plaintext, Binding, LocalBundle, OneTimePrekey, Session, MAX_SKIP};
use anp_e2ee::{ka_secret_from_seed, new_prekey, public_of, Bundle, Ctx, Prekey};
use serde_json::{json, Value};

struct Peer {
    did: String,
    device: String,
    ka_id: String,
    ka: [u8; 32],
    spk: Prekey,
}
impl Peer {
    fn new(seed: u8, name: &str) -> Peer {
        Peer {
            did: format!("did:wba:{name}.example.com:agents:{name}:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            device: format!("dev-{name}"),
            ka_id: format!("did:wba:{name}.example.com:agents:{name}:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#key-agreement-1"),
            ka: ka_secret_from_seed(&[seed; 32]),
            spk: new_prekey(0),
        }
    }
    fn bundle(&self) -> Bundle {
        Bundle {
            bundle_id: format!("bundle-{}", self.spk.id),
            owner_did: self.did.clone(),
            device_id: self.device.clone(),
            ka_id: self.ka_id.clone(),
            ka_public: public_of(&self.ka),
            spk_id: self.spk.id.clone(),
            spk_public: self.spk.public,
            expires_at: "2099-01-01T00:00:00Z".into(),
        }
    }
    fn binding(&self, other: &Peer) -> Binding {
        Binding {
            local_did: self.did.clone(),
            local_device_id: self.device.clone(),
            local_ka_id: self.ka_id.clone(),
            peer_did: other.did.clone(),
            peer_device_id: other.device.clone(),
            peer_ka_id: other.ka_id.clone(),
        }
    }
    fn local<'a>(&'a self, bundle: &'a Bundle, opk: Option<(&'a str, &'a [u8; 32])>) -> LocalBundle<'a> {
        LocalBundle { bundle_id: &bundle.bundle_id, signed_prekey_id: &self.spk.id, signed_prekey_secret: &self.spk.secret, one_time_prekey: opk }
    }
}

fn text(t: &str) -> Value {
    json!({ "application_content_type": "text/plain", "text": t })
}

/// A started conversation: alice initiated, bob accepted. Returns both sessions.
fn started() -> (Peer, Peer, Session, Session) {
    let (a, b) = (Peer::new(1, "alice"), Peer::new(2, "bob"));
    let bundle = b.bundle();
    let (sa, init) = Session::initiate(&a.binding(&b), "m0", &a.ka, &bundle, None, &text("hello bob")).unwrap();
    let (sb, plain) = Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, None), &public_of(&a.ka), &init).unwrap();
    assert_eq!(plain["text"], "hello bob");
    (a, b, sa, sb)
}

#[test]
fn a_conversation_runs_in_both_directions_and_turns_the_ratchet() {
    let (_a, _b, mut sa, mut sb) = started();
    assert!(sb.is_established() && !sa.is_established());
    assert_eq!(sa.session_id(), sb.session_id());
    // bob replies twice; alice's first reply completes her session
    let r1 = sb.encrypt("m1", &text("hi alice")).unwrap();
    let r2 = sb.encrypt("m2", &text("how are you")).unwrap();
    assert_eq!(r1["ratchet_header"]["n"], "0");
    assert_eq!(r2["ratchet_header"]["n"], "1");
    assert_eq!(r1["ratchet_header"]["dh_pub_b64u"], r2["ratchet_header"]["dh_pub_b64u"], "one chain, one ratchet key");
    assert_eq!(sa.decrypt("m1", &r1).unwrap()["text"], "hi alice");
    assert!(sa.is_established());
    assert_eq!(sa.decrypt("m2", &r2).unwrap()["text"], "how are you");
    // alice answers: a new chain, with the previous chain's length in pn
    let a1 = sa.encrypt("m3", &text("fine")).unwrap();
    assert_eq!(a1["ratchet_header"]["n"], "0");
    assert_eq!(a1["ratchet_header"]["pn"], "1", "alice sent the init (1 message) on her previous chain");
    assert_eq!(sb.decrypt("m3", &a1).unwrap()["text"], "fine");
    // and bob again: another turn
    let r3 = sb.encrypt("m4", &text("good")).unwrap();
    assert_ne!(r3["ratchet_header"]["dh_pub_b64u"], r1["ratchet_header"]["dh_pub_b64u"], "the ratchet key changes on every turn");
    assert_eq!(r3["ratchet_header"]["pn"], "2");
    assert_eq!(sa.decrypt("m4", &r3).unwrap()["text"], "good");
    for i in 0..5 {
        let m = sa.encrypt(&format!("x{i}"), &text(&format!("a{i}"))).unwrap();
        assert_eq!(sb.decrypt(&format!("x{i}"), &m).unwrap()["text"], format!("a{i}"));
    }
}

#[test]
fn the_initiator_cannot_send_before_the_first_reply_and_the_reply_must_start_a_chain() {
    let (_a, _b, mut sa, mut sb) = started();
    assert!(sa.encrypt("early", &text("too soon")).unwrap_err().0.contains("pending"));
    let r1 = sb.encrypt("m1", &text("one")).unwrap();
    let r2 = sb.encrypt("m2", &text("two")).unwrap();
    // the second message cannot be the first thing alice sees
    assert!(sa.decrypt("m2", &r2).unwrap_err().0.contains("first reply"));
    assert!(!sa.is_established());
    // and the failure did not cost her the chance to read the right one
    assert_eq!(sa.decrypt("m1", &r1).unwrap()["text"], "one");
    assert_eq!(sa.decrypt("m2", &r2).unwrap()["text"], "two");
}

#[test]
fn messages_may_arrive_late_and_out_of_order_but_only_once() {
    let (_a, _b, mut sa, mut sb) = started();
    let msgs: Vec<Value> = (0..5).map(|i| sb.encrypt(&format!("m{i}"), &text(&format!("t{i}"))).unwrap()).collect();
    assert_eq!(sa.decrypt("m0", &msgs[0]).unwrap()["text"], "t0");
    for i in [4usize, 2, 1, 3] {
        assert_eq!(sa.decrypt(&format!("m{i}"), &msgs[i]).unwrap()["text"], format!("t{i}"), "message {i}");
    }
    assert_eq!(sa.skipped_count(), 0, "every kept key was used");
    // a replay of any of them fails
    for i in 0..5 {
        assert!(sa.decrypt(&format!("m{i}"), &msgs[i]).is_err(), "replay of {i}");
    }
    // late messages of an *earlier* chain after the ratchet has turned
    let (_a, _b, mut sa, mut sb) = started();
    let first: Vec<Value> = (0..3).map(|i| sb.encrypt(&format!("f{i}"), &text(&format!("f{i}"))).unwrap()).collect();
    assert_eq!(sa.decrypt("f0", &first[0]).unwrap()["text"], "f0");
    let reply = sa.encrypt("r0", &text("r0")).unwrap();
    sb.decrypt("r0", &reply).unwrap();
    let second = sb.encrypt("s0", &text("s0")).unwrap(); // a new chain
    assert_eq!(sa.decrypt("s0", &second).unwrap()["text"], "s0"); // alice skips f1 and f2 of the old chain
    assert_eq!(sa.skipped_count(), 2);
    assert_eq!(sa.decrypt("f2", &first[2]).unwrap()["text"], "f2");
    assert_eq!(sa.decrypt("f1", &first[1]).unwrap()["text"], "f1");
}

#[test]
fn a_message_that_does_not_authenticate_changes_nothing() {
    let (_a, _b, mut sa, mut sb) = started();
    let r1 = sb.encrypt("m1", &text("one")).unwrap();
    sa.decrypt("m1", &r1).unwrap();
    let r2 = sb.encrypt("m2", &text("two")).unwrap();
    let before = sa.clone();
    // a flipped ciphertext byte, a changed counter, another message id (the associated data), another session
    let mut flipped = r2.clone();
    let ct = flipped["ciphertext_b64u"].as_str().unwrap().to_string();
    flipped["ciphertext_b64u"] = json!(format!("{}{}", &ct[..ct.len() - 2], if ct.ends_with("AA") { "BB" } else { "AA" }));
    assert!(sa.decrypt("m2", &flipped).is_err());
    let mut renumbered = r2.clone();
    renumbered["ratchet_header"]["n"] = json!("5");
    assert!(sa.decrypt("m2", &renumbered).is_err());
    assert!(sa.decrypt("another-id", &r2).is_err(), "the message id is part of the associated data");
    let mut other = r2.clone();
    other["session_id"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
    assert!(sa.decrypt("m2", &other).is_err());
    let mut badpn = r2.clone();
    badpn["ratchet_header"]["pn"] = json!("01");
    assert!(sa.decrypt("m2", &badpn).is_err(), "counters are canonical decimal strings");
    assert_eq!(sa, before, "no failed attempt moved the session");
    assert_eq!(sa.decrypt("m2", &r2).unwrap()["text"], "two", "and the genuine message still works");
}

#[test]
fn the_skip_limit_is_enforced() {
    let (_a, _b, mut sa, mut sb) = started();
    let r0 = sb.encrypt("m0", &text("zero")).unwrap();
    sa.decrypt("m0", &r0).unwrap();
    // exactly MAX_SKIP skipped is fine, one more is refused (and refused cleanly)
    let mut last = Value::Null;
    for i in 0..=MAX_SKIP + 1 {
        last = sb.encrypt(&format!("k{i}"), &text("x")).unwrap();
    }
    let before = sa.clone();
    assert!(sa.decrypt(&format!("k{}", MAX_SKIP + 1), &last).unwrap_err().0.contains("too many"));
    assert_eq!(sa, before);
    let (_a, _b, mut sa, mut sb) = started();
    let r0 = sb.encrypt("m0", &text("zero")).unwrap();
    sa.decrypt("m0", &r0).unwrap();
    let mut msgs = Vec::new();
    for i in 0..=MAX_SKIP {
        msgs.push(sb.encrypt(&format!("k{i}"), &text("x")).unwrap());
    }
    // the last of these has n = MAX_SKIP + 1 and alice expects n = 1: it skips exactly MAX_SKIP, the allowed boundary
    assert!(sa.decrypt(&format!("k{MAX_SKIP}"), msgs.last().unwrap()).is_ok());
    assert_eq!(sa.skipped_count(), MAX_SKIP as usize);
}

#[test]
fn one_time_prekeys_are_mixed_in_and_required() {
    let (a, b) = (Peer::new(1, "alice"), Peer::new(2, "bob"));
    let bundle = b.bundle();
    let opk_secret = [77u8; 32];
    let opk = OneTimePrekey { id: "opk-1".into(), public: public_of(&opk_secret) };
    let (sa, init) = Session::initiate(&a.binding(&b), "m0", &a.ka, &bundle, Some(&opk), &text("with an opk")).unwrap();
    let (plain_no_opk, init_no_opk) = {
        let (s, i) = Session::initiate(&a.binding(&b), "m0", &a.ka, &bundle, None, &text("without")).unwrap();
        (s, i)
    };
    assert_eq!(init["recipient_one_time_prekey_id"], "opk-1");
    assert!(init_no_opk.get("recipient_one_time_prekey_id").is_none());
    assert_ne!(sa.session_id(), plain_no_opk.session_id());
    // bob needs the same one-time prekey
    let ok = Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, Some(("opk-1", &opk_secret))), &public_of(&a.ka), &init);
    assert_eq!(ok.unwrap().1["text"], "with an opk");
    assert!(Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, None), &public_of(&a.ka), &init).is_err(), "an init that used one needs it");
    assert!(Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, Some(("opk-2", &opk_secret))), &public_of(&a.ka), &init).is_err(), "another id");
    assert!(Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, Some(("opk-1", &[78u8; 32]))), &public_of(&a.ka), &init).is_err(), "another secret");
    assert!(Session::accept(&b.binding(&a), "m0", &b.ka, &b.local(&bundle, Some(("opk-1", &opk_secret))), &public_of(&a.ka), &init_no_opk).is_err(), "and one that did not use it must not be given one");
    // a stolen ciphertext cannot be moved to another message id
    assert!(Session::accept(&b.binding(&a), "other", &b.ka, &b.local(&bundle, Some(("opk-1", &opk_secret))), &public_of(&a.ka), &init).is_err());
}

#[test]
fn a_session_survives_being_saved_and_reloaded() {
    let (_a, _b, mut sa, mut sb) = started();
    let r1 = sb.encrypt("m1", &text("one")).unwrap();
    sa.decrypt("m1", &r1).unwrap();
    let r2 = sb.encrypt("m2", &text("two")).unwrap();
    sa.decrypt("m2", &r2).unwrap();
    // reload both mid-conversation
    let mut sa2 = Session::from_json(&sa.to_json()).unwrap();
    let mut sb2 = Session::from_json(&sb.to_json()).unwrap();
    assert_eq!(sa2, sa);
    assert_eq!(sb2, sb);
    let m = sa2.encrypt("m3", &text("back")).unwrap();
    assert_eq!(sb2.decrypt("m3", &m).unwrap()["text"], "back");
    // with skipped keys in the saved state
    let x: Vec<Value> = (0..3).map(|i| sb2.encrypt(&format!("y{i}"), &text(&format!("y{i}"))).unwrap()).collect();
    sa2.decrypt("y2", &x[2]).unwrap();
    assert_eq!(sa2.skipped_count(), 2);
    let mut sa3 = Session::from_json(&sa2.to_json()).unwrap();
    assert_eq!(sa3.skipped_count(), 2);
    assert_eq!(sa3.decrypt("y0", &x[0]).unwrap()["text"], "y0");
    assert_eq!(sa3.decrypt("y1", &x[1]).unwrap()["text"], "y1");
    assert!(sa3.decrypt("y0", &x[0]).is_err(), "a used key is gone, also after a reload");
    // a session that has not had its first reply yet reloads as pending
    let (_a, _b, pending, _sb) = started();
    let reloaded = Session::from_json(&pending.to_json()).unwrap();
    assert!(!reloaded.is_established() && reloaded.is_initiator());
    // corrupted state is refused
    let mut bad = sa.to_json();
    bad["ratchet_public"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(Session::from_json(&bad).is_err());
    assert!(Session::from_json(&json!({})).is_err());
}
#[test]
fn the_message_associated_data_is_byte_for_byte_the_sdks() {
    let v: Value = serde_json::from_str(include_str!("../../../testdata/anp-sdk/direct_e2ee_p5_v2_wire_vectors.json")).unwrap();
    let ctx = Ctx {
        message_id: "msg-a-b-002",
        sender_did: "did:wba:a.example:agents:alice:e1_fixture",
        sender_device_id: "dev-a-7N3KQ2",
        sender_ka_id: "unused-for-messages",
        recipient_did: "did:wba:b.example:agents:bob:e1_fixture",
        recipient_device_id: "dev-b-9R5TLM",
    };
    let h = &v["direct_cipher_request"]["params"]["body"]["ratchet_header"];
    let ad = message_aad(&ctx, "or8NgG6Q0INmcN79HzN2Nw", h["dh_pub_b64u"].as_str().unwrap(), h["pn"].as_str().unwrap(), h["n"].as_str().unwrap()).unwrap();
    assert_eq!(String::from_utf8(ad).unwrap(), v["expected_ad_msg"].as_str().unwrap());
}

#[test]
fn a_payload_plaintext_helper_and_the_plaintext_rules() {
    let (_a, _b, _sa, mut sb) = started();
    let p = payload_plaintext("t1", &json!({ "k": [1.5, 1e30] }));
    assert!(sb.encrypt("m1", &p).is_ok());
    assert!(sb.encrypt("m2", &json!({ "application_content_type": "text/plain" })).is_err(), "no body");
    assert!(sb.encrypt("m3", &json!({ "application_content_type": "text/plain", "text": "a", "payload": {} })).is_err(), "two bodies");
    assert!(sb.encrypt("m4", &json!({ "text": "a" })).is_err(), "no content type");
}
