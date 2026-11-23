//! `cargo xtask e2e-direct`: two nodes of two companies (`store.test` and `carrier.test`) start encrypted direct conversations
//! with each other (ANP-09 P5), both ways. Each fetches the other's prekey bundle from the other's endpoint, every request is
//! signed (ANP-02, `--require-auth`), each side's agent answers what the other asked, and an answer goes back to whoever asked
//! instead of to the agent (no endless ping-pong). Then a follow-up in the same session, a restart in the middle, and the
//! guards on the operator's control endpoint.

use crate::harness::*;
use serde_json::{json, Value};
use std::path::Path;

const STORE: u16 = 18961;
const CARRIER: u16 = 18962;

/// The node's options: its DID host, encryption, direct messaging, and signed requests.
fn base(name: &str, port: u16) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.test"), "--e2ee", "--direct-messaging", "--require-auth", "--public-origin", &format!("http://127.0.0.1:{port}")])
}

/// Start the node alone once to get its DID document (key agreement, device manifest, message service), and save it.
fn document(work: &Path, name: &str, port: u16) -> Result<(String, std::path::PathBuf), String> {
    let did = did_for(work, name, &format!("{name}.test"), name);
    let mut n = Node::start(work, name, name, port, &base(name, port));
    let e1 = did.rsplit(':').next().unwrap_or_default();
    let doc = get_json(&format!("http://127.0.0.1:{port}/agents/{name}/{e1}/did.json"));
    n.kill();
    if doc["id"] != json!(did) {
        return Err(format!("{name}: no DID document ({doc})"));
    }
    let f = work.join(format!("{name}.did.json"));
    std::fs::write(&f, doc.to_string()).map_err(|e| e.to_string())?;
    Ok((did, f))
}

fn start(work: &Path, name: &str, port: u16, peer_doc: &Path, peer_did: &str, peer_port: u16) -> Node {
    let extra = [
        base(name, port),
        strs(&["--allow-caller", &peer_doc.display().to_string(), "--direct-peer", &format!("{peer_did}=http://127.0.0.1:{peer_port}/anp/direct"), "--agent", "echo"]),
    ]
    .concat();
    Node::start(work, name, name, port, &extra)
}

fn send(port: u16, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{port}/anp/direct/conversations"), &body.to_string())
}

fn conversation(port: u16, peer: &str) -> Vec<Value> {
    let url = format!("http://127.0.0.1:{port}/anp/direct/conversations?peer={}", urlencode(peer));
    get_json(&url)["messages"].as_array().cloned().unwrap_or_default()
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn text_of(m: &Value) -> String {
    m["plaintext"]["text"].as_str().unwrap_or_default().to_string()
}

/// Wait until `port`'s log with `peer` holds an incoming answer containing `needle`.
fn wait_answer(port: u16, peer: &str, needle: &str) -> Option<Value> {
    let mut found = None;
    poll(60, 500, || {
        found = conversation(port, peer).into_iter().find(|m| m["direction"] == "in" && text_of(m).contains(needle));
        found.is_some()
    });
    found
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let work = work_dir("xtask-direct");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("Two companies, two domains");
    let (store_did, store_doc) = document(&work, "store", STORE)?;
    let (carrier_did, carrier_doc) = document(&work, "carrier", CARRIER)?;
    c.check("the store and the carrier have DIDs on different domains", store_did.contains(":store.test:") && carrier_did.contains(":carrier.test:"), format!("{store_did} {carrier_did}"));
    let mut store = start(&work, "store", STORE, &carrier_doc, &carrier_did, CARRIER);
    let mut carrier = start(&work, "carrier", CARRIER, &store_doc, &store_did, STORE);

    println!("The store starts a conversation");
    let (code, r) = send(STORE, json!({ "to": carrier_did, "text": "QUOTE-REQ-1 three pallets frozen to Rungis, pick-up 02:45" }));
    c.check("the store's node accepts the message to send", code == 200 && r["message_id"].is_string(), format!("{code} {r}"));
    let answer = wait_answer(STORE, &carrier_did, "QUOTE-REQ-1");
    c.check("the carrier's agent answered and the answer came back to the store", answer.is_some(), format!("{:?}", conversation(STORE, &carrier_did)));
    c.check("...marked as an answer to the store's own conversation", answer.as_ref().map_or(false, |a| a["answer"] == json!(true)), "");
    let on_carrier = conversation(CARRIER, &store_did);
    c.check(
        "the carrier received the store's message and sent its answer",
        on_carrier.iter().any(|m| m["direction"] == "in" && text_of(m).contains("QUOTE-REQ-1")) && on_carrier.iter().any(|m| m["direction"] == "out"),
        Value::Array(on_carrier.clone()).to_string(),
    );
    let list = get_json(&format!("http://127.0.0.1:{STORE}/anp/direct/conversations"));
    c.check("the store lists the conversation as started here", list["conversations"][0]["session"] == "started here", list.to_string());

    println!("A follow-up in the same session");
    let (code, _) = send(STORE, json!({ "to": carrier_did, "text": "FOLLOW-UP-2 can you take a fourth pallet" }));
    c.check("a second message goes out in the session", code == 200, code.to_string());
    c.check("...and its answer comes back", wait_answer(STORE, &carrier_did, "FOLLOW-UP-2").is_some(), "");
    sleep(2);
    let ins = conversation(STORE, &carrier_did).iter().filter(|m| m["direction"] == "in").count();
    c.check("each question got exactly one answer: nobody answered an answer", ins == 2, format!("{ins} answers"));
    let outs = conversation(CARRIER, &store_did).iter().filter(|m| m["direction"] == "out").count();
    c.check("...and the carrier sent exactly two", outs == 2, format!("{outs}"));

    println!("A structured payload");
    let (code, _) = send(STORE, json!({ "to": carrier_did, "payload": { "type": "QuoteRequest", "id": "req-9", "category": "transport" } }));
    c.check("a JSON payload (a quote message) goes out too", code == 200, code.to_string());
    let got = poll(40, 500, || conversation(CARRIER, &store_did).iter().any(|m| m["plaintext"]["payload"]["id"] == "req-9"));
    c.check("...and arrives intact on the carrier", got, "");
    c.check("...whose agent is handed it as JSON and answers it", wait_answer(STORE, &carrier_did, "req-9").is_some(), "");

    println!("A restart in the middle");
    store.kill();
    store = start(&work, "store", STORE, &carrier_doc, &carrier_did, CARRIER);
    let (code, r) = send(STORE, json!({ "to": carrier_did, "text": "AFTER-RESTART-3 still on for 02:45" }));
    c.check("after a restart the store continues the same session", code == 200, format!("{code} {r}"));
    c.check("...and gets the answer", wait_answer(STORE, &carrier_did, "AFTER-RESTART-3").is_some(), "");
    c.check("the log survived the restart", conversation(STORE, &carrier_did).iter().any(|m| text_of(m).contains("QUOTE-REQ-1")), "");

    println!("The other way round");
    let (code, _) = send(CARRIER, json!({ "to": store_did, "text": "CARRIER-ASKS-4 is the loading bay open" }));
    c.check("the carrier asks the store in the same session (either side can ask)", code == 200, code.to_string());
    c.check("...and gets the store agent's answer", wait_answer(CARRIER, &store_did, "CARRIER-ASKS-4").is_some(), format!("{:?}", conversation(CARRIER, &store_did)));
    let (code, _) = send(CARRIER, json!({ "to": store_did, "text": "CARRIER-OPENS-5 new key exchange", "new_session": true }));
    c.check("the carrier starts a session of its own with the store (a new key exchange)", code == 200, code.to_string());
    c.check("...and gets the answer in it", wait_answer(CARRIER, &store_did, "CARRIER-OPENS-5").is_some(), "");
    let list = get_json(&format!("http://127.0.0.1:{CARRIER}/anp/direct/conversations"));
    c.check("the carrier now lists the conversation as started there", list["conversations"][0]["session"] == "started here", list.to_string());
    let (code, _) = send(STORE, json!({ "to": carrier_did, "text": "STORE-AGAIN-6 thanks" }));
    c.check("the store asks in the carrier's session and gets its answer", code == 200 && wait_answer(STORE, &carrier_did, "STORE-AGAIN-6").is_some(), code.to_string());
    sleep(2);
    let (s_out, s_in) = {
        let m = conversation(STORE, &carrier_did);
        (m.iter().filter(|x| x["direction"] == "out").count(), m.iter().filter(|x| x["direction"] == "in").count())
    };
    c.check("in all, every message got exactly one reply (store: as many in as out)", s_out == s_in, format!("{s_out} out, {s_in} in"));

    println!("Guards");
    let (code, _) = send(STORE, json!({ "to": "did:wba:mallory.test:agents:m:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "text": "hi" }));
    c.check("a DID the node does not know is refused", code == 400, code.to_string());
    let (code, _) = send(STORE, json!({ "to": carrier_did }));
    c.check("a message with neither text nor payload is refused", code == 400, code.to_string());
    let proxied = ureq::post(&format!("http://127.0.0.1:{STORE}/anp/direct/conversations"))
        .set("content-type", "application/json")
        .set("x-forwarded-for", "203.0.113.7")
        .send_string(&json!({ "to": carrier_did, "text": "via a proxy" }).to_string());
    let pcode = match proxied {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(_) => 0,
    };
    c.check("the control endpoint refuses a request that came through a proxy", pcode == 403, pcode.to_string());
    let (code, _) = post_json(&format!("http://127.0.0.1:{CARRIER}/anp/direct"), &json!({ "jsonrpc": "2.0", "id": 1, "method": "direct.send", "params": {} }).to_string());
    c.check("the peer endpoint itself still wants a signed request", code == 401, code.to_string());

    store.kill();
    carrier.kill();
    Ok(c.finish())
}
