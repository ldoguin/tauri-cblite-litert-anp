//! `cargo xtask e2e-group`: three nodes of three companies (`store.test`, `carrier.test`, `warehouse.test`) are members of one end-to-end
//! encrypted group (ANP-09 P6, MLS) hosted by a fourth node (`groups.test`). The store creates the group and adds the other two; everyone
//! writes and reads; a member restarts and keeps reading; the store removes the warehouse, which reads nothing after that; and the host,
//! which relays every message, holds none of them in clear.

use crate::harness::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const HOST: u16 = 18981;
const STORE: u16 = 18982;
const CARRIER: u16 = 18983;
const WAREHOUSE: u16 = 18984;

fn host_url() -> String {
    format!("http://127.0.0.1:{HOST}")
}

fn member_base(name: &str) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.test"), "--group-member", &host_url()])
}

/// Start a member once on its own to get its DID document (with the group profiles in its device entry), and save it.
fn document(work: &Path, name: &str, port: u16) -> Result<(String, PathBuf), String> {
    let did = did_for(work, name, &format!("{name}.test"), name);
    let mut n = Node::start(work, name, name, port, &member_base(name));
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

fn allow(docs: &[&PathBuf]) -> Vec<String> {
    docs.iter().flat_map(|d| ["--allow-caller".to_string(), d.display().to_string()]).collect()
}

fn start_member(work: &Path, name: &str, port: u16, docs: &[&PathBuf]) -> Node {
    Node::start(work, name, name, port, &[member_base(name), allow(docs)].concat())
}

fn act(port: u16, action: &str, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{port}/anp/groups/member/{action}"), &body.to_string())
}

fn groups(port: u16) -> Vec<Value> {
    get_json(&format!("http://127.0.0.1:{port}/anp/groups/member"))["groups"].as_array().cloned().unwrap_or_default()
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn events(port: u16, group: &str) -> Vec<Value> {
    get_json(&format!("http://127.0.0.1:{port}/anp/groups/member?group={}", urlencode(group)))["events"].as_array().cloned().unwrap_or_default()
}

/// Has `port` received a message containing `needle` in `group`?
fn received(port: u16, group: &str, needle: &str) -> bool {
    events(port, group).iter().any(|e| e["kind"] == "message" && e["direction"] == "in" && e["plaintext"]["text"].as_str().map_or(false, |t| t.contains(needle)))
}

fn wait_received(port: u16, group: &str, needle: &str) -> bool {
    poll(60, 500, || received(port, group, needle))
}

fn status_in(port: u16, group: &str) -> Option<String> {
    groups(port).into_iter().find(|g| g["group_did"] == json!(group)).and_then(|g| g["status"].as_str().map(str::to_string))
}

fn epoch_in(port: u16, group: &str) -> Value {
    groups(port).into_iter().find(|g| g["group_did"] == json!(group)).map(|g| g["epoch"].clone()).unwrap_or(Value::Null)
}

/// Add with retries: the member publishes its key package when it starts, which may not have happened yet.
fn add(port: u16, group: &str, member: &str) -> (u16, Value) {
    let mut last = (0, Value::Null);
    poll(20, 500, || {
        last = act(port, "add", json!({ "group": group, "member": member }));
        last.0 == 200
    });
    last
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let work = work_dir("xtask-group");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("Three companies and a group host");
    let (store_did, store_doc) = document(&work, "store", STORE)?;
    let (carrier_did, carrier_doc) = document(&work, "carrier", CARRIER)?;
    let (warehouse_did, warehouse_doc) = document(&work, "warehouse", WAREHOUSE)?;
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(&store_doc).unwrap_or_default()).unwrap_or(Value::Null);
    c.check(
        "a member's DID document lists the group profiles for its device",
        manifest["deviceManifest"]["devices"][0]["profiles"].as_array().map_or(false, |p| p.iter().any(|x| x == "anp.group.e2ee.v2")),
        manifest["deviceManifest"].to_string(),
    );
    let host_args = [
        strs(&["--did-host", "groups.test", "--group-host", "--require-auth", "--public-origin", &host_url()]),
        allow(&[&store_doc, &carrier_doc, &warehouse_doc]),
    ]
    .concat();
    let mut host = Node::start(&work, "groups", "groups", HOST, &host_args);
    let mut store = start_member(&work, "store", STORE, &[&carrier_doc, &warehouse_doc]);
    let mut carrier = start_member(&work, "carrier", CARRIER, &[&store_doc, &warehouse_doc]);
    let mut warehouse = start_member(&work, "warehouse", WAREHOUSE, &[&store_doc, &carrier_doc]);

    println!("The store creates a group and adds the carrier and the warehouse");
    let (code, r) = act(STORE, "create", json!({ "name": "rescue-0412" }));
    let group = r["group_did"].as_str().unwrap_or_default().to_string();
    c.check("the store creates a group on the host (the host provisions its DID)", code == 200 && group.starts_with("did:wba:groups.test"), format!("{code} {r}"));
    let (code, r) = add(STORE, &group, &carrier_did);
    c.check("the store adds the carrier (its key package, a commit and a welcome)", code == 200, format!("{code} {r}"));
    c.check("the carrier joins from the welcome", poll(60, 500, || status_in(CARRIER, &group).as_deref() == Some("active")), format!("{:?}", groups(CARRIER)));
    let (code, r) = add(STORE, &group, &warehouse_did);
    c.check("the store adds the warehouse", code == 200, format!("{code} {r}"));
    c.check("the warehouse joins", poll(60, 500, || status_in(WAREHOUSE, &group).as_deref() == Some("active")), format!("{:?}", groups(WAREHOUSE)));
    c.check(
        "the carrier processes the commit that added the warehouse",
        poll(60, 500, || events(CARRIER, &group).iter().any(|e| e["kind"] == "membership" && e["event"] == "added" && e["member"] == json!(warehouse_did))),
        Value::Array(events(CARRIER, &group)).to_string(),
    );
    let members = groups(CARRIER).into_iter().find(|g| g["group_did"] == json!(group)).map(|g| g["members"].clone()).unwrap_or(Value::Null);
    c.check("the carrier sees three members, each bound to its DID", members.as_array().map_or(0, |m| m.len()) == 3, members.to_string());
    c.check("all three are in the same epoch", { let e = epoch_in(STORE, &group); e == epoch_in(CARRIER, &group) && e == epoch_in(WAREHOUSE, &group) && e == json!(2) }, format!("{} {} {}", epoch_in(STORE, &group), epoch_in(CARRIER, &group), epoch_in(WAREHOUSE, &group)));

    println!("Everyone writes, everyone reads");
    let (code, r) = act(STORE, "send", json!({ "group": group, "text": "PLAN-1 pallets 1-2 to the warehouse, dairy to the food bank" }));
    c.check("the store writes to the group", code == 200, format!("{code} {r}"));
    c.check("the carrier reads it", wait_received(CARRIER, &group, "PLAN-1"), "");
    c.check("the warehouse reads it", wait_received(WAREHOUSE, &group, "PLAN-1"), "");
    let (code, _) = act(CARRIER, "send", json!({ "group": group, "text": "ETA-2 truck at the loading bay 02:58" }));
    c.check("the carrier writes", code == 200, code.to_string());
    c.check("the store and the warehouse read the carrier's message", wait_received(STORE, &group, "ETA-2") && wait_received(WAREHOUSE, &group, "ETA-2"), "");
    let from = events(STORE, &group).into_iter().find(|e| e["plaintext"]["text"].as_str().map_or(false, |t| t.contains("ETA-2"))).map(|e| e["from"].clone()).unwrap_or(Value::Null);
    c.check("...and know it came from the carrier's DID (origin proof and MLS sender agree)", from == json!(carrier_did), from.to_string());
    let (code, _) = act(CARRIER, "add", json!({ "group": group, "member": store_did }));
    c.check("a member that is not the controller cannot change the membership", code == 400, code.to_string());

    println!("A restart");
    warehouse.kill();
    warehouse = start_member(&work, "warehouse", WAREHOUSE, &[&store_doc, &carrier_doc]);
    let (code, _) = act(STORE, "send", json!({ "group": group, "text": "AFTER-RESTART-3 second truck at 03:30" }));
    c.check("the store writes while the warehouse restarts", code == 200, code.to_string());
    c.check("the warehouse, restarted, still reads the group (its MLS state is kept on disk)", wait_received(WAREHOUSE, &group, "AFTER-RESTART-3"), "");

    println!("The store removes the warehouse");
    let (code, r) = act(STORE, "remove", json!({ "group": group, "member": warehouse_did }));
    c.check("the store removes the warehouse", code == 200, format!("{code} {r}"));
    c.check("the warehouse learns it was removed", poll(60, 500, || status_in(WAREHOUSE, &group).as_deref() == Some("removed")), format!("{:?}", groups(WAREHOUSE)));
    c.check(
        "the carrier processes the removal",
        poll(60, 500, || events(CARRIER, &group).iter().any(|e| e["event"] == "removed" && e["member"] == json!(warehouse_did))),
        "",
    );
    let (code, _) = act(STORE, "send", json!({ "group": group, "text": "SECRET-4 the code for gate B is 4471" }));
    c.check("the store writes after the removal", code == 200, code.to_string());
    c.check("the carrier reads it", wait_received(CARRIER, &group, "SECRET-4"), "");
    sleep(3);
    // the host no longer delivers to it; that it could not decrypt the message anyway (the group moved to an epoch it has no keys
    // for) is tested on the MLS layer itself: anp-group-mls, tests/group.rs, "a removed device cannot read what is sent after it"
    c.check("the removed warehouse gets nothing written after its removal", !received(WAREHOUSE, &group, "SECRET-4"), "");
    let (code, _) = act(WAREHOUSE, "send", json!({ "group": group, "text": "still here?" }));
    c.check("...nor can it write to the group any more", code == 400, code.to_string());
    c.check("the store and the carrier moved on to a new epoch together", epoch_in(STORE, &group) == epoch_in(CARRIER, &group) && epoch_in(STORE, &group) == json!(3), format!("{} {}", epoch_in(STORE, &group), epoch_in(CARRIER, &group)));

    println!("Guards");
    let proxied = ureq::post(&format!("http://127.0.0.1:{STORE}/anp/groups/member/send"))
        .set("content-type", "application/json")
        .set("x-forwarded-for", "203.0.113.7")
        .send_string(&json!({ "group": group, "text": "via a proxy" }).to_string());
    let pcode = match proxied {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(_) => 0,
    };
    c.check("the member controls refuse a request that came through a proxy", pcode == 403, pcode.to_string());
    let (code, _) = act(STORE, "send", json!({ "group": "did:wba:groups.test:groups:nope:e1_x", "text": "x" }));
    c.check("a group the node is not in is refused", code == 400, code.to_string());

    println!("What the host holds");
    for n in [&mut host, &mut store, &mut carrier, &mut warehouse] {
        n.kill();
    }
    sleep(2);
    for secret in ["PLAN-1", "ETA-2", "AFTER-RESTART-3", "SECRET-4"] {
        let leak = file_contains(&work.join("groups"), secret);
        c.check(&format!("the host, which relayed it, holds no clear copy of {secret}"), leak.is_none(), format!("{leak:?}"));
    }
    c.check("(the members do keep their own log)", file_contains(&work.join("carrier"), "SECRET-4").is_some(), "");
    Ok(c.finish())
}
