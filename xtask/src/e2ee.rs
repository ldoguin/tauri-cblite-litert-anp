//! `cargo xtask e2e-e2ee`: end-to-end encryption on real nodes. Bob sends carol a task through alice, who only relays it; a control run without
//! `--e2ee` shows the relay really can read it otherwise (so the search for the secret in her files means something).
//! The same checks as `scripts/e2e-e2ee.ps1`.

use crate::harness::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

const MARKER: &str = "TOP-SECRET-MARKER-9137";
const NAMES: [&str; 3] = ["alice", "bob", "carol"];

struct Mesh {
    alice: Node,
    bob: Node,
    carol: Node,
    dids: HashMap<String, String>,
}

fn pins(dids: &HashMap<String, String>, me: &str, extra: &[&str]) -> Vec<String> {
    let mut o = vec![];
    for m in NAMES {
        if m != me {
            o.push("--trust-did".to_string());
            o.push(dids[m].clone());
        }
    }
    for e in extra {
        o.push("--trust-did".into());
        o.push((*e).into());
    }
    o
}

fn base(me: &str, e2ee: bool) -> Vec<String> {
    let mut o: Vec<String> = ["--did-host", &format!("{me}.example.com"), "--tls", "--admit"].iter().map(|s| s.to_string()).collect();
    if e2ee {
        o.push("--e2ee".into());
    }
    o
}

fn connect_to(work: &Path, alice_dir: &str, port: u16) -> Vec<String> {
    vec!["--connect".into(), format!("wss://127.0.0.1:{port}/a2a"), "--pin-cert".into(), work.join(alice_dir).join("tls.cert.pem").display().to_string()]
}

/// One mesh: alice (the relay), bob and carol, each pinning the other two. `tag` names the data folders.
fn mesh(work: &Path, tag: &str, e2ee: bool, port0: u16) -> Mesh {
    let dids: HashMap<String, String> = NAMES.iter().map(|n| (n.to_string(), did_of(work, n, &format!("{tag}-{n}")))).collect();
    let opts = |n: &str| [base(n, e2ee), pins(&dids, n, &[])].concat();
    let alice = Node::start(work, "alice", &format!("{tag}-alice"), port0, &opts("alice"));
    let port = alice.p2p_port().expect("alice's P2P port");
    let conn = connect_to(work, &format!("{tag}-alice"), port);
    let bob = Node::start(work, "bob", &format!("{tag}-bob"), port0 + 1, &[opts("bob"), conn.clone()].concat());
    let carol = Node::start(work, "carol", &format!("{tag}-carol"), port0 + 2, &[opts("carol"), conn].concat());
    Mesh { alice, bob, carol, dids }
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let work = work_dir("xtask-e2ee");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("Encrypted mesh: bob -> carol through the relay alice");
    let mut m = mesh(&work, "enc", true, 18901);
    let sec = get_json("http://127.0.0.1:18901/security");
    c.check("nodes report end-to-end encryption on", sec["e2ee"] == json!(true), sec.to_string());
    c.check("each node keeps its signed prekeys in its data directory", work.join("enc-alice/e2ee-prekeys.json").exists() && work.join("enc-bob/e2ee-prekeys.json").exists(), "");
    let e1 = m.dids["alice"].rsplit(':').next().unwrap_or_default().to_string();
    let doc = get_json(&format!("http://127.0.0.1:18901/agents/alice/{e1}/did.json"));
    // the layout the ANP SDK uses: keyAgreement refers to an X25519KeyAgreementKey2019 verification method; a deviceManifest names the device
    let ka: Vec<&Value> = doc["verificationMethod"].as_array().into_iter().flatten().filter(|v| v["id"] == doc["keyAgreement"][0]).collect();
    c.check(
        "the DID document publishes an X25519 key-agreement key (a verification method that keyAgreement refers to)",
        ka.len() == 1 && ka[0]["type"] == "X25519KeyAgreementKey2019" && ka[0]["publicKeyMultibase"].as_str().map_or(false, |s| s.starts_with('z')),
        doc.to_string(),
    );
    c.check(
        "...and a deviceManifest lists the device with that key",
        doc["deviceManifest"]["devices"][0]["e2ee_key_id"] == doc["keyAgreement"][0] && doc["deviceManifest"]["devices"][0]["profiles"].as_array().map_or(false, |p| p.iter().any(|x| x == "anp.direct.e2ee.v2")),
        "",
    );
    c.check("bob learns about carol through the relay", wait_sees(18902, "carol", 20), "");
    c.check("carol learns about bob", wait_sees(18903, "bob", 20), "");
    // cards carry the prekey bundles; allow a moment for them to be read
    sleep(3);
    let r = rpc(18902, "SendMessage", json!({ "tenant": "carol", "message": msg(&format!("please echo this: {MARKER}")) }));
    let tid = r["result"]["task"]["id"].clone();
    c.check("a task bob -> carol completes", r["result"]["task"]["status"]["state"] == "TASK_STATE_COMPLETED", r.to_string());
    c.check("bob reads carol's result (decrypted on his side)", task_text(&r).contains(MARKER), task_text(&r));
    let g = rpc(18903, "GetTask", json!({ "id": tid }));
    c.check("carol, the executor, reads her own task back", task_text(&g).contains(MARKER), "");
    sleep(3);
    let ga = rpc(18901, "GetTask", json!({ "id": tid }));
    c.check("alice, who relayed it, cannot read the task (not found through her API)", ga["error"]["code"] == -32001, ga.to_string());
    c.check("...nor does it show in her task list", !rpc(18901, "ListTasks", json!({})).to_string().contains(MARKER), "");
    c.check("no document was refused anywhere", [18901u16, 18902, 18903].iter().all(|p| rejections(*p).is_empty()), "");

    println!("A peer that sends plaintext");
    let dave_did = did_of(&work, "dave", "enc-dave");
    // dave is pinned by alice and bob; the nodes restart with that pin (alice's listener port changes, so bob and carol reconnect to it)
    m.bob.kill();
    m.alice.kill();
    m.carol.kill();
    m.alice = Node::start(&work, "alice", "enc-alice", 18901, &[base("alice", true), pins(&m.dids, "alice", &[&dave_did])].concat());
    let port = m.alice.p2p_port().expect("alice's P2P port");
    let conn2 = connect_to(&work, "enc-alice", port);
    m.bob = Node::start(&work, "bob", "enc-bob", 18902, &[base("bob", true), pins(&m.dids, "bob", &[&dave_did]), conn2.clone()].concat());
    m.carol = Node::start(&work, "carol", "enc-carol", 18903, &[base("carol", true), pins(&m.dids, "carol", &[]), conn2.clone()].concat());
    // dave: a valid DID, pinned by alice and bob, but not running end-to-end encryption
    let dave_pins: Vec<String> = ["--trust-did", &m.dids["alice"], "--trust-did", &m.dids["bob"]].iter().map(|s| s.to_string()).collect();
    let mut dave = Node::start(&work, "dave", "enc-dave", 18904, &[base("dave", false), dave_pins, conn2].concat());
    c.check("dave (no encryption) joins the mesh and sees bob", wait_sees(18904, "bob", 20), "");
    c.check("bob sees dave", wait_sees(18902, "dave", 20), "");
    let r = rpc(18904, "SendMessage", json!({ "tenant": "bob", "message": msg("plaintext from dave: DAVE-PLAINTEXT-9137"), "configuration": { "returnImmediately": true } }));
    let dtid = r["result"]["task"]["id"].clone();
    sleep(8);
    let st = rpc(18904, "GetTask", json!({ "id": dtid }))["result"]["status"]["state"].clone();
    c.check("dave's plaintext command is never executed (his task does not complete)", st != "TASK_STATE_COMPLETED", st.to_string());
    let rej = rejections(18902);
    c.check("bob logged the refusal: plaintext where encryption is required", rej.iter().any(|r| r["reason"].as_str().map_or(false, |s| s.contains("plaintext"))), Value::Array(rej.clone()).to_string());

    println!("At rest on the relay");
    for n in [&mut m.alice, &mut m.bob, &mut m.carol, &mut dave] {
        n.kill();
    }
    sleep(2);
    let leak = file_contains(&work.join("enc-alice"), MARKER);
    c.check("the secret is NOT in the relay's database files", leak.is_none(), format!("{leak:?}"));
    let dave_leak = file_contains(&work.join("enc-alice"), "DAVE-PLAINTEXT-9137").is_some();
    c.note(&format!("dave's plaintext message did replicate through the relay ({dave_leak}): only bob refused to act on it. That is why dave is the weak link, not alice."));

    println!("Control: the same task with encryption off");
    let mut p = mesh(&work, "plain", false, 18911);
    wait_sees(18912, "carol", 20);
    wait_sees(18913, "bob", 20);
    sleep(3);
    let r = rpc(18912, "SendMessage", json!({ "tenant": "carol", "message": msg(&format!("please echo this: {MARKER}")) }));
    let ctid = r["result"]["task"]["id"].clone();
    c.check("control: the task completes", r["result"]["task"]["status"]["state"] == "TASK_STATE_COMPLETED", r.to_string());
    sleep(4);
    let ga = rpc(18911, "GetTask", json!({ "id": ctid }));
    c.check("CONTROL: without encryption the relay CAN read the task through its own API", task_text(&ga).contains(MARKER), ga.to_string());
    for n in [&mut p.alice, &mut p.bob, &mut p.carol] {
        n.kill();
    }
    sleep(2);
    c.check("CONTROL: without encryption the secret IS in the relay's database files", file_contains(&work.join("plain-alice"), MARKER).is_some(), "");
    Ok(c.finish())
}
