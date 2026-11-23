//! `cargo xtask e2e-did-biscuit`: DID and Biscuit together on real nodes: `did:wba` identities, tokens bound to them (scoping, revocation), TLS
//! and connection admission. No peer is pinned: the authority's tokens do the trusting. The same checks as `scripts/e2e-did-biscuit.ps1`.

use crate::harness::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

/// A token for `node`, bound to `did`, from the authority `root`, allowed to send inbox commands to `inbox_to`.
fn issue(work: &Path, root: &str, node: &str, did: &str, inbox_to: &str, dir: &str) {
    let (code, out) = run_tool(
        "anp-admin",
        &strs(&["issue", "--root", &work.join(format!("{root}.key")).display().to_string(), "--node", node, "--node-dir", &work.join(dir).display().to_string(), "--did", did, "--inbox-to", inbox_to, "--out", &work.join(format!("{node}.token")).display().to_string()]),
    );
    assert_eq!(code, 0, "anp-admin issue: {out}");
}

/// The options of a node that runs on a DID and a token from the authority whose public key is `root`.
fn hard(work: &Path, n: &str, root: &str) -> Vec<String> {
    strs(&["--did-host", &format!("{n}.example.com"), "--root-key", root, "--token", &work.join(format!("{n}.token")).display().to_string(), "--tls", "--admit"])
}

fn with(a: Vec<String>, b: &[&str]) -> Vec<String> {
    [a, strs(b)].concat()
}

fn task_state(port: u16, id: &Value) -> Value {
    rpc(port, "GetTask", json!({ "id": id }))["result"]["status"]["state"].clone()
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let work = work_dir("xtask-hybrid");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("Setup: DIDs, then tokens bound to them");
    let root_pub = root_key(&work, "root");
    let fake_pub = root_key(&work, "fake");
    let d: HashMap<&str, String> = ["alice", "bob", "carol", "mallory"].iter().map(|n| (*n, did_of(&work, n, n))).collect();
    issue(&work, "root", "alice", &d["alice"], "*", "alice");
    issue(&work, "root", "bob", &d["bob"], "*", "bob");
    issue(&work, "root", "carol", &d["carol"], "bob", "carol"); // carol may only message bob
    issue(&work, "fake", "mallory", &d["mallory"], "*", "mallory"); // mallory's token comes from another authority
    let (_, ins) = run_tool("anp-admin", &strs(&["inspect", "--root-pub", &root_pub, "--token", &work.join("carol.token").display().to_string()]));
    c.check("the token carries the DID it is bound to", ins.contains(&d["carol"]), &ins);

    let alice = Node::start(&work, "alice", "alice", 18801, &hard(&work, "alice", &root_pub));
    let port = alice.p2p_port().ok_or("alice printed no P2P port")?;
    let url = format!("wss://127.0.0.1:{port}/a2a");
    let pin = work.join("alice").join("tls.cert.pem").display().to_string();
    let sec = get_json("http://127.0.0.1:18801/security");
    c.check("alice runs in did+biscuit mode with her DID", sec["mode"] == "did+biscuit" && sec["did"] == json!(d["alice"]), sec.to_string());

    let bob = Node::start(&work, "bob", "bob", 18802, &with(hard(&work, "bob", &root_pub), &["--pin-cert", &pin, "--connect", &url]));
    c.check("bob joins with no pinned peers (the authority's token is the trust anchor)", wait_sees(18802, "alice", 15), "");
    c.check("alice sees bob", wait_sees(18801, "bob", 15), "");
    let r = rpc(18801, "SendMessage", json!({ "tenant": "bob", "message": msg("hello over DID + token") }));
    c.check("a task alice -> bob completes", completed(&r), r.to_string());
    c.check("nothing refused during normal operation", rejections(18801).is_empty(), "");

    println!("Scoping");
    let mut carol = Node::start(&work, "carol", "carol", 18803, &with(hard(&work, "carol", &root_pub), &["--pin-cert", &pin, "--connect", &url]));
    c.check("carol (token: may message bob only) joins", wait_sees(18803, "alice", 15), "");
    let r = rpc(18803, "SendMessage", json!({ "tenant": "bob", "message": msg("carol to bob") }));
    c.check("carol -> bob (allowed) completes", completed(&r), r.to_string());
    let r = rpc(18803, "SendMessage", json!({ "tenant": "alice", "message": msg("carol to alice, not allowed"), "configuration": { "returnImmediately": true } }));
    let tid = r["result"]["task"]["id"].clone();
    sleep(8);
    let st = task_state(18803, &tid);
    c.check("carol -> alice (not in her token) never completes", st != "TASK_STATE_COMPLETED", st.to_string());
    c.check("alice logged the refused command", rejections(18801).iter().any(|r| r["collection"] == "inbox" && r["author"] == "carol"), Value::Array(rejections(18801)).to_string());

    println!("Attackers");
    // 1. a valid DID, a valid token, but from another authority
    let mut mal = Node::start(&work, "mallory", "mallory", 18804, &with(hard(&work, "mallory", &fake_pub), &["--pin-cert", &pin, "--connect", &url]));
    sleep(8);
    c.check("mallory (valid DID, token from another authority) never sees alice", !agents(18804).iter().any(|n| n == "alice"), "");
    c.check("alice logged the refused connection", refused(18801, "connection", "mallory", ""), Value::Array(rejections(18801)).to_string());
    mal.kill();

    // 2. a stolen token: bob's token on a node with another key (and so another DID)
    std::fs::copy(work.join("bob.token"), work.join("stolen.token")).map_err(|e| e.to_string())?;
    let _ = did_for(&work, "bob", "bob.example.com", "fakebob"); // makes the other key
    let args = strs(&[
        "--name", "bob", "--data", &work.join("fakebob").display().to_string(), "--http-port", "18805", "--did-host", "bob.example.com", "--root-key", &root_pub, "--token", &work.join("stolen.token").display().to_string(), "--tls", "--admit", "--pin-cert", &pin, "--connect", &url,
    ]);
    let thief = expect_exit(&work, "thief", &args, 15);
    c.check("bob's token cannot even start a node with a different key (the token names bob's DID)", thief.exited && thief.code != Some(0), format!("exited={}", thief.exited));
    c.check("...and the error says why", thief.stderr.contains("token is not usable"), &thief.stderr);

    // 3. a DID-bound token used by a node that proves no DID
    let args = strs(&["--name", "bob", "--data", &work.join("bob2").display().to_string(), "--http-port", "18806", "--root-key", &root_pub, "--token", &work.join("bob.token").display().to_string(), "--tls"]);
    let nodid = expect_exit(&work, "nodid", &args, 15);
    c.check("a DID-bound token is useless without the DID", nodid.exited && nodid.code != Some(0), "");

    println!("Revocation");
    carol.kill();
    let revoke_file = work.join("carol-revoke.json");
    let (code, out) = run_tool("anp-admin", &strs(&["revoke", "--root", &work.join("root.key").display().to_string(), "--token", &work.join("carol.token").display().to_string(), "--reason", "tablet lost", "--out", &revoke_file.display().to_string()]));
    assert_eq!(code, 0, "anp-admin revoke: {out}");
    let (status, res) = post_json("http://127.0.0.1:18801/security/revocations", &std::fs::read_to_string(&revoke_file).map_err(|e| e.to_string())?);
    c.check("the authority's revocation is accepted", status == 200 && res["revoked"].as_str().map_or(false, |s| s.len() >= 32), res.to_string());
    let carol = Node::start(&work, "carol", "carol", 18803, &with(hard(&work, "carol", &root_pub), &["--pin-cert", &pin, "--connect", &url]));
    // (carol's database still holds alice's card from before, so /agents proves nothing: check that her task never arrives)
    let r = rpc(18803, "SendMessage", json!({ "tenant": "bob", "message": msg("revoked carol tries again"), "configuration": { "returnImmediately": true } }));
    let ctid = r["result"]["task"]["id"].clone();
    sleep(8);
    c.check(
        "revoked carol (same DID, same key) cannot get a task out: it never reaches bob",
        task_state(18803, &ctid) == "TASK_STATE_SUBMITTED" && rpc(18802, "GetTask", json!({ "id": ctid }))["error"]["code"] == -32001,
        "",
    );
    c.check("alice logged: token revoked", refused(18801, "connection", "carol", "revoked"), Value::Array(rejections(18801)).to_string());
    let sec2 = get_json("http://127.0.0.1:18802/security");
    c.check("bob learned of the revocation through replication", sec2["revokedTokens"].as_array().map_or(0, |a| a.len()) >= 1, sec2.to_string());
    let r = rpc(18801, "SendMessage", json!({ "tenant": "bob", "message": msg("the others are unaffected") }));
    c.check("alice <-> bob still works", completed(&r), r.to_string());

    drop((alice, bob, carol));
    Ok(c.finish())
}
