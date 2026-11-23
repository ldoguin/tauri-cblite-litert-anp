//! `cargo xtask e2e-hardened`: the whole hardened setup on real nodes: Biscuit tokens, TLS (wss://), connection admission and an encrypted
//! database. Each layer gets an attacker that the layer alone must stop. The same checks as `scripts/e2e-hardened.ps1`.

use crate::harness::*;
use serde_json::{json, Value};

const MARKER: &str = "TOP-SECRET-MARKER-7421";

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let work = work_dir("xtask-hard");
    fresh_dir(&work);
    std::env::set_var("A2A_DB_KEY", "correct horse battery staple");
    let mut c = Checks::default();

    println!("Setup: authority, node keys, tokens");
    let root_pub = root_key(&work, "root");
    let fake_pub = root_key(&work, "fake");
    for n in ["alice", "bob", "carol", "dave", "mallory"] {
        pubkey_of(&work, n);
    }
    issue_token(&work, "root", "alice", "alice", None, "*");
    issue_token(&work, "root", "bob", "bob", None, "*");
    issue_token(&work, "root", "carol", "carol", None, "bob");
    issue_token(&work, "root", "dave", "dave", None, "bob");
    issue_token(&work, "fake", "mallory", "mallory", None, "*");
    let hard = |node: &str, root: &str| strs(&["--root-key", root, "--token", &work.join(format!("{node}.token")).display().to_string(), "--tls", "--admit", "--db-key-env", "A2A_DB_KEY"]);
    let with = |a: Vec<String>, b: &[&str]| [a, strs(b)].concat();

    println!("Hardened mesh: alice (listener) and bob (dialer) over wss://, tokens, encrypted databases");
    let alice = Node::start(&work, "alice", "alice", 18601, &hard("alice", &root_pub));
    let port = alice.p2p_port().ok_or("alice printed no P2P port")?;
    let url = format!("wss://127.0.0.1:{port}/a2a");
    let out = alice.output();
    c.check("alice reports TLS, admission and an encrypted database", out.contains("transport TLS") && out.contains("admission") && out.contains("database encrypted"), &out);
    c.check("alice's listener URLs are wss://", out.lines().any(|l| l.trim_start().strip_prefix("P2P url").map_or(false, |r| r.trim_start().starts_with("wss://"))), &out);
    c.check("alice wrote her certificate for peers to pin", work.join("alice").join("tls.cert.pem").exists(), "");
    let bob = Node::start(&work, "bob", "bob", 18602, &with(hard("bob", &root_pub), &["--connect", &url]));
    c.check("bob (with a valid token) joins over TLS and sees alice", wait_sees(18602, "alice", 15), "");
    c.check("alice sees bob", wait_sees(18601, "bob", 15), "");
    let r = rpc(18601, "SendMessage", json!({ "tenant": "bob", "message": msg(&format!("routed through TLS, admission and an encrypted database: {MARKER}")) }));
    c.check("a task alice -> bob completes over the hardened link", completed(&r), r.to_string());

    println!("Attackers");
    // 1. plaintext: a node with a REAL token but no TLS dials ws:// on the TLS listener
    let plain_args = strs(&["--connect", &format!("ws://127.0.0.1:{port}/a2a"), "--root-key", &root_pub, "--token", &work.join("carol.token").display().to_string(), "--db-key-env", "A2A_DB_KEY"]);
    let mut plain = Node::start(&work, "carol", "carol", 18603, &plain_args);
    sleep(8);
    c.check("plaintext ws:// to the TLS listener is refused (carol never sees alice)", !agents(18603).iter().any(|n| n == "alice"), agents(18603).join(","));
    c.check("...and alice never sees carol", !agents(18601).iter().any(|n| n == "carol"), "");
    plain.kill();

    // 2. a node from a fake authority, over TLS: admission refuses it at the door
    let mut mal = Node::start(&work, "mallory", "mallory", 18604, &with(hard("mallory", &fake_pub), &["--connect", &url]));
    sleep(8);
    c.check("a fake authority's token does not get mallory in", !agents(18604).iter().any(|n| n == "alice"), "");
    c.check("alice logged the refused connection for mallory", refused(18601, "connection", "mallory", ""), Value::Array(rejections(18601)).to_string());
    c.check("no mallory document ever reached alice", !agents(18601).iter().any(|n| n == "mallory"), "");
    mal.kill();

    // 3. TLS but no credentials at all
    let mut anon = Node::start(&work, "anon", "anon", 18605, &strs(&["--connect", &url, "--tls"]));
    sleep(8);
    c.check("a node with TLS but no token is refused (anon never sees alice)", !agents(18605).iter().any(|n| n == "alice"), "");
    anon.kill();

    // 4. certificate pinning
    std::fs::copy(work.join("mallory").join("tls.cert.pem"), work.join("wrong.cert.pem")).map_err(|e| e.to_string())?;
    let mut dave = Node::start(&work, "dave", "dave", 18606, &with(hard("dave", &root_pub), &["--connect", &url, "--pin-cert", &work.join("wrong.cert.pem").display().to_string()]));
    sleep(8);
    c.check("pinning the wrong certificate: dave cannot connect (even with a valid token)", !agents(18606).iter().any(|n| n == "alice"), agents(18606).join(","));
    dave.kill();
    let mut dave = Node::start(&work, "dave", "dave", 18606, &with(hard("dave", &root_pub), &["--connect", &url, "--pin-cert", &work.join("alice").join("tls.cert.pem").display().to_string()]));
    c.check("pinning alice's real certificate: dave connects", wait_sees(18606, "alice", 15), "");
    let r = rpc(18606, "SendMessage", json!({ "tenant": "bob", "message": msg("dave via a pinned link") }));
    c.check("dave (token: bob only) can task bob", completed(&r), r.to_string());
    dave.kill();

    // 5. revocation also closes the door
    let mut carol = Node::start(&work, "carol", "carol", 18603, &with(hard("carol", &root_pub), &["--connect", &url]));
    c.check("carol (valid token, TLS) joins", wait_sees(18603, "alice", 15), "");
    carol.kill();
    let revoke_file = work.join("carol-revoke.json");
    let (code, o) = run_tool("anp-admin", &strs(&["revoke", "--root", &work.join("root.key").display().to_string(), "--token", &work.join("carol.token").display().to_string(), "--reason", "tablet lost", "--out", &revoke_file.display().to_string()]));
    assert_eq!(code, 0, "anp-admin revoke: {o}");
    let (status, res) = post_json("http://127.0.0.1:18601/security/revocations", &std::fs::read_to_string(&revoke_file).map_err(|e| e.to_string())?);
    c.check("the authority's revocation is accepted", status == 200 && res["revoked"].as_str().map_or(false, |s| s.len() >= 32), res.to_string());
    let mut carol = Node::start(&work, "carol", "carol", 18603, &with(hard("carol", &root_pub), &["--connect", &url]));
    let r = rpc(18603, "SendMessage", json!({ "tenant": "bob", "message": msg("revoked carol tries again"), "configuration": { "returnImmediately": true } }));
    let ctid = r["result"]["task"]["id"].clone();
    sleep(8);
    c.check(
        "revoked carol cannot get her task out (it never reaches bob)",
        rpc(18603, "GetTask", json!({ "id": ctid }))["result"]["status"]["state"] == "TASK_STATE_SUBMITTED" && rpc(18602, "GetTask", json!({ "id": ctid }))["error"]["code"] == -32001,
        "",
    );
    c.check("alice logged the refused connection: token revoked", refused(18601, "connection", "carol", "revoked"), Value::Array(rejections(18601)).to_string());
    carol.kill();

    // 6. at rest
    println!("At rest");
    drop(bob);
    drop(alice);
    sleep(1);
    c.check("the secret text is NOT readable in alice's database files", file_contains(&work.join("alice"), MARKER).is_none(), "");
    c.check("the secret text is NOT readable in bob's database files", file_contains(&work.join("bob"), MARKER).is_none(), "");
    // control: the same search must find it in an unencrypted database, or it proves nothing
    std::env::remove_var("A2A_DB_KEY");
    let mut ctl = Node::start(&work, "ctl", "ctl", 18607, &[]);
    let _ = rpc(18607, "SendMessage", json!({ "message": msg(&format!("plain database: {MARKER}")) }));
    ctl.kill();
    sleep(1);
    c.check("CONTROL: the same text IS readable in an unencrypted database", file_contains(&work.join("ctl"), MARKER).is_some(), "");
    // wrong key
    std::env::set_var("A2A_DB_KEY", "wrong password");
    let bad = expect_exit(&work, "bad", &strs(&["--name", "alice", "--data", &work.join("alice").display().to_string(), "--http-port", "18601", "--db-key-env", "A2A_DB_KEY"]), 15);
    c.check("opening alice's database with the wrong key fails", bad.exited && bad.code != Some(0), format!("exited={} code={:?}", bad.exited, bad.code));
    Ok(c.finish())
}
