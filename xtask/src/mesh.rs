//! `cargo xtask e2e`, `e2e-secure`, `e2e-biscuit`: two `anp-node` processes replicate peer to peer; every request goes to alice and is routed to bob
//! through Couchbase Lite. Plain, with signed documents and a key list (`--secure`: two outsiders try to get in), or with Biscuit tokens from one
//! authority (carol holds a real token that only lets her message bob). The same checks as `scripts/e2e.ps1`.

use crate::harness::*;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Plain,
    Secure,
    Biscuit,
}

struct Setup {
    mode: Mode,
    work: std::path::PathBuf,
    root_pub: String,
}

impl Setup {
    /// The command-line security options of one node.
    fn sec(&self, node: &str) -> Vec<String> {
        match self.mode {
            Mode::Biscuit => strs(&["--root-key", &self.root_pub, "--token", &self.work.join(format!("{node}.token")).display().to_string()]),
            Mode::Secure => strs(&["--trust", &self.work.join("trust.json").display().to_string()]),
            Mode::Plain => vec![],
        }
    }
}

fn trust_file(work: &Path, file: &str, names: &[&str]) {
    let nodes: serde_json::Map<String, Value> = names.iter().map(|n| (n.to_string(), json!(pubkey_of(work, n)))).collect();
    std::fs::write(work.join(file), json!({ "nodes": nodes }).to_string()).expect("write the trust list");
}

fn issue(work: &Path, root: &str, node: &str, inbox_to: &str) {
    let (code, out) = run_tool("anp-admin", &strs(&["issue", "--root", &work.join(format!("{root}.key")).display().to_string(), "--node", node, "--node-dir", &work.join(node).display().to_string(), "--inbox-to", inbox_to, "--out", &work.join(format!("{node}.token")).display().to_string()]));
    assert_eq!(code, 0, "anp-admin issue: {out}");
}

fn state(r: &Value) -> Value {
    r["result"]["task"]["status"]["state"].clone()
}

fn task_state(port: u16, id: &Value) -> Value {
    rpc(port, "GetTask", json!({ "id": id }))["result"]["status"]["state"].clone()
}

fn poll(tries: u32, every_ms: u64, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..tries {
        std::thread::sleep(std::time::Duration::from_millis(every_ms));
        if f() {
            return true;
        }
    }
    false
}

fn list_total(port: u16) -> Value {
    rpc(port, "ListTasks", json!({}))["result"]["totalSize"].clone()
}

fn security(port: u16) -> Value {
    get_json(&format!("http://127.0.0.1:{port}/security"))
}

fn revoked(port: u16, id: &str) -> bool {
    security(port)["revokedTokens"].as_array().map_or(false, |a| a.iter().any(|x| x == id))
}

pub fn run(mode: Mode) -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    if mode == Mode::Biscuit {
        require_bins(&["anp-admin"])?;
    }
    let tag = match mode {
        Mode::Plain => "xtask-e2e",
        Mode::Secure => "xtask-e2e-secure",
        Mode::Biscuit => "xtask-e2e-biscuit",
    };
    let work = work_dir(tag);
    fresh_dir(&work);
    let mut c = Checks::default();
    let mut s = Setup { mode, work: work.clone(), root_pub: String::new() };
    let secure = mode != Mode::Plain;
    let mut fake_pub = String::new();

    if mode == Mode::Biscuit {
        println!("BISCUIT MODE: authority, node keys and tokens");
        s.root_pub = root_key(&work, "root"); // the real mesh authority
        fake_pub = root_key(&work, "fake"); // an impostor authority (mallory's)
        for n in ["alice", "bob", "carol", "mallory"] {
            pubkey_of(&work, n); // creates each node's key
        }
        issue(&work, "root", "alice", "*");
        issue(&work, "root", "bob", "*");
        issue(&work, "root", "carol", "bob"); // carol may only message bob
        issue(&work, "fake", "mallory", "*"); // signed by the impostor authority
    } else if mode == Mode::Secure {
        println!("SECURE MODE: generating keys and trust lists");
        trust_file(&work, "trust.json", &["alice", "bob"]); // alice and bob trust only each other
        trust_file(&work, "trust-mallory.json", &["alice", "bob"]); // mallory trusts them, they do not trust her
    }

    println!("Starting alice and bob");
    let alice = Node::start(&work, "alice", "alice", 18081, &s.sec("alice"));
    let port = alice.p2p_port().ok_or("alice printed no P2P port")?;
    let connect = vec!["--connect".to_string(), format!("ws://127.0.0.1:{port}/a2a")];
    let mut bob = Node::start(&work, "bob", "bob", 18082, &[connect.clone(), s.sec("bob")].concat());

    if secure {
        let sec = security(18081);
        if mode == Mode::Biscuit {
            c.check("alice reports Biscuit mode", sec["secure"] == true && sec["mode"] == "biscuit", sec.to_string());
        } else {
            let enrolled = sec["enrolled"].as_array().cloned().unwrap_or_default();
            c.check("alice reports secure mode with bob enrolled", sec["secure"] == true && enrolled.iter().any(|e| e == "bob") && !enrolled.iter().any(|e| e == "mallory"), sec.to_string());
        }
    }

    // ── discovery: agent cards replicate ──
    println!("Discovery");
    let ok = poll(50, 300, || agents(18081).iter().any(|n| n == "bob"));
    c.check("alice learns bob's card over P2P", ok, "");
    let card = get_json("http://127.0.0.1:18081/agents/bob/agent-card.json");
    c.check("peer card is rewritten to alice's gateway + tenant", card["supportedInterfaces"][0]["tenant"] == "bob" && card["supportedInterfaces"][0]["url"].as_str().map_or(false, |u| u.contains("18081")), card.to_string());

    // ── routed SendMessage (blocking) ──
    println!("SendMessage alice -> bob");
    let r = rpc(18081, "SendMessage", json!({ "tenant": "bob", "message": msg("hello from alice") }));
    let t = r["result"]["task"].clone();
    c.check("task COMPLETED", state(&r) == "TASK_STATE_COMPLETED", r.to_string());
    let streamed: String = t["artifacts"][0]["parts"].as_array().into_iter().flatten().filter_map(|p| p["text"].as_str()).collect();
    c.check("artifact streamed back through replication", streamed == "hello from alice", &streamed);
    let rb = rpc(18082, "GetTask", json!({ "id": t["id"] }));
    c.check("bob (owner) has the task too", rb["result"]["id"] == t["id"], rb.to_string());
    c.check("ListTasks on origin", list_total(18081).as_i64().unwrap_or(0) >= 1, "");

    // ── local (no tenant) ──
    println!("SendMessage local");
    let r = rpc(18081, "SendMessage", json!({ "message": msg("local run") }));
    c.check("alice runs its own task", state(&r) == "TASK_STATE_COMPLETED", r.to_string());

    // ── input-required round trip ──
    println!("INPUT_REQUIRED");
    let r = rpc(18081, "SendMessage", json!({ "tenant": "bob", "message": msg("ask") }));
    c.check("INPUT_REQUIRED", state(&r) == "TASK_STATE_INPUT_REQUIRED", r.to_string());
    let tid = r["result"]["task"]["id"].clone();
    let r = rpc(18081, "SendMessage", json!({ "message": msg_for("forty two", &tid) }));
    c.check("follow-up completes the same task", r["result"]["task"]["id"] == tid && state(&r) == "TASK_STATE_COMPLETED", r.to_string());
    c.check("history holds both user turns + agent question", r["result"]["task"]["history"].as_array().map_or(0, |h| h.len()) >= 3, "");

    // ── streaming ──
    println!("SendStreamingMessage");
    let events = sse_events(18081, json!({ "tenant": "bob", "message": msg("one two three four") }), 20);
    let kinds: Vec<String> = events.iter().filter_map(|e| e["result"].as_object().and_then(|o| o.keys().next().cloned())).collect();
    c.check("first event is the task", kinds.first().map_or(false, |k| k == "task"), kinds.join(","));
    c.check("artifactUpdate events arrive", kinds.iter().filter(|k| *k == "artifactUpdate").count() >= 2, kinds.join(","));
    c.check("stream ends with COMPLETED statusUpdate", events.last().map_or(false, |e| e["result"]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"), "");

    // ── cancel ──
    println!("CancelTask");
    let r = rpc(18081, "SendMessage", json!({ "tenant": "bob", "message": msg("slow"), "configuration": { "returnImmediately": true } }));
    let tid = r["result"]["task"]["id"].clone();
    c.check("returnImmediately gives a non-terminal task", state(&r) == "TASK_STATE_SUBMITTED" || state(&r) == "TASK_STATE_WORKING", r.to_string());
    std::thread::sleep(std::time::Duration::from_millis(800));
    let cc = rpc(18081, "CancelTask", json!({ "id": tid }));
    c.check("remote task canceled", cc["result"]["status"]["state"] == "TASK_STATE_CANCELED", cc.to_string());
    let c2 = rpc(18081, "CancelTask", json!({ "id": tid }));
    c.check("cancel of terminal task -> -32002", c2["error"]["code"] == -32002, c2.to_string());

    // ── errors ──
    println!("Errors");
    c.check("unknown task -> -32001", rpc(18081, "GetTask", json!({ "id": "nope" }))["error"]["code"] == -32001, "");
    c.check("unknown method -> -32601", rpc(18081, "Nope", json!({}))["error"]["code"] == -32601, "");
    c.check("unknown tenant -> -32602", rpc(18081, "SendMessage", json!({ "tenant": "zed", "message": msg("x") }))["error"]["code"] == -32602, "");

    // ── outsiders (secure modes only) ──
    let mut carol: Option<Node> = None;
    if secure {
        println!("Outsiders: mallory (not enrolled) and legacy (unsigned) dial alice");
        let tasks_before = list_total(18081);
        let mal_args = if mode == Mode::Biscuit { strs(&["--root-key", &fake_pub, "--token", &work.join("mallory.token").display().to_string()]) } else { strs(&["--trust", &work.join("trust-mallory.json").display().to_string()]) };
        let mut mallory = Node::start(&work, "mallory", "mallory", 18083, &[connect.clone(), mal_args].concat());
        let mut legacy = Node::start(&work, "legacy", "legacy", 18084, &connect);
        let seen = if mode == Mode::Biscuit {
            // mallory trusts only her own (fake) authority, so she cannot read alice's cards; her connection is proven by alice receiving, and
            // refusing, her documents
            let seen = poll(60, 300, || {
                let _ = agents(18081); // a document is only checked when it is read
                rejections(18081).iter().any(|r| r["author"] == "mallory")
            });
            c.check("mallory is connected and replicating (alice has received and refused her documents)", seen, "");
            seen
        } else {
            // mallory trusts alice, so she must see alice: proves she is connected and replicating
            let seen = poll(60, 300, || agents(18083).iter().any(|n| n == "alice"));
            c.check("mallory is connected and sees alice (so any refusal is about trust, not connectivity)", seen, "");
            seen
        };
        let _ = seen;
        let rm = rpc(18083, "SendMessage", json!({ "tenant": "alice", "message": msg("mallory wants to run something"), "configuration": { "returnImmediately": true } }));
        let rl = rpc(18084, "SendMessage", json!({ "tenant": "alice", "message": msg("legacy wants to run something"), "configuration": { "returnImmediately": true } }));
        sleep(6);
        let mut actors: Vec<(&str, u16, Value)> = vec![("legacy", 18084, rl)];
        if mode == Mode::Biscuit {
            // trusting only her own authority, mallory cannot verify alice's card, so she cannot even address her
            c.check("mallory cannot address alice (her authority does not vouch for alice's card)", rm["error"]["code"] == -32602, rm.to_string());
        } else {
            actors.insert(0, ("mallory", 18083, rm));
        }
        for (name, p, r) in &actors {
            let tid = r["result"]["task"]["id"].clone();
            c.check(&format!("{name}'s task never ran (still SUBMITTED on {name})"), task_state(*p, &tid) == "TASK_STATE_SUBMITTED", "");
            c.check(&format!("alice has no record of {name}'s task"), rpc(18081, "GetTask", json!({ "id": tid }))["error"]["code"] == -32001, "");
            c.check("bob has no record of it either", task_state(18082, &tid) != "TASK_STATE_COMPLETED", "");
        }
        c.check("alice's task list is unchanged", list_total(18081) == tasks_before, "");
        for p in [18081u16, 18082] {
            let names = agents(p);
            c.check(&format!("node on :{p} does not list mallory or legacy as agents"), !names.iter().any(|n| n == "mallory" || n == "legacy"), names.join(","));
        }
        for p in [18081u16, 18082] {
            let rej = rejections(p);
            let (why, label) = if mode == Mode::Biscuit { ("credential refused", "token from a fake authority") } else { ("not enrolled", "not enrolled") };
            let found = rej.iter().any(|r| r["author"] == "mallory" && r["reason"].as_str().map_or(false, |s| if mode == Mode::Biscuit { s.starts_with(why) } else { s.contains(why) }));
            c.check(&format!("node on :{p} logged mallory ({label})"), found, Value::Array(rej.clone()).to_string());
            c.check(&format!("node on :{p} logged legacy's documents as unsigned"), rej.iter().any(|r| r["reason"] == "unsigned document"), "");
        }
        mallory.kill();
        legacy.kill();

        // ── carol: a genuine token, but only for bob (Biscuit mode) ──
        if mode == Mode::Biscuit {
            println!("Scoped token: carol may message bob, not alice");
            let mut cn = Node::start(&work, "carol", "carol", 18085, &[connect.clone(), s.sec("carol")].concat());
            let sees = poll(80, 300, || {
                let n = agents(18085);
                n.iter().any(|x| x == "alice") && n.iter().any(|x| x == "bob")
            });
            c.check("carol's token is accepted: she joins the mesh and sees alice and bob", sees, agents(18085).join(","));
            c.check("alice lists carol as an agent", agents(18081).iter().any(|n| n == "carol"), "");
            let r = rpc(18085, "SendMessage", json!({ "tenant": "bob", "message": msg("carol asks bob") }));
            c.check("carol -> bob COMPLETES (her token allows bob)", state(&r) == "TASK_STATE_COMPLETED", r.to_string());
            let r = rpc(18085, "SendMessage", json!({ "tenant": "alice", "message": msg("carol asks alice"), "configuration": { "returnImmediately": true } }));
            let ctid = r["result"]["task"]["id"].clone();
            sleep(6);
            c.check("carol -> alice never runs (her token does not allow alice)", task_state(18085, &ctid) == "TASK_STATE_SUBMITTED", "");
            c.check("alice has no record of that task", rpc(18081, "GetTask", json!({ "id": ctid }))["error"]["code"] == -32001, "");
            let rej = rejections(18081);
            c.check("alice logged carol's command: credential refused", rej.iter().any(|r| r["author"] == "carol" && r["collection"] == "inbox" && r["reason"].as_str().map_or(false, |s| s.starts_with("credential refused"))), Value::Array(rej).to_string());
            cn.kill();
        }
    }

    // ── store and forward: bob offline ──
    println!("Store-and-forward (bob offline)");
    bob.kill();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let r = rpc(18081, "SendMessage", json!({ "tenant": "bob", "message": msg("sent while bob was away"), "configuration": { "returnImmediately": true } }));
    let tid = r["result"]["task"]["id"].clone();
    c.check("alice accepts it as SUBMITTED", state(&r) == "TASK_STATE_SUBMITTED", r.to_string());
    sleep(2);
    c.check("still SUBMITTED while bob is down", task_state(18081, &tid) == "TASK_STATE_SUBMITTED", "");

    // ── revocation, issued while bob is offline (Biscuit mode) ──
    let mut cid = String::new();
    if mode == Mode::Biscuit {
        println!("Revocation of carol's token while bob is offline");
        let (_, insp) = run_tool("anp-admin", &strs(&["inspect", "--root-pub", &s.root_pub, "--token", &work.join("carol.token").display().to_string()]));
        cid = insp.split_once("revocation ids:").map(|(_, rest)| rest.trim_start().chars().take_while(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()).collect()).unwrap_or_default();
        c.check("carol's token has a revocation id", cid.len() >= 32, &insp);
        // an impostor authority tries to revoke carol (or anyone): refused
        let forged = work.join("forged-revoke.json");
        run_tool("anp-admin", &strs(&["revoke", "--root", &work.join("fake.key").display().to_string(), "--id", &cid, "--reason", "forged", "--out", &forged.display().to_string()]));
        let (code, _) = post_json("http://127.0.0.1:18081/security/revocations", &std::fs::read_to_string(&forged).unwrap_or_default());
        c.check("a revocation signed by a fake authority is refused (HTTP 400)", code == 400, code.to_string());
        c.check("...and nothing was revoked", security(18081)["revokedTokens"].as_array().map_or(0, |a| a.len()) == 0, "");
        // the real authority revokes it
        let real = work.join("carol-revoke.json");
        run_tool("anp-admin", &strs(&["revoke", "--root", &work.join("root.key").display().to_string(), "--token", &work.join("carol.token").display().to_string(), "--reason", "tablet lost", "--out", &real.display().to_string()]));
        let (code, res) = post_json("http://127.0.0.1:18081/security/revocations", &std::fs::read_to_string(&real).unwrap_or_default());
        c.check("alice accepts the authority's revocation", code == 200 && res["revoked"] == json!(cid), res.to_string());
        c.check("alice now lists the token as revoked", revoked(18081, &cid), "");
    }
    let bob = Node::start(&work, "bob", "bob", 18082, &[connect.clone(), s.sec("bob")].concat()); // same data dir: resumes where it left off
    let done = poll(60, 500, || task_state(18081, &tid) == "TASK_STATE_COMPLETED");
    c.check("bob comes back, pulls the inbox, completes it", done, "");

    if mode == Mode::Biscuit {
        // bob was offline when the revocation was issued: he must learn of it by syncing
        let learned = poll(60, 400, || revoked(18082, &cid));
        c.check("bob, offline when it was issued, learns the revocation after syncing", learned, "");

        println!("Revoked carol comes back");
        let mut cn = Node::start(&work, "carol", "carol", 18085, &[connect.clone(), s.sec("carol")].concat());
        sleep(8);
        for p in [18081u16, 18082] {
            let n = agents(p);
            c.check(&format!("node on :{p} no longer lists carol (her earlier card is not served from a saved copy)"), !n.iter().any(|x| x == "carol"), n.join(","));
        }
        let r = rpc(18085, "SendMessage", json!({ "tenant": "bob", "message": msg("revoked carol tries bob"), "configuration": { "returnImmediately": true } }));
        let rtid = r["result"]["task"]["id"].clone();
        sleep(6);
        c.check("revoked carol's task to bob never runs", task_state(18085, &rtid) == "TASK_STATE_SUBMITTED", "");
        c.check("bob has no record of it", rpc(18082, "GetTask", json!({ "id": rtid }))["error"]["code"] == -32001, "");
        let rej = rejections(18082);
        c.check("bob logged carol: token revoked", rej.iter().any(|r| r["author"] == "carol" && r["reason"].as_str().map_or(false, |s| s.contains("revoked"))), Value::Array(rej).to_string());
        cn.kill();
    }
    carol.take();
    drop((alice, bob));
    Ok(c.finish())
}
