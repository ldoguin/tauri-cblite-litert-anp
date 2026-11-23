//! `cargo xtask e2e-second-host`: the P6 group host and a two-node mesh against a node on another host, reached over ssh (key or agent, no
//! password prompt). The same checks as `scripts/e2e-second-host.ps1`.
//!
//!   cargo xtask e2e-second-host --remote-host me@box --remote-addr box [--remote-dir ~/anp-linux] [--ssh-port 22] [--identity KEY]
//!                               [--known-hosts FILE] [--port 18950] [--mesh-http-port 18802] [--mesh-p2p-port 18803] [--skip-mesh]
//!
//! Part 1: all the live tests of `crates/anp-group-host/tests/node_live.rs` (HTTP, the WebSocket push channel, state hashes, the member cap, two
//! devices of one DID, a held pull) against the remote node. Part 2: the node here (alice) dials the remote one (bob): DIDs and tokens bound to
//! them, TLS with a pinned certificate, admission, encryption, tasks both ways, descriptions verified, scoping, an unauthorised node refused, and
//! the remote node restarted. The remote needs the node built there (`scripts/linux-node-build.sh`), and its ports reachable from here.

use crate::harness::*;
use crate::remote::Remote;
use serde_json::{json, Value};
use std::process::Stdio;

pub fn run(args: &[String]) -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let host = opt(args, "--remote-host").ok_or("--remote-host is required (ssh target, e.g. me@box)")?;
    let addr = opt(args, "--remote-addr").ok_or("--remote-addr is required (the name or address this machine reaches the node at)")?;
    let dir = opt(args, "--remote-dir").unwrap_or_else(|| "~/anp-linux".into());
    let num = |k: &str, d: u16| opt(args, k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let (port, mesh_http, mesh_p2p) = (num("--port", 18950), num("--mesh-http-port", 18802), num("--mesh-p2p-port", 18803));
    let remote = Remote::Ssh { host: host.clone(), port: num("--ssh-port", 22), identity: opt(args, "--identity"), known_hosts: opt(args, "--known-hosts") };
    let work = work_dir("xtask-p6remote");
    fresh_dir(&work);
    let mut c = Checks::default();

    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let rtime = remote.run("uname -sr; uname -m; date -u +%s");
    println!("Remote: {}", rtime.replace('\n', " "));
    if let Some(rs) = rtime.lines().last().and_then(|l| l.trim().parse::<i64>().ok()) {
        println!("Clock difference (remote - here): {} s", rs - now_secs);
    }
    let env = remote.node_env(&dir);

    // ── part 1: the P6 host ──
    let st = cargo_cmd().args(["test", "-q", "-p", "anp-group-host", "--test", "node_live", "live_docs"]).env("ANP_P6_STEP", "docs").env("ANP_P6_DIR", &work).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("could not write the devices' DID documents".into());
    }
    remote.run("rm -rf ~/x/p6remote && mkdir -p ~/x/p6remote/docs");
    let mut docs = String::new();
    for f in std::fs::read_dir(&work).map_err(|e| e.to_string())?.flatten() {
        let name = f.file_name().to_string_lossy().to_string();
        if name.ends_with(".did.json") {
            remote.put(&f.path(), "~/x/p6remote/docs/");
            docs.push_str(&format!(" --allow-caller ~/x/p6remote/docs/{name}"));
        }
    }
    let origin = format!("http://{addr}:{port}");
    let p6 = remote.spawn(&format!("{env} ./anp-node --name grp --data ~/x/p6remote/node --http-port {port} --did-host groups.example --public-origin {origin} --require-auth --group-host{docs} > ~/x/p6remote/node.out 2> ~/x/p6remote/node.err"));
    sleep(5);
    let out = cargo_cmd()
        .args(["test", "-q", "-p", "anp-group-host", "--test", "node_live", "live_", "--", "--nocapture", "--test-threads=1"])
        .env("ANP_P6_STEP", "run")
        .env("ANP_P6_URL", &origin)
        .env("ANP_P6_SIGN", "1")
        .output()
        .map_err(|e| e.to_string())?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let detail = if text.contains("test result: ok. 6 passed") { String::new() } else { format!("\n{text}\n--- remote node log\n{}", remote.run("tail -20 ~/x/p6remote/node.err")) };
    c.check(
        &format!("the group host on {host}: create/add/send/remove over signed HTTP across the network, two devices of one DID, a held pull, the WebSocket push channel (signed upgrade, push, ack), roster/policy hashes, the member cap and the signed group state"),
        detail.is_empty(),
        detail,
    );
    remote.pkill("[a]np-node --name grp");
    drop(p6);

    // ── part 2: the mesh ──
    if !flag(args, "--skip-mesh") {
        mesh(&mut c, &remote, &addr, &env, &work, mesh_http, mesh_p2p)?;
    }
    Ok(c.finish())
}

fn mesh(c: &mut Checks, remote: &Remote, addr: &str, env: &str, work: &std::path::Path, mesh_http: u16, mesh_p2p: u16) -> Result<(), String> {
    println!("Mesh: this machine's node (alice) dials the remote node (bob)");
    let m = work.join("mesh");
    std::fs::create_dir_all(&m).map_err(|e| e.to_string())?;
    let (local, rbase) = ("http://127.0.0.1:18801".to_string(), format!("http://{addr}:{mesh_http}"));
    let second = |out: &str| out.split_whitespace().nth(1).unwrap_or_default().to_string();

    remote.pkill("[a]np-node --name bob");
    remote.run("rm -rf ~/x/mesh && mkdir -p ~/x/mesh");
    let root_pub = root_key(&m, "root");
    remote.put(&m.join("root.key"), "~/x/mesh/root.key"); // a test root key: it goes to the remote only so the remote admin tool can issue bob's token
    let alice_did = did_for(&m, "alice", "alice.example.com", "alice");
    let bob_did = second(&remote.run(&format!("{env} ./anp-node --name bob --data ~/x/mesh/bob --did-host bob.example.com --print-did")));
    c.check("the remote node has a DID of the same form", bob_did.starts_with("did:wba:bob.example.com:agents:bob:e1_"), &bob_did);
    issue_token(&m, "root", "alice", "alice", Some(&alice_did), "bob");
    remote.run(&format!("{env} ./anp-admin issue --root ~/x/mesh/root.key --node bob --node-dir ~/x/mesh/bob --did {bob_did} --inbox-to alice --out ~/x/mesh/bob.token"));
    remote.get("~/x/mesh/bob.token", &m.join("bob.token"));
    let (_, ins) = run_tool("anp-admin", &strs(&["inspect", "--root-pub", &root_pub, "--token", &m.join("bob.token").display().to_string()]));
    c.check("this machine's admin tool reads the token the remote one made, bound to bob's DID", ins.contains(&bob_did), &ins);

    let start_bob = || remote.spawn(&format!("{env} ./anp-node --name bob --data ~/x/mesh/bob --http-port {mesh_http} --p2p-port {mesh_p2p} --did-host bob.example.com --e2ee --agent reviewer --root-key {root_pub} --token ~/x/mesh/bob.token --tls --admit > ~/x/mesh/bob.out 2> ~/x/mesh/bob.err"));
    let answers = || poll(60, 500, || get_json(&format!("{rbase}/security")).is_object());
    let bob_proc = start_bob();
    c.check("the remote node answers over the network", answers(), "");
    let cert = m.join("bob.tls.cert.pem");
    remote.get("~/x/mesh/bob/tls.cert.pem", &cert);
    let connect = strs(&["--pin-cert", &cert.display().to_string(), "--connect", &format!("wss://{addr}:{mesh_p2p}/a2a")]);
    let alice_args = |extra: &[String]| [strs(&["--did-host", "alice.example.com", "--e2ee", "--agent", "echo", "--root-key", &root_pub, "--token", &m.join("alice.token").display().to_string(), "--tls", "--admit"]), extra.to_vec()].concat();
    let mut alice = Node::start(&m, "alice", "alice", 18801, &alice_args(&connect));

    println!("Joining across the network");
    c.check("alice (here) sees bob (remote)", wait_sees_at(&local, "bob", 40), "");
    c.check("bob (remote) sees alice (here)", wait_sees_at(&rbase, "alice", 40), "");
    let (sa, sb) = (get_json(&format!("{local}/security")), get_json(&format!("{rbase}/security")));
    c.check("both run in did+biscuit mode with end-to-end encryption", sa["mode"] == "did+biscuit" && sb["mode"] == "did+biscuit" && sa["e2ee"] == true && sb["e2ee"] == true, format!("{} {}", sa["mode"], sb["mode"]));
    c.check("bob's DID is the one the remote tool printed", sb["did"] == json!(bob_did), "");

    println!("Tasks both ways");
    let r = rpc_url(&local, "SendMessage", json!({ "tenant": "bob", "message": msg("Asset: boiler\nFindings: leak\nRisk: High\nAction: fix this week") }), 60);
    c.check("alice -> bob: the remote node's reviewer answers", completed(&r) && task_text(&r).contains("REVIEW"), r.to_string());
    let r = rpc_url(&rbase, "SendMessage", json!({ "tenant": "alice", "message": msg("hello from the remote node") }), 60);
    c.check("bob -> alice: this machine's echo agent answers", completed(&r), r.to_string());
    sleep(3);
    let (da, db) = (get_json(&format!("{local}/discover")), get_json(&format!("{rbase}/discover")));
    let find = |d: &Value, n: &str| d.as_array().and_then(|a| a.iter().find(|x| x["nodeId"] == n).cloned()).unwrap_or(Value::Null);
    let (bob_seen, alice_seen) = (find(&da, "bob"), find(&db, "alice"));
    c.check("alice verified bob's signed agent description", bob_seen["descriptionVerified"] == true && bob_seen["did"] == json!(bob_did), da.to_string());
    c.check("bob verified alice's signed agent description", alice_seen["descriptionVerified"] == true && alice_seen["did"] == json!(alice_did), db.to_string());
    let rej = |base: &str| get_json(&format!("{base}/security"))["rejections"].as_array().cloned().unwrap_or_default();
    c.check("nothing was refused on either side during normal operation", rej(&local).is_empty() && rej(&rbase).is_empty(), "");

    println!("Scoping (alice's token lets her message bob only; bob's lets him message alice only)");
    let r = rpc_url(&rbase, "SendMessage", json!({ "tenant": "nobody", "message": msg("x") }), 60);
    c.check("bob cannot address anyone his token does not allow", !r["error"].is_null(), r.to_string());

    println!("An unauthorised node dials the remote node");
    let fake_pub = root_key(&m, "fake");
    let mal_did = did_for(&m, "mal", "mal.example.com", "mal");
    issue_token(&m, "fake", "mal", "mal", Some(&mal_did), "*");
    let mal_args = [strs(&["--did-host", "mal.example.com", "--root-key", &fake_pub, "--token", &m.join("mal.token").display().to_string(), "--tls", "--admit"]), connect.clone()].concat();
    let mut mal = Node::start(&m, "mal", "mal", 18809, &mal_args);
    sleep(10);
    c.check("a node with another authority's token never sees bob", !agents(18809).iter().any(|n| n == "bob"), "");
    c.check("bob never sees it either", !agents_at(&rbase).iter().any(|n| n == "mal"), "");
    let rj = rej(&rbase);
    c.check("bob logged the refused connection", rj.iter().any(|r| r["collection"] == "connection" && r["docId"] == "mal"), Value::Array(rj.clone()).to_string());
    mal.kill();

    println!("The remote node restarts");
    remote.pkill("[a]np-node --name bob");
    drop(bob_proc);
    sleep(3);
    let bob_proc = start_bob();
    c.check("the remote node is back from its stored state", answers(), "");
    // The listener keeps its TLS identity in its data folder, so a restart gives the same certificate and a dialler that pinned it can reconnect
    // by itself. (Both nodes still list each other from replicated data, so "seeing" proves nothing here: the real test is a task over the link.)
    let before = std::fs::read(&cert).unwrap_or_default();
    remote.get("~/x/mesh/bob/tls.cert.pem", &cert);
    c.check("the listener's certificate is the same after a restart", before == std::fs::read(&cert).unwrap_or_default(), "");
    let through = |secs: u64| {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            let r = rpc_url(&local, "SendMessage", json!({ "tenant": "bob", "message": msg("Asset: roof\nFindings: fine\nRisk: Low\nAction: none") }), 8);
            if completed(&r) {
                return true;
            }
            sleep(3);
        }
        false
    };
    let mut ok = through(120);
    if !ok {
        // not wanted: the dialler should have come back on its own; restarting it tells whether anything else is wrong
        c.note("alice's link did not come back by itself within 120 s; restarting alice");
        alice.kill();
        alice = Node::start(&m, "alice", "alice", 18801, &alice_args(&connect));
        wait_sees_at(&local, "bob", 40);
        let fell_back = through(60);
        c.check("the link came back by itself (without restarting alice)", false, "");
        ok = fell_back;
    }
    c.check("a task goes alice -> bob again after bob restarted (same DIDs, same tokens)", ok, "");
    let r = rpc_url(&rbase, "SendMessage", json!({ "tenant": "alice", "message": msg("after the restart") }), 20);
    c.check("and bob -> alice", completed(&r), r.to_string());

    remote.pkill("[a]np-node --name bob");
    drop((bob_proc, alice));
    Ok(())
}
