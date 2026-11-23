//! `cargo xtask e2e-cross-os`: two independent deployments, a node on this machine and a Linux node (built in WSL, see `scripts/linux-node-build.sh`),
//! in one mesh over the network (the host's address as WSL sees it, not loopback): DIDs, tokens bound to them, TLS with a pinned certificate,
//! connection admission, end-to-end encryption. The same checks as `scripts/e2e-cross-os.ps1`.
//!
//!   cargo xtask e2e-cross-os [--distro Ubuntu] [--linux-dir ~/anp-linux]

use crate::harness::*;
use crate::remote::{wsl_path, Remote};
use serde_json::{json, Value};

pub fn run(args: &[String]) -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let remote = Remote::Wsl { distro: opt(args, "--distro").unwrap_or_else(|| "Ubuntu".into()) };
    let linux_dir = opt(args, "--linux-dir").unwrap_or_else(|| "~/anp-linux".into());
    let work = work_dir("xtask-cross");
    fresh_dir(&work);
    let wsl_work = wsl_path(&work);
    let mut c = Checks::default();

    let route = remote.run("ip route show default");
    let host_ip = route.split("via ").nth(1).and_then(|r| r.split_whitespace().next()).ok_or_else(|| format!("no default route in WSL: {route}"))?.to_string();
    let env = remote.node_env(&linux_dir);
    remote.run("mkdir -p ~/x");
    println!("The Linux node runs on: {} ({})", remote.run("uname -sr"), remote.run("uname -m"));
    println!("Setup: DIDs and tokens (the authority is here; bob's token is made by the Linux admin tool)");

    let root_pub = root_key(&work, "root");
    let alice_did = did_for(&work, "alice", "alice.example.com", "alice");
    let second = |out: &str| out.split_whitespace().nth(1).unwrap_or_default().to_string();
    let bob_did = second(&remote.run(&format!("{env} rm -rf ~/x/cross-bob; ./anp-node --name bob --data ~/x/cross-bob --did-host bob.example.com --print-did")));
    c.check("the Linux node has a DID of the same form", bob_did.starts_with("did:wba:bob.example.com:agents:bob:e1_"), &bob_did);
    issue_token(&work, "root", "alice", "alice", Some(&alice_did), "bob");
    remote.run(&format!("{env} ./anp-admin issue --root {wsl_work}/root.key --node bob --node-dir ~/x/cross-bob --did {bob_did} --inbox-to alice --out {wsl_work}/bob.token"));
    c.check("both tokens exist", work.join("alice.token").exists() && work.join("bob.token").exists(), "");
    let (_, ins) = run_tool("anp-admin", &strs(&["inspect", "--root-pub", &root_pub, "--token", &work.join("bob.token").display().to_string()]));
    c.check("the local admin tool reads the token the Linux one made, bound to bob's DID", ins.contains(&bob_did), &ins);

    let start_bob = |extra: &str| {
        remote.spawn(&format!(
            "{env} ./anp-node --name bob --data ~/x/cross-bob --http-port 18802 --did-host bob.example.com --e2ee --agent reviewer --root-key {root_pub} --token {wsl_work}/bob.token --tls --admit {extra} > {wsl_work}/bob.out.txt 2> {wsl_work}/bob.err.txt"
        ))
    };
    let alice = Node::start(
        &work,
        "alice",
        "alice",
        18801,
        &strs(&["--did-host", "alice.example.com", "--e2ee", "--agent", "echo", "--root-key", &root_pub, "--token", &work.join("alice.token").display().to_string(), "--tls", "--admit"]),
    );
    let port = alice.p2p_port().ok_or("alice printed no P2P port")?;
    let connect = format!("--pin-cert {wsl_work}/alice/tls.cert.pem --connect wss://{host_ip}:{port}/a2a");
    let mut bob = start_bob(&connect);

    println!("Joining across the two systems");
    c.check("alice (here) sees bob (Linux)", wait_sees(18801, "bob", 40), "");
    c.check("bob (Linux) sees alice (here)", wait_sees(18802, "alice", 40), "");
    let (sa, sb) = (get_json("http://127.0.0.1:18801/security"), get_json("http://127.0.0.1:18802/security"));
    c.check("both run in did+biscuit mode with end-to-end encryption", sa["mode"] == "did+biscuit" && sb["mode"] == "did+biscuit" && sa["e2ee"] == true && sb["e2ee"] == true, format!("{} {}", sa["mode"], sb["mode"]));
    c.check("bob's DID is the one the Linux tool printed", sb["did"] == json!(bob_did), "");

    println!("Tasks both ways");
    let r = rpc(18801, "SendMessage", json!({ "tenant": "bob", "message": msg("Asset: boiler\nFindings: leak\nRisk: High\nAction: fix this week") }));
    c.check("alice -> bob: the Linux node's reviewer answers", completed(&r) && task_text(&r).contains("REVIEW"), r.to_string());
    let r = rpc(18802, "SendMessage", json!({ "tenant": "alice", "message": msg("hello from the Linux node") }));
    c.check("bob -> alice: this machine's echo agent answers", completed(&r), r.to_string());
    sleep(3);
    let (da, db) = (get_json("http://127.0.0.1:18801/discover"), get_json("http://127.0.0.1:18802/discover"));
    let find = |d: &Value, n: &str| d.as_array().and_then(|a| a.iter().find(|x| x["nodeId"] == n).cloned()).unwrap_or(Value::Null);
    let (bob_seen, alice_seen) = (find(&da, "bob"), find(&db, "alice"));
    c.check("this machine verified the Linux node's signed agent description", bob_seen["descriptionVerified"] == true && bob_seen["did"] == json!(bob_did), da.to_string());
    c.check("the Linux node verified this machine's signed agent description", alice_seen["descriptionVerified"] == true && alice_seen["did"] == json!(alice_did), db.to_string());
    c.check("nothing was refused on either side during normal operation", rejections(18801).is_empty() && rejections(18802).is_empty(), "");

    println!("Scoping (alice's token lets her message bob only; bob's lets him message alice only)");
    let r = rpc(18802, "SendMessage", json!({ "tenant": "nobody", "message": msg("x") }));
    c.check("bob cannot address anyone his token does not allow", !r["error"].is_null(), r.to_string());

    println!("An unauthorised Linux node");
    let fake_pub = root_key(&work, "fake");
    let mal_did = second(&remote.run(&format!("{env} rm -rf ~/x/cross-mal; ./anp-node --name mal --data ~/x/cross-mal --did-host mal.example.com --print-did")));
    remote.run(&format!("{env} ./anp-admin issue --root {wsl_work}/fake.key --node mal --node-dir ~/x/cross-mal --did {mal_did} --inbox-to '*' --out {wsl_work}/mal.token"));
    let mal = remote.spawn(&format!(
        "{env} ./anp-node --name mal --data ~/x/cross-mal --http-port 18809 --did-host mal.example.com --root-key {fake_pub} --token {wsl_work}/mal.token --tls --admit {connect} > {wsl_work}/mal.out.txt 2> {wsl_work}/mal.err.txt"
    ));
    sleep(10);
    c.check("a Linux node with another authority's token never sees alice", !agents(18809).iter().any(|n| n == "alice"), "");
    c.check("alice logged the refused connection", refused(18801, "connection", "mal", ""), Value::Array(rejections(18801)).to_string());
    remote.pkill("[a]np-node --name mal");
    drop(mal);

    println!("The Linux node restarts");
    remote.pkill("[a]np-node --name bob");
    drop(bob);
    sleep(3);
    bob = start_bob(&connect);
    c.check("bob rejoins from its stored state (same DID, same token)", wait_sees(18802, "alice", 40), "");
    let r = rpc(18801, "SendMessage", json!({ "tenant": "bob", "message": msg("Asset: roof\nFindings: fine\nRisk: Low\nAction: none") }));
    c.check("and a task still goes alice -> bob", completed(&r), r.to_string());

    remote.pkill("[a]np-node --name");
    drop((bob, alice));
    Ok(c.finish())
}
