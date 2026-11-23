//! `cargo xtask e2e-field-did`: the field-inspection scenario (tablet, branch office, head office) on DID identities, on real nodes with the built-in
//! agents in place of the on-device model: did:wba identities, Biscuit tokens bound to them (the tablet may only message branch and hq), end-to-end
//! encrypted task text, TLS with a pinned certificate, connection admission, an encrypted database and a tablet that loses its signal.
//! The same checks as `scripts/e2e-field-did.ps1`.

use crate::harness::*;
use serde_json::{json, Value};

fn link(up: bool) {
    let _ = post_json("http://127.0.0.1:18801/link", &json!({ "up": up }).to_string());
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let work = work_dir("xtask-field");
    fresh_dir(&work);
    std::env::set_var("A2A_DB_KEY", "demo database password");
    let mut c = Checks::default();

    println!("Setup: DIDs, tokens bound to them (the tablet may only message branch and hq)");
    let root_pub = root_key(&work, "root");
    let fake_pub = root_key(&work, "fake");
    let did = |n: &str| did_for(&work, n, &format!("{n}.field.example.com"), n);
    for (root, node, to) in [("root", "tablet", "branch,hq"), ("root", "branch", "*"), ("root", "hq", "*"), ("fake", "mallory", "*")] {
        issue_token(&work, root, node, node, Some(&did(node)), to);
    }
    let hard = |n: &str, root: &str| strs(&["--did-host", &format!("{n}.field.example.com"), "--e2ee", "--root-key", root, "--token", &work.join(format!("{n}.token")).display().to_string(), "--tls", "--admit", "--db-key-env", "A2A_DB_KEY"]);
    let with = |a: Vec<String>, b: &[&str]| [a, strs(b)].concat();

    let branch = Node::start(&work, "branch", "branch", 18802, &with(hard("branch", &root_pub), &["--agent", "reviewer"]));
    let port = branch.p2p_port().ok_or("branch printed no P2P port")?;
    let url = format!("wss://127.0.0.1:{port}/a2a");
    let pin = work.join("branch").join("tls.cert.pem").display().to_string();
    let hq = Node::start(&work, "hq", "hq", 18803, &with(hard("hq", &root_pub), &["--agent", "claims", "--pin-cert", &pin, "--connect", &url]));
    let tablet = Node::start(&work, "tablet", "tablet", 18801, &with(hard("tablet", &root_pub), &["--agent", "echo", "--pin-cert", &pin, "--connect", &url]));
    c.check("the tablet sees the branch and head office", wait_sees(18801, "branch", 20) && wait_sees(18801, "hq", 20), "");

    println!("1. Connected");
    let sec = get_json("http://127.0.0.1:18801/security");
    c.check("the tablet runs in did+biscuit mode with end-to-end encryption", sec["mode"] == "did+biscuit" && sec["e2ee"] == true && sec["did"].as_str().map_or(false, |d| d.starts_with("did:wba:")), sec.to_string());
    sleep(3);
    let disc = get_json("http://127.0.0.1:18801/discover");
    let all = disc.as_array().cloned().unwrap_or_default();
    c.check(
        "every device is a DID, and the tablet has verified each one's signed description",
        all.len() == 3 && all.iter().all(|d| d["did"].as_str().map_or(false, |x| x.starts_with("did:wba:")) && d["descriptionVerified"] == true),
        disc.to_string(),
    );
    let note = "Asset: Plant room B, boiler 3\nFindings: Feed pipe corroded near the flange, small leak at the isolation valve\nRisk: High\nAction: Replace the flange this week";
    let r = rpc(18801, "SendMessage", json!({ "message": msg(note) }));
    let report = task_text(&r);
    c.check("the tablet writes the report on the device", completed(&r) && !report.is_empty(), r.to_string());
    let rv = rpc(18801, "SendMessage", json!({ "tenant": "branch", "message": msg(&report) }));
    let review = task_text(&rv);
    c.check("the branch reviews it (over TLS, sealed to the branch's key)", completed(&rv) && review.starts_with("REVIEW:"), &review);
    let hr = rpc(18801, "SendMessage", json!({ "tenant": "hq", "message": msg(&format!("{report}\n\n{review}")) }));
    let claim = task_text(&hr);
    c.check("head office answers (files it if approved)", claim.contains("CLAIM FILED") || claim.contains("NOT FILED"), &claim);

    println!("2. The signal is lost");
    link(false);
    sleep(2);
    c.check("the tablet reports its link as down", get_json("http://127.0.0.1:18801/link")["up"] == false, "");
    let r2 = rpc(18801, "SendMessage", json!({ "message": msg("Asset: Warehouse roof vent 12\nFindings: Seals look good, no water ingress\nRisk: Low\nAction: None") }));
    c.check("offline, the tablet still writes a report on the device", completed(&r2), r2.to_string());
    let q = rpc(18801, "SendMessage", json!({ "tenant": "branch", "message": msg(&task_text(&r2)), "configuration": { "returnImmediately": true } }));
    let qid = q["result"]["task"]["id"].clone();
    sleep(6);
    let st = rpc(18801, "GetTask", json!({ "id": qid }))["result"]["status"]["state"].clone();
    c.check("the report for the branch waits: queued, not lost", st == "TASK_STATE_SUBMITTED", st.to_string());

    println!("3. The signal returns");
    link(true);
    let done = poll(60, 1000, || rpc(18801, "GetTask", json!({ "id": qid }))["result"]["status"]["state"] == "TASK_STATE_COMPLETED");
    c.check("the queued report is delivered and reviewed after reconnecting", done, "");
    let rej: usize = [18801u16, 18802, 18803].iter().map(|p| rejections(*p).len()).sum();
    c.check("nothing was refused anywhere during normal operation (no false alarms)", rej == 0, rej.to_string());

    println!("4. An unauthorised device tries to join");
    let mut mallory = Node::start(&work, "mallory", "mallory", 18809, &with(hard("mallory", &fake_pub), &["--pin-cert", &pin, "--connect", &url]));
    sleep(10);
    c.check("a device with a token from another authority (bound to its own DID) sees nothing of the mesh", !agents(18809).iter().any(|n| n == "branch"), "");
    c.check("the branch logged the refused connection", refused(18802, "connection", "mallory", ""), Value::Array(rejections(18802)).to_string());
    let x = rpc(18801, "SendMessage", json!({ "tenant": "nobody", "message": msg("x") }));
    c.check("the tablet cannot be used to message anyone its token does not allow", !x["error"].is_null() || x.is_null(), x.to_string());
    mallory.kill();
    drop((branch, hq, tablet));
    Ok(c.finish())
}