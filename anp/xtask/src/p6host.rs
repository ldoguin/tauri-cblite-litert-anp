//! `cargo xtask p6-host`: this project's MLS devices (alice, bob, carol, dave, erin, frank) use the node's P6 group host over HTTP with signed
//! requests (ANP-02): the live tests of `crates/anp-group-host/tests/node_live.rs` against a node started here. The part of
//! `scripts/e2e-p6-host.ps1` where the official Rust SDK is a device (it runs in WSL) is not in this task.

use crate::harness::*;
use std::process::Stdio;

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let work = work_dir("xtask-p6");
    fresh_dir(&work);
    let mut c = Checks::default();
    // the devices' public DID documents, for the node to be started with
    let st = cargo_cmd().args(["test", "-q", "-p", "anp-group-host", "--test", "node_live", "live_docs"]).env("ANP_P6_STEP", "docs").env("ANP_P6_DIR", &work).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("could not write the devices' DID documents".into());
    }
    let port = 18950u16;
    let origin = format!("http://127.0.0.1:{port}");
    let mut extra: Vec<String> = ["--did-host", "groups.example", "--public-origin", &origin, "--require-auth", "--p6-host"].iter().map(|s| s.to_string()).collect();
    for f in std::fs::read_dir(&work).map_err(|e| e.to_string())?.flatten() {
        if f.file_name().to_string_lossy().ends_with(".did.json") {
            extra.push("--allow-caller".into());
            extra.push(f.path().display().to_string());
        }
    }
    let mut node = Node::start(&work, "grp", "node", port, &extra);
    sleep(2);
    let out = cargo_cmd()
        .args(["test", "-q", "-p", "anp-group-host", "--test", "node_live", "live_", "--", "--nocapture", "--test-threads=1"])
        .env("ANP_P6_STEP", "run")
        .env("ANP_P6_URL", &origin)
        .env("ANP_P6_SIGN", "1")
        .output()
        .map_err(|e| e.to_string())?;
    node.kill();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    c.check(
        "devices create/add/send/remove through the node's P6 host over signed HTTP; two devices of one DID; a held pull; the WebSocket push channel; roster/policy hashes, the member cap, the signed group state",
        text.contains("test result: ok. 6 passed"),
        format!("\n{text}\n--- node log\n{}", std::fs::read_to_string(work.join("node.err.txt")).unwrap_or_default()),
    );
    c.note("the official SDK as a device (WSL) is in scripts/e2e-p6-host.ps1, not here");
    Ok(c.finish())
}