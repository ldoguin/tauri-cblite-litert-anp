//! `cargo xtask cold-rescue [--record OUT.mp4 | --hold SECONDS]`: the cold-stock rescue demo. Brings up the night's ten nodes (the store with its cold room,
//! buying desk and agent; eight companies on their own HTTPS origins; a group host) and a search agent the companies register with, and opens
//! nothing: it prints the control room's address. The store's agent finds the companies through the search agent (see `e2e-discovery`).
//!
//! * Without `--record` it waits: open `http://127.0.0.1:19102/demo/rescue` and drive the night with the page's buttons, or add
//!   `?autoplay=1` to watch it play with captions. Press Enter to stop every node.
//! * With `--record OUT.mp4` it films the autoplay in a headless browser, with an explainer under each caption and intro and outro
//!   cards (`scripts/video/record.mjs`; needs Node 22+, Chrome or Edge, and ffmpeg), then stops.

use crate::harness::*;
use crate::rescue::{bring_up_discovered, STORE_PORT};

pub fn run(args: &[String]) -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin", "anp-search"])?;
    let work = work_dir("cold-rescue");
    fresh_dir(&work);
    // the realistic night: the companies register with a search agent and the store finds them there, every DID over HTTPS
    let mut night = bring_up_discovered(&work)?;
    if night.token_issued.0 != 0 {
        return Err(format!("the store's spending token was not issued: {}", night.token_issued.1));
    }
    let url = format!("http://127.0.0.1:{STORE_PORT}/demo/rescue");
    let ready = poll(60, 500, || get_json(&format!("http://127.0.0.1:{STORE_PORT}/rescue"))["phase"] == "idle");
    let stop = |night: &mut crate::rescue::Night| {
        night.store.kill();
        for n in &mut night.others {
            n.kill();
        }
    };
    if !ready {
        stop(&mut night);
        return Err("the store's agent did not come up".into());
    }
    sleep(4); // the companies publish their key packages to the group host
    let code = match opt(args, "--record") {
        Some(out) => {
            let out = std::path::PathBuf::from(out);
            let out = if out.is_absolute() { out } else { std::env::current_dir().map_err(|e| e.to_string())?.join(out) };
            println!("recording the night to {}", out.display());
            let status = std::process::Command::new("node")
                .current_dir(repo_root().join("anp"))
                .args(["scripts/video/record.mjs", "--url", &format!("{url}?autoplay=1"), "--out"])
                .arg(&out)
                .args(["--intro", "rescue-intro", "--outro", "rescue-outro", "--explainers", "rescue-explainers.js", "--max-secs", "600"])
                .status()
                .map_err(|e| format!("node (Node 22+ is needed to record): {e}"));
            match status {
                Ok(s) => s.code().unwrap_or(1),
                Err(e) => {
                    stop(&mut night);
                    return Err(e);
                }
            }
        }
        None => {
            println!("\nthe control room:  {url}\n  drive the night with its buttons, or open {url}?autoplay=1 to watch it play");
            match opt(args, "--hold").and_then(|s| s.parse::<u64>().ok()) {
                // run unattended (no console to press Enter in) for that many seconds
                Some(secs) => {
                    println!("holding for {secs} s");
                    sleep(secs);
                }
                None => {
                    println!("press Enter to stop the ten nodes");
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                }
            }
            0
        }
    };
    stop(&mut night);
    Ok(code)
}
