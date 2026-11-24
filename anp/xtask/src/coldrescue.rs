//! `cargo xtask cold-rescue [--record OUT.mp4 | --hold SECONDS]`: the cold-stock rescue demo. Brings up the night's ten nodes (the store with its cold room,
//! buying desk and agent; eight companies on their own HTTPS origins; a group host) and a search agent the companies register with, and opens
//! nothing: it prints the control room's address. The store's agent finds the companies through the search agent (see `e2e-discovery`).
//!
//! * Without `--record` it waits: open `http://127.0.0.1:19102/demo/rescue` and drive the night with the page's buttons, or add
//!   `?autoplay=1` to watch it play with captions. Press Enter to stop every node.
//! * With `--record OUT.mp4` it films the autoplay in a headless browser, with an explainer under each caption and intro and outro
//!   cards (`scripts/video/record.mjs`; needs Node 22+, Chrome or Edge, and ffmpeg), then stops.

use crate::harness::*;
use crate::approval::purge_store_docs;
use crate::fleet::{http, put_user, ADMIN, DB};
use crate::rescue::{bring_up_discovered_fleet, FLEET_STORES, HQ, STORE_PORT};
use serde_json::json;

pub fn run(args: &[String]) -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin", "anp-search"])?;
    let work = work_dir("cold-rescue");
    fresh_dir(&work);
    let gateway = flag(args, "--gateway");
    let fleet = flag(args, "--fleet") || gateway;
    if gateway {
        // the stores and the head office replicate through Sync Gateway into Couchbase Server: the k3d fleet must be up (`cargo xtask fleet-up`)
        let up = http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false);
        if !up {
            return Err("--gateway needs the fleet: run `cargo xtask fleet-up` first".into());
        }
        purge_store_docs(); // what an earlier run left under these names, so this run's documents are new ones
        for (name, var) in [("store", "STORE"), ("store-b", "STORE_B"), ("store-c", "STORE_C")] {
            std::env::set_var(format!("ANP_DEMO_PW_{var}"), format!("pw-{name}"));
            put_user(name, &format!("pw-{name}"), &[format!("store.{name}")])?;
        }
        std::env::set_var("ANP_DEMO_PW_HQ", "pw-hq");
        put_user("hq", "pw-hq", &["*".to_string()])?;
    }
    // the realistic night: the companies register with a search agent and the store finds them there, every DID over HTTPS
    let mut night = bring_up_discovered_fleet(&work, &[], fleet, gateway)?;
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
    if fleet {
        // the same night at two other stores: their freezers fail and their agents start at a demo's pace. Each plan is over its 6,000 budget, so each waits for a duty manager (nobody answers) and commits nothing: a store that committed first would take the carrier and change the night the control room tells.
        for (name, port, _, _) in FLEET_STORES {
            let post = |path: &str, body: serde_json::Value| post_json(&format!("http://127.0.0.1:{port}{path}"), &body.to_string()).0;
            post("/store/sim/fault", json!({ "unit": "frz-1", "fault": "defrost-stuck" }));
            post("/store/sim/fault", json!({ "unit": "chl-1", "fault": "compressor-off" }));
            post("/store/sim/advance", json!({ "minutes": 50 }));
            post("/store/sim/fault", json!({ "unit": "frz-2", "fault": "defrost-stuck" }));
            post("/store/sim/advance", json!({ "minutes": 1 }));
            let code = post("/rescue/start", json!({ "paceMs": 3000 }));
            println!("{name}: freezers failed, agent started ({code})");
        }
    }
    let fleet_url = format!("http://127.0.0.1:{HQ}/demo/fleet");
    let code = match opt(args, "--record") {
        Some(out) => {
            let out = std::path::PathBuf::from(out);
            let out = if out.is_absolute() { out } else { std::env::current_dir().map_err(|e| e.to_string())?.join(out) };
            println!("recording the night to {}", out.display());
            let mut cmd = std::process::Command::new("node");
            cmd.current_dir(repo_root().join("anp"))
                .args(["scripts/video/record.mjs", "--url", &format!("{url}?autoplay=1"), "--out"])
                .arg(&out)
                .args(["--intro", "rescue-intro", "--outro", "rescue-outro", "--explainers", "rescue-explainers.js", "--max-secs", "600"]);
            if fleet {
                // after the night: the head office's page, where the three stores' signed records have been arriving all along
                cmd.args(["--then", &fleet_url, "--then-secs", "24"]).args([
                    "--then-caption",
                    if gateway {
                        "The head office never asked a store anything. Each store's Couchbase Lite database replicates its signed documents through Sync Gateway into Couchbase Server, and the head office's Couchbase Lite pulls them out and verifies them. Store 0412 is done; stores 0207 and 0933 wait for their duty managers."
                    } else {
                        "The head office never asked a store anything. Each store's Couchbase Lite database replicates its signed documents straight to the head office's, which verifies them on arrival. Store 0412 is done; stores 0207 and 0933 wait for their duty managers."
                    },
                ]);
            }
            let status = cmd.status()
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
            if fleet {
                println!("the head office:   {fleet_url}\n  all three stores, their failing units, their agents' phases and spend");
            }
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
