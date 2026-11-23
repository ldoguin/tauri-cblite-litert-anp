//! `cargo xtask e2e-fleet-view` (needs `fleet-up` first): the head office's view of the fleet, live. Three stores, each a node with its cold
//! room, its buying desk and its rescue agent, replicate with Sync Gateway only; the head office is a fourth node that does the same and holds
//! no simulation. All three stores' freezers fail at once; each agent starts its rescue; the head office, which never asks a store anything, shows
//! all three at `/demo/fleet` (`GET /fleet`): the failing units, each agent's phase, what each has spent.

use crate::fleet::{http, logs_at, put_user, ADMIN, DB};
use crate::harness::*;
use serde_json::{json, Value};

const HQ_PORT: u16 = 18998;
const STORE_PORTS: [u16; 3] = [18999, 19001, 19002];

fn fleet() -> Value {
    get_json(&format!("http://127.0.0.1:{HQ_PORT}/fleet"))
}

fn store_of<'a>(f: &'a Value, node: &str) -> &'a Value {
    f["stores"].as_array().and_then(|s| s.iter().find(|x| x["node"] == node)).unwrap_or(&Value::Null)
}

/// `--hold SECONDS`: keep the nodes running that long after the checks, so the page can be looked at (`http://127.0.0.1:18998/demo/fleet`).
pub fn run(args: &[String]) -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let alive = http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false);
    if !alive {
        return Err("the fleet is not up (no database anp at 127.0.0.1:4985): run `cargo xtask fleet-up` first".into());
    }
    let work = work_dir("xtask-fleet-view");
    fresh_dir(&work);
    let mut c = Checks::default();
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) % 1_000_000;
    let names: Vec<String> = ["a", "b", "c"].iter().map(|s| format!("v{stamp}{s}")).collect();
    let hq = format!("v{stamp}hq");

    println!("Three stores with their agents, and a head office");
    let root = root_key(&work, "retailer");
    let empty = work.join("no-companies.json");
    std::fs::write(&empty, "[]").map_err(|e| e.to_string())?;
    for (i, n) in names.iter().enumerate() {
        std::env::set_var(format!("ANP_FLEET_PW_{i}"), format!("pw-{n}"));
        put_user(n, &format!("pw-{n}"), &[format!("store.{n}")])?;
    }
    std::env::set_var("ANP_FLEET_PW_HQ", format!("pw-{hq}"));
    put_user(&hq, &format!("pw-{hq}"), &["*".to_string()])?;
    let gateway = |var: &str| strs(&["--sync-gateway", &format!("ws://127.0.0.1:{}/{DB}", 4984), "--sync-password-env", var]);

    let mut dids = vec![];
    let mut stores = vec![];
    for (i, n) in names.iter().enumerate() {
        let port = STORE_PORTS[i];
        let did = did_for(&work, n, &format!("{n}.test"), n);
        let key = std::fs::read_to_string(work.join(n).join("node.pub")).map_err(|e| e.to_string())?.trim().to_string();
        let token = work.join(format!("{n}.token"));
        let issued = run_tool(
            "anp-admin",
            &strs(&[
                "issue", "--root", &work.join("retailer.key").display().to_string(), "--node", n, "--key", &key, "--did", &did, "--days", "1",
                "--spend-cap", "6000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", &format!("site-{n}"),
                "--out", &token.display().to_string(),
            ]),
        );
        if issued.0 != 0 {
            return Err(format!("issuing {n}'s spending token: {}", issued.1));
        }
        let args = [
            strs(&["--did-host", &format!("{n}.test"), "--e2ee", "--direct-messaging", "--require-auth", "--public-origin", &format!("http://127.0.0.1:{port}")]),
            strs(&["--store-sim", "0", "--spend-token", &token.display().to_string(), "--spend-root", &root, "--budget", "6000", "--site", &format!("site-{n}"), "--rescue", &empty.display().to_string()]),
            gateway(&format!("ANP_FLEET_PW_{i}")),
        ]
        .concat();
        stores.push(Node::start(&work, n, n, port, &args));
        dids.push(did);
    }
    let mut trust = vec![];
    for d in &dids {
        trust.extend(strs(&["--trust-did", d]));
    }
    let mut ho = Node::start(&work, &hq, &hq, HQ_PORT, &[strs(&["--did-host", &format!("{hq}.test")]), trust, gateway("ANP_FLEET_PW_HQ")].concat());

    println!("The head office, with every store calm");
    c.check(
        "the head office lists three stores, 4 units each, all ok, through Sync Gateway only",
        poll(90, 500, || {
            let f = fleet();
            f["stores"].as_array().map_or(0, |s| s.len()) == 3 && f["stores"].as_array().unwrap().iter().all(|s| s["units"].as_array().map_or(0, |u| u.len()) == 4 && s["failing"] == 0)
        }),
        fleet()["totals"].to_string(),
    );
    let f = fleet();
    c.check("...none failing, no rescue run yet, nothing spent", f["totals"]["failingStores"] == 0 && f["totals"]["spentMinor"] == 0 && f["stores"].as_array().unwrap().iter().all(|s| s["rescue"].is_null()), f["totals"].to_string());
    let page = http_get(&format!("http://127.0.0.1:{HQ_PORT}/demo/fleet"));
    c.check("the page is served at /demo/fleet", page.status == 200, page.status.to_string());

    println!("All three stores' freezers fail at once");
    for (i, n) in names.iter().enumerate() {
        let port = STORE_PORTS[i];
        let (code, _) = post_json(&format!("http://127.0.0.1:{port}/store/sim/fault"), &json!({ "unit": "frz-1", "fault": "defrost-stuck" }).to_string());
        c.check(&format!("{n}: freezer 1 sticks in defrost"), code == 200, code.to_string());
        let (code, _) = post_json(&format!("http://127.0.0.1:{port}/store/sim/advance"), &json!({ "minutes": 30 }).to_string());
        c.check(&format!("{n}: 30 minutes pass"), code == 200, code.to_string());
    }
    c.check(
        "the head office shows three failing stores, each with its freezer out, without asking any store",
        poll(60, 500, || {
            let f = fleet();
            f["totals"]["failingStores"] == 3 && names.iter().all(|n| store_of(&f, n)["units"].as_array().map_or(false, |u| u.iter().any(|x| x["id"] == "frz-1" && x["state"] == "fault" && x["fault"] == "defrost-stuck")))
        }),
        fleet()["totals"].to_string(),
    );

    println!("Each store's agent starts its rescue");
    for (i, n) in names.iter().enumerate() {
        let (code, _) = post_json(&format!("http://127.0.0.1:{}/rescue/start", STORE_PORTS[i]), "{}");
        c.check(&format!("{n}: the agent starts"), code == 200 || code == 202, code.to_string());
    }
    let ended = |s: &Value| matches!(s["rescue"]["phase"].as_str(), Some("done" | "failed" | "declined"));
    c.check(
        "the head office shows each agent's phase from its own signed record, and each run ended",
        poll(90, 500, || {
            let f = fleet();
            names.iter().all(|n| ended(store_of(&f, n)))
        }),
        fleet()["stores"].to_string(),
    );
    let f = fleet();
    c.check("...three rescue records, one per store, each its own run", names.iter().map(|n| store_of(&f, n)["rescue"]["run"].as_str().unwrap_or("").to_string()).collect::<std::collections::BTreeSet<_>>().len() == 3, f["stores"].to_string());
    c.check("...the totals: 3 stores failing, 3 or more units out, no agent still running", f["totals"]["failingStores"] == 3 && f["totals"]["failingUnits"].as_u64().unwrap_or(0) >= 3 && f["totals"]["rescuing"] == 0, f["totals"].to_string());
    let s0 = store_of(&f, &names[0]);
    c.check("...each store's signature is the one named, verified on arrival", names.iter().zip(&dids).all(|(n, d)| store_of(&f, n)["signedBy"]["author"] == json!(n) && store_of(&f, n)["signedBy"]["did"] == json!(d)), s0["signedBy"].to_string());
    c.check("the head office holds all twelve logs and no store's records were refused", logs_at(HQ_PORT).len() == 12, format!("{} logs", logs_at(HQ_PORT).len()));
    let refused: Vec<Value> = [HQ_PORT].iter().chain(STORE_PORTS.iter()).flat_map(|p| rejections(*p)).filter(|r| names.iter().any(|n| r["author"] == json!(n))).collect();
    c.check("...nothing refused anywhere", refused.is_empty(), format!("{refused:?}"));
    let proxied = ureq::get(&format!("http://127.0.0.1:{HQ_PORT}/fleet")).set("x-forwarded-for", "203.0.113.7").call();
    c.check("the view is for this machine's operator only: a proxied request is refused", matches!(proxied, Err(ureq::Error::Status(403, _))), "");

    if let Some(secs) = opt(args, "--hold").and_then(|s| s.parse::<u64>().ok()) {
        println!("holding for {secs} s: http://127.0.0.1:{HQ_PORT}/demo/fleet");
        sleep(secs);
    }
    for mut n in stores {
        n.kill();
    }
    ho.kill();
    for n in names.iter().chain(std::iter::once(&hq)) {
        let _ = http("DELETE", &format!("{ADMIN}/{DB}/_user/{n}"), None, None);
    }
    Ok(c.finish())
}
