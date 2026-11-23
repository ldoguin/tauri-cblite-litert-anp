//! `cargo xtask e2e-quotes`: the store's node buys from eight counterparties of the cold-stock rescue scenario, each its own node on its
//! own domain: three carriers (one too expensive, one unavailable, one right), two warehouses (one short of room), a food bank, an insurer
//! and a supplier. Requests, quotes, acceptances and confirmations are signed messages in encrypted direct conversations. The store's
//! spending token (from the retailer's authority) caps each commitment at €6,000 and its budget caps them all: the best plan, €7,200, needs
//! the duty manager, who raises the budget; the expensive carrier needs a new token from the authority. A supplier that does not know the
//! retailer's authority refuses the store's acceptance on its own. Every confirmed deal audits offline.

use crate::harness::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const STORE: u16 = 19001;
const SELLERS: [(&str, u16); 8] = [("frostline", 19002), ("polar", 19003), ("coldchain", 19004), ("rungis-cold", 19005), ("orly-freeze", 19006), ("foodbank", 19007), ("insurer", 19008), ("supplier", 19009)];

fn base(name: &str, port: u16) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.test"), "--e2ee", "--direct-messaging", "--require-auth", "--public-origin", &format!("http://127.0.0.1:{port}")])
}

fn document(work: &Path, name: &str, port: u16) -> Result<(String, PathBuf), String> {
    let did = did_for(work, name, &format!("{name}.test"), name);
    let mut n = Node::start(work, name, name, port, &base(name, port));
    let e1 = did.rsplit(':').next().unwrap_or_default();
    let doc = get_json(&format!("http://127.0.0.1:{port}/agents/{name}/{e1}/did.json"));
    n.kill();
    if doc["id"] != json!(did) {
        return Err(format!("{name}: no DID document ({doc})"));
    }
    let f = work.join(format!("{name}.did.json"));
    std::fs::write(&f, doc.to_string()).map_err(|e| e.to_string())?;
    Ok((did, f))
}

fn peer(doc: &Path, did: &str, port: u16) -> Vec<String> {
    strs(&["--allow-caller", &doc.display().to_string(), "--direct-peer", &format!("{did}=http://127.0.0.1:{port}/anp/direct")])
}

fn quotes() -> Value {
    get_json(&format!("http://127.0.0.1:{STORE}/anp/quotes"))["buyer"].clone()
}

fn act(action: &str, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{STORE}/anp/quotes/{action}"), &body.to_string())
}

/// Ask `seller` and wait for its answer: `(request id, the quote if one came)`.
fn ask(seller: &str, did: &str, category: &str, pallets: u32) -> (String, Option<Value>) {
    let (_, r) = act("request", json!({ "to": did, "category": category, "pallets": pallets, "need": { "for": seller } }));
    let id = r["request"].as_str().unwrap_or_default().to_string();
    poll(60, 500, || quotes()["requests"][&id]["answers"].as_array().map_or(false, |a| !a.is_empty()));
    let quote = quotes()["quotes"].as_object().and_then(|q| q.values().find(|q| q["requestId"] == json!(id)).map(|q| q["quote"].clone()));
    (id, quote)
}

fn refusal_for(request_id: &str) -> Option<String> {
    let q = quotes();
    let answer = q["requests"][request_id]["answers"][0].clone();
    q["refusals"].as_array()?.iter().find(|r| r["id"] == answer).and_then(|r| r["reason"].as_str().map(str::to_string))
}

/// Accept and wait for the seller's answer: `(HTTP status, the store's answer, the acceptance's final status)`.
fn accept(quote: &Value) -> (u16, Value, String) {
    let (code, r) = act("accept", json!({ "quote": quote["id"] }));
    if code != 200 {
        return (code, r, String::new());
    }
    let id = r["acceptance"].as_str().unwrap_or_default().to_string();
    let mut status = String::new();
    poll(60, 500, || {
        status = quotes()["acceptances"][&id]["status"].as_str().unwrap_or_default().to_string();
        status != "pending"
    });
    (code, r, status)
}

fn euros(minor: &Value) -> f64 {
    minor.as_u64().unwrap_or(0) as f64 / 100.0
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let work = work_dir("xtask-quotes");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("The retailer's authority, the store and eight companies");
    let root = root_key(&work, "retailer");
    let other_root = root_key(&work, "someone-else");
    let (store_did, store_doc) = document(&work, "store", STORE)?;
    let store_key = std::fs::read_to_string(work.join("store").join("node.pub")).map_err(|e| e.to_string())?.trim().to_string();
    let token = work.join("store.token");
    let (code, out) = run_tool(
        "anp-admin",
        &strs(&[
            "issue", "--root", &work.join("retailer.key").display().to_string(), "--node", "store", "--key", &store_key, "--did", &store_did, "--days", "1",
            "--spend-cap", "6000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", "store-0412",
            "--out", &token.display().to_string(),
        ]),
    );
    c.check("the authority issues the store a spending token: €6,000 per commitment, for store 0412", code == 0, out);
    let mut sellers: Vec<(String, String, PathBuf, u16)> = vec![];
    for (name, port) in SELLERS {
        let (did, doc) = document(&work, name, port)?;
        sellers.push((name.to_string(), did, doc, port));
    }
    let mut nodes = vec![];
    for (name, _, _, port) in &sellers {
        // the supplier knows another authority than the retailer's: it will not take the store's token
        let trusted = if name == "supplier" { &other_root } else { &root };
        let extra = [base(name, *port), peer(&store_doc, &store_did, STORE), strs(&["--counterparty", name, "--buyer-root", trusted, "--agent", "echo"])].concat();
        nodes.push(Node::start(&work, name, name, *port, &extra));
    }
    let store_args = |sellers: &[(String, String, PathBuf, u16)]| {
        let mut a = [base("store", STORE), strs(&["--spend-token", &token.display().to_string(), "--spend-root", &root, "--budget", "6000", "--site", "store-0412"])].concat();
        for (_, did, doc, port) in sellers {
            a.extend(peer(doc, did, *port));
        }
        a
    };
    let mut store = Node::start(&work, "store", "store", STORE, &store_args(&sellers));
    let did = |n: &str| sellers.iter().find(|s| s.0 == n).map(|s| s.1.clone()).unwrap_or_default();
    let l = quotes()["ledger"].clone();
    c.check("the store's ledger: a €6,000 budget, nothing spent", l["budgetMinor"] == 600_000 && l["committedMinor"] == 0, l.to_string());

    println!("Quotes from the three carriers, the two warehouses, the food bank and the insurer");
    let (_, frost) = ask("frostline", &did("frostline"), "transport", 3);
    let (polar_req, polar) = ask("polar", &did("polar"), "transport", 3);
    let (_, cold) = ask("coldchain", &did("coldchain"), "transport", 3);
    let (_, rungis) = ask("rungis-cold", &did("rungis-cold"), "storage", 3);
    let (_, orly) = ask("orly-freeze", &did("orly-freeze"), "storage", 3);
    let (_, bank) = ask("foodbank", &did("foodbank"), "donation", 1);
    let (_, insurer) = ask("insurer", &did("insurer"), "coverage", 3);
    let (frost, cold, rungis, orly, bank, insurer) = (frost.unwrap_or_default(), cold.unwrap_or_default(), rungis.unwrap_or_default(), orly.unwrap_or_default(), bank.unwrap_or_default(), insurer.unwrap_or_default());
    c.check("FrostLine quotes €9,400 for 3 pallets", frost["amountMinor"] == 940_000, frost.to_string());
    c.check("Polar Express refuses: no truck before 06:00", polar.is_none() && refusal_for(&polar_req).map_or(false, |r| r.contains("06:00")), format!("{:?}", refusal_for(&polar_req)));
    c.check("ColdChain quotes €5,400", cold["amountMinor"] == 540_000, cold.to_string());
    c.check("Rungis Cold has room for 2 pallets only: €1,800, marked partial", rungis["amountMinor"] == 180_000 && rungis["terms"]["pallets"] == 2 && rungis["terms"]["partial"] == true, rungis.to_string());
    c.check("Orly Freeze quotes €4,500 for 3", orly["amountMinor"] == 450_000, orly.to_string());
    c.check("the food bank takes a pallet for free, collected by 04:00", bank["amountMinor"] == 0 && bank["terms"]["collectBy"] == "04:00", bank.to_string());
    c.check("the insurer says the plan is covered and lists the evidence it wants", insurer["terms"]["covered"] == true && insurer["terms"]["evidence"].as_array().map_or(false, |e| e.len() == 3), insurer.to_string());
    c.check("every quote is signed by its company's DID (verified by the store on arrival)", quotes()["quotes"].as_object().map_or(false, |q| q.values().all(|q| q["quote"]["from"] == q["from"] && q["quote"]["proof"].is_object())), "");

    println!("Accepting, within the limits");
    let (code, r, _) = accept(&frost);
    c.check("the store will not sign FrostLine's €9,400: above its €6,000 token, it needs a person", code == 400 && r["needsApproval"] == true && r["error"].as_str().map_or(false, |e| e.contains("not authorized")), r.to_string());
    let (code, r, status) = accept(&cold);
    c.check("the store accepts ColdChain's €5,400, and ColdChain confirms", code == 200 && status == "confirmed", format!("{code} {r} {status}"));
    let cold_acc = r["acceptance"].as_str().unwrap_or_default().to_string();
    let (code, r, _) = accept(&rungis);
    c.check("Rungis's €1,800 would make €7,200, over the €6,000 budget: the store asks the duty manager", code == 400 && r["needsApproval"] == true && r["error"].as_str().map_or(false, |e| e.contains("over budget")), r.to_string());
    let (code, _) = act("authority", json!({ "budget": "8000" }));
    c.check("the duty manager raises the budget to €8,000", code == 200 && quotes()["ledger"]["budgetMinor"] == 800_000, "");
    let (code, r, status) = accept(&rungis);
    c.check("now the store accepts Rungis's offer, and Rungis confirms", code == 200 && status == "confirmed", format!("{code} {r} {status}"));
    let l = quotes()["ledger"].clone();
    c.check("the plan is committed: €7,200 of €8,000", l["committedMinor"] == 720_000 && l["remainingMinor"] == 80_000, l.to_string());
    let (_, again) = ask("rungis-cold", &did("rungis-cold"), "storage", 1);
    c.check("Rungis, now full, refuses another pallet", again.is_none(), format!("{again:?}"));
    let (_, _, status) = accept(&bank);
    c.check("the food bank confirms the donation (no money, still a signed commitment)", status == "confirmed", status);
    let (_, _, status) = accept(&insurer);
    c.check("the insurer confirms its cover", status == "confirmed", status);

    println!("A new token from the authority");
    let big = work.join("store-big.token");
    let (code, out) = run_tool(
        "anp-admin",
        &strs(&[
            "issue", "--root", &work.join("retailer.key").display().to_string(), "--node", "store", "--key", &store_key, "--did", &store_did, "--days", "1",
            "--spend-cap", "10000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", "store-0412",
            "--out", &big.display().to_string(),
        ]),
    );
    c.check("the authority issues a new token with a €10,000 cap (the holder could not raise its own)", code == 0, out);
    let (code, _) = act("authority", json!({ "token": std::fs::read_to_string(&big).unwrap_or_default(), "budget": "20000" }));
    c.check("the duty manager gives it to the store, with a €20,000 budget", code == 200, code.to_string());
    let (code, r, status) = accept(&frost);
    c.check("now FrostLine's €9,400 goes through, and FrostLine confirms (it checked the new token itself)", code == 200 && status == "confirmed", format!("{code} {r} {status}"));
    let (code, _) = act("authority", json!({ "token": "not a token" }));
    c.check("a token from no authority is refused", code == 400, code.to_string());

    println!("A seller checks the buyer's authority on its own");
    let (_, supply) = ask("supplier", &did("supplier"), "restock", 2);
    let supply = supply.unwrap_or_default();
    c.check("the supplier quotes a rush restock: €1,200", supply["amountMinor"] == 120_000, supply.to_string());
    let before = quotes()["ledger"]["outstandingMinor"].clone();
    let (code, r, status) = accept(&supply);
    c.check("the store signs, but the supplier, who does not know the retailer's authority, refuses", code == 200 && status == "refused", format!("{code} {r} {status}"));
    let reason = quotes()["refusals"].as_array().and_then(|r| r.last().cloned()).unwrap_or_default();
    c.check("...and says why: the token is not one it accepts", reason["reason"].as_str().map_or(false, |r| r.contains("not authorized")), reason.to_string());
    c.check("the amount it had reserved is free again", quotes()["ledger"]["outstandingMinor"] == before, quotes()["ledger"].to_string());

    println!("The record");
    let (code, a) = act("audit", json!({ "acceptance": cold_acc }));
    c.check("the ColdChain deal audits offline: four signed messages, the token as it was at acceptance", code == 200 && a["valid"] == true && a["amountMinor"] == 540_000 && a["onBehalfOf"] == "store-0412", a.to_string());
    let confirmed = quotes()["acceptances"].as_object().map_or(0, |a| a.values().filter(|a| a["status"] == "confirmed" && a["record"].is_object()).count());
    c.check("five confirmed deals, each with its full record", confirmed == 5, confirmed.to_string());
    let carrier_log = get_json(&format!("http://127.0.0.1:19004/anp/direct/conversations?peer={}", urlencode(&store_did)));
    let outs: Vec<&Value> = carrier_log["messages"].as_array().map(|m| m.iter().filter(|x| x["direction"] == "out").collect()).unwrap_or_default();
    c.check("the carrier's desk answered, not its chat agent: every reply is a signed protocol message", !outs.is_empty() && outs.iter().all(|m| m["plaintext"]["payload"]["protocol"] == "anp.quote.v1"), carrier_log.to_string());
    let seller = get_json("http://127.0.0.1:19004/anp/quotes")["seller"].clone();
    c.check("ColdChain's own book: one quote, one confirmation", seller["answers"].as_array().map_or(0, |a| a.len()) == 2, seller["answers"].to_string());

    println!("A restart");
    store.kill();
    store = Node::start(&work, "store", "store", STORE, &store_args(&sellers));
    let l = quotes()["ledger"].clone();
    c.check("after a restart the store still has its ledger: €16,600 committed", l["committedMinor"] == 1_660_000, format!("€{} {l}", euros(&l["committedMinor"])));
    let (code, a) = act("audit", json!({ "acceptance": cold_acc }));
    c.check("...and its records", code == 200 && a["valid"] == true, a.to_string());

    store.kill();
    for n in &mut nodes {
        n.kill();
    }
    Ok(c.finish())
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}
