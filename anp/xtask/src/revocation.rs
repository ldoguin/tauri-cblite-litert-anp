//! `cargo xtask e2e-revocation` (needs `fleet-up` first): the retailer's authority revokes a store's spending token and issues it a new one,
//! both through Sync Gateway. The head office (a node, in the Sync Gateway role `head-office`) takes the authority's signed revocation and
//! writes it into the replicated `revocations`; the store, which never talks to the authority, reads it through the gateway and stops using the
//! token. The head office then carries a new token the authority issued, and the store takes it and buys again. What must not work: a
//! node the store was not told to take tokens from carries one (ignored), and the revoked token is carried again (refused).
//!
//! What this does not do: a company still accepts the revoked token if a store used it (companies are outside the retailer and do not read
//! its gateway). The store refuses to sign with it.

use crate::approval::purge_store_docs;
use crate::fleet::{http, put_role, put_user, put_user_roles, ADMIN, DB};
use crate::harness::*;
use crate::rescue::{bring_up_with, HQ, STORE};
use serde_json::{json, Value};

const OFFICE: u16 = 19114;

fn buyer() -> Value {
    get_json(&format!("http://127.0.0.1:{STORE}/anp/quotes"))["buyer"].clone()
}

fn act(action: &str, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{STORE}/anp/quotes/{action}"), &body.to_string())
}

/// Ask `did` for one pallet of restock, wait for its quote. (The cheapest thing the token allows: the budget is €6,000, and the check buys four times.)
fn ask(did: &str) -> Option<Value> {
    let (_, r) = act("request", json!({ "to": did, "category": "restock", "pallets": 1, "need": { "for": "revocation check" } }));
    let id = r["request"].as_str().unwrap_or_default().to_string();
    poll(60, 500, || buyer()["requests"][&id]["answers"].as_array().map_or(false, |a| !a.is_empty()));
    buyer()["quotes"].as_object().and_then(|q| q.values().find(|q| q["requestId"] == json!(id)).map(|q| q["quote"].clone()))
}

/// Accept a quote and wait for the answer: `(HTTP status, the store's answer, the acceptance's final status)`.
fn accept(quote: &Value) -> (u16, Value, String) {
    let (code, r) = act("accept", json!({ "quote": quote["id"] }));
    if code != 200 {
        return (code, r, String::new());
    }
    let id = r["acceptance"].as_str().unwrap_or_default().to_string();
    let mut status = String::new();
    poll(60, 500, || {
        status = buyer()["acceptances"][&id]["status"].as_str().unwrap_or_default().to_string();
        status != "pending"
    });
    (code, r, status)
}

fn carry(port: u16, store: &str, token: &str) -> u16 {
    post_json(&format!("http://127.0.0.1:{port}/fleet/token"), &json!({ "store": store, "token": token }).to_string()).0
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let alive = http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false);
    if !alive {
        return Err("the fleet is not up (no database anp at 127.0.0.1:4985): run `cargo xtask fleet-up` first".into());
    }
    let work = work_dir("xtask-revocation");
    fresh_dir(&work);
    let mut c = Checks::default();
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) % 1_000_000;
    let office_id = format!("e2e{stamp}o");
    purge_store_docs();

    println!("The store, a head office carrying the authority's documents, and the night's companies");
    std::env::set_var("ANP_REVOKE_PW_STORE", "pw-store");
    std::env::set_var("ANP_REVOKE_PW_OFFICE", format!("pw-{office_id}"));
    put_role("head-office")?;
    // the store reads its own channel and `fleet` (the authority's documents); the office may write them; it reads every channel (`*`) and carries tokens only into the channels it is named for (`*` does not satisfy the gateway's access check)
    put_user("store", "pw-store", &["store.store".to_string(), "fleet".to_string()])?;
    put_user_roles(&office_id, &format!("pw-{office_id}"), &["*".to_string(), "store.store".to_string()], &["head-office"])?;
    let office_did = did_for(&work, &office_id, "office.test", "office");
    let gateway = |var: &str| strs(&["--sync-gateway", &format!("ws://127.0.0.1:4984/{DB}"), "--sync-password-env", var]);
    let night = bring_up_with(&work, &[strs(&["--trust-did", &office_did, "--token-from", &office_id]), gateway("ANP_REVOKE_PW_STORE")].concat())?;
    let (mut store, mut nodes, sellers, root) = (night.store, night.others, night.sellers, night.root);
    let store_did = did_for(&work, "store", "store.test", "store");
    let mut office = Node::start(
        &work,
        &office_id,
        "office",
        OFFICE,
        &[strs(&["--did-host", "office.test", "--trust-did", &store_did, "--authority-root", &root]), gateway("ANP_REVOKE_PW_OFFICE")].concat(),
    );
    let supplier = sellers.iter().find(|s| s.0 == "supplier").map(|s| s.2.clone()).unwrap_or_default();
    let retailer_key = work.join("retailer.key").display().to_string();
    let old_token = work.join("store.token");
    c.check("the store holds its spending token and it is not revoked", night.token_issued.0 == 0 && buyer()["tokenRevoked"] == false, buyer()["tokenRevoked"].to_string());

    println!("The token works");
    let q = ask(&supplier);
    c.check("the supplier quotes one pallet to restock", q.is_some(), buyer()["refusals"].to_string());
    let q = q.unwrap_or(Value::Null);
    let (code, _, status) = accept(&q);
    c.check("the store accepts it with its token, and the supplier confirms", code == 200 && status == "confirmed", format!("{code} {status}"));

    println!("The authority revokes the token");
    let rev_file = work.join("revoke.json");
    let (code, out) = run_tool("anp-admin", &strs(&["revoke", "--root", &retailer_key, "--token", &old_token.display().to_string(), "--reason", "store phone lost", "--out", &rev_file.display().to_string()]));
    c.check("the authority signs a revocation of the store's token", code == 0, out);
    let bundle: Value = std::fs::read_to_string(&rev_file).ok().and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok()).unwrap_or(Value::Null);
    let (code, body) = post_json(&format!("http://127.0.0.1:{OFFICE}/security/revocations"), &bundle.to_string());
    c.check("the head office verifies it against the authority's key and publishes it", code == 200, format!("{code} {body}"));
    c.check("the revocation reaches the store through Sync Gateway: its token is revoked", poll(90, 500, || buyer()["tokenRevoked"] == true), buyer()["tokenRevoked"].to_string());
    let q2 = ask(&supplier).unwrap_or(Value::Null);
    let (code, r, _) = accept(&q2);
    c.check("the store will not accept another quote with it", code != 200 && r.to_string().contains("revoked"), format!("{code} {r}"));

    println!("What must not work");
    let new_token = work.join("store-new.token");
    let store_key = std::fs::read_to_string(work.join("store").join("node.pub")).map_err(|e| e.to_string())?.trim().to_string();
    let (code, out) = run_tool(
        "anp-admin",
        &strs(&[
            "issue", "--root", &retailer_key, "--node", "store", "--key", &store_key, "--did", &store_did, "--days", "1",
            "--spend-cap", "9000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", "store-0412",
            "--out", &new_token.display().to_string(),
        ]),
    );
    c.check("the authority issues the store a new token (cap €9,000)", code == 0, out);
    let new = std::fs::read_to_string(&new_token).map_err(|e| e.to_string())?.trim().to_string();
    let old = std::fs::read_to_string(&old_token).map_err(|e| e.to_string())?.trim().to_string();
    // the head office of the P2P link is trusted by the store for its records, but is not a node the store takes tokens from
    c.check("a node the store was not told to take tokens from carries the new token", carry(HQ, "store", &new) == 200, "");
    sleep(6);
    c.check("the store ignores it: its token is still revoked", buyer()["tokenRevoked"] == true, buyer()["tokenRevoked"].to_string());

    println!("The head office carries the new token");
    c.check("the head office carries it, signed, into the store's channel", carry(OFFICE, "store", &new) == 200, "");
    c.check("the store takes it: its token is no longer revoked", poll(90, 500, || buyer()["tokenRevoked"] == false), buyer()["tokenRevoked"].to_string());
    let q3 = ask(&supplier).unwrap_or(Value::Null);
    let (code, _, status) = accept(&q3);
    c.check("the store buys again, and the supplier confirms", code == 200 && status == "confirmed", format!("{code} {status}"));
    c.check("the confirmed deal audits, as the insurer will check it", buyer()["acceptances"].as_object().map_or(false, |a| a.values().filter(|x| x["status"] == "confirmed").count() == 2), buyer()["acceptances"].to_string());

    println!("The revoked token is carried again");
    c.check("the head office carries the old, revoked token again", carry(OFFICE, "store", &old) == 200, "");
    sleep(8);
    c.check("the store refuses it: it keeps the new token", buyer()["tokenRevoked"] == false, buyer()["tokenRevoked"].to_string());
    let q4 = ask(&supplier).unwrap_or(Value::Null);
    let (code, _, status) = accept(&q4);
    c.check("...and can still buy", code == 200 && status == "confirmed", format!("{code} {status}"));

    println!("A revocation that is not the authority's");
    run_tool("anp-admin", &strs(&["root-keygen", "--out", &work.join("impostor.key").display().to_string()]));
    let (code, out) = run_tool("anp-admin", &strs(&["revoke", "--root", &work.join("impostor.key").display().to_string(), "--token", &new_token.display().to_string(), "--reason", "mallory says so", "--out", &work.join("fake.json").display().to_string()]));
    let fake: Value = std::fs::read_to_string(work.join("fake.json")).ok().and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok()).unwrap_or(Value::Null);
    let (st, _) = post_json(&format!("http://127.0.0.1:{OFFICE}/security/revocations"), &fake.to_string());
    c.check("an impostor's revocation is refused by the head office", code != 0 || st == 400 || st == 403 || st == 422, format!("{code} {out} {st}"));
    sleep(4);
    c.check("...and the store's new token is still in use", buyer()["tokenRevoked"] == false, buyer()["tokenRevoked"].to_string());

    store.kill();
    office.kill();
    for n in &mut nodes {
        n.kill();
    }
    purge_store_docs();
    for n in ["store", office_id.as_str()] {
        let _ = http("DELETE", &format!("{ADMIN}/{DB}/_user/{n}"), None, None);
    }
    Ok(c.finish())
}
