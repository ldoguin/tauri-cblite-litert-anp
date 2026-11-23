//! `cargo xtask e2e-approval` (needs `fleet-up` first): the duty manager's approval as a signed document. The night of `e2e-rescue`, with the
//! store replicating through Sync Gateway and a phone (a node, as the duty manager) doing the same. The store's agent stops at a plan over its
//! budget; the phone reads the question from the store's signed record, and approves by signing a document that reaches the store through the
//! gateway. The store acts on a duty manager's document only: the HTTP approve is refused, a head office's signed approval is logged and
//! ignored, and an approval for a store the phone was not given never leaves the phone.

use crate::fleet::{http, put_user, query, ADMIN, DB};
use crate::harness::*;
use crate::rescue::{act, bring_up_with, logged, rescue, wait_phase, HQ, STORE};
use serde_json::{json, Value};

const PHONE: u16 = 19113;

fn at(port: u16, path: &str) -> Value {
    get_json(&format!("http://127.0.0.1:{port}{path}"))
}

fn decide(port: u16, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{port}/approvals/decide"), &body.to_string())
}

/// Remove every document named `store::...` from the gateway and Server, whatever collection it is in: with no tombstone left, a later run's
/// documents of the same names are new documents, not conflicts with the last run's.
fn purge_store_docs() {
    for coll in ["telemetry", "rescue", "approvals"] {
        let ids = query(&format!("SELECT RAW META().id FROM `fleet`.`a2a`.`{coll}` WHERE META().id LIKE 'store::%'")).unwrap_or_default();
        if ids.is_empty() {
            continue;
        }
        let body: serde_json::Map<String, Value> = ids.into_iter().map(|id| (id, json!(["*"]))).collect();
        let _ = http("POST", &format!("{ADMIN}/{DB}.a2a.{coll}/_purge"), Some(&Value::Object(body)), None);
    }
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let alive = http("GET", &format!("{ADMIN}/{DB}/"), None, None).map(|(s, b)| s == 200 && b["state"] == "Online").unwrap_or(false);
    if !alive {
        return Err("the fleet is not up (no database anp at 127.0.0.1:4985): run `cargo xtask fleet-up` first".into());
    }
    let work = work_dir("xtask-approval");
    fresh_dir(&work);
    let mut c = Checks::default();
    // the store is `store` (its DID, its token and the companies' allow lists name it); what an earlier run left in Server under that name is
    // purged first, and after. The phone's id is this run's own.
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) % 1_000_000;
    let (store_id, phone_id) = ("store".to_string(), format!("e2e{stamp}p"));
    purge_store_docs();

    println!("The store and the duty manager's phone, each on Sync Gateway as itself");
    std::env::set_var("ANP_APPROVAL_PW_STORE", format!("pw-{store_id}"));
    std::env::set_var("ANP_APPROVAL_PW_PHONE", format!("pw-{phone_id}"));
    put_user(&store_id, &format!("pw-{store_id}"), &[format!("store.{store_id}")])?;
    // the phone is given this store's channel and no other: it may read the store's records and write approvals into it
    put_user(&phone_id, &format!("pw-{phone_id}"), &[format!("store.{store_id}")])?;
    let phone_did = did_for(&work, &phone_id, "phone.test", "phone");
    let gateway = |var: &str| strs(&["--sync-gateway", &format!("ws://127.0.0.1:4984/{DB}"), "--sync-password-env", var]);
    let night = bring_up_with(
        &work,
        &[strs(&["--trust-did", &phone_did, "--duty-manager", &phone_id]), gateway("ANP_APPROVAL_PW_STORE")].concat(),
    )?;
    let (mut store, mut nodes) = (night.store, night.others);
    let store_did = did_for(&work, "store", "store.test", "store");
    let mut phone = Node::start(&work, &phone_id, "phone", PHONE, &[strs(&["--did-host", "phone.test", "--trust-did", &store_did]), gateway("ANP_APPROVAL_PW_PHONE")].concat());
    c.check("the store's agent is idle, and takes its approval from documents", rescue()["phase"] == "idle", rescue().to_string());

    println!("The night: three freezers and a chiller fail, the agent plans, and asks");
    act("/store/sim/fault", json!({ "unit": "frz-1", "fault": "defrost-stuck" }));
    act("/store/sim/fault", json!({ "unit": "chl-1", "fault": "compressor-off" }));
    act("/store/sim/advance", json!({ "minutes": 50 }));
    act("/store/sim/fault", json!({ "unit": "frz-2", "fault": "defrost-stuck" }));
    act("/store/sim/advance", json!({ "minutes": 1 }));
    let (code, _) = act("/rescue/start", json!({}));
    c.check("the agent starts", code == 200, code.to_string());
    let phase = wait_phase(&["awaiting-approval", "done", "failed"], 150);
    let r = rescue();
    c.check("the plan costs €10,500, over the €6,000 budget: the agent stops and asks", phase == "awaiting-approval" && r["approval"]["planMinor"] == 1_050_000, format!("{phase} {}", r["approval"]));
    let run = r["log"].as_array().and_then(|_| get_json(&format!("http://127.0.0.1:{STORE}/rescues"))["records"][0]["run"].as_str().map(str::to_string)).unwrap_or_default();
    c.check("...and writes the question into its signed record, with a run of its own", !run.is_empty(), "");

    println!("The phone reads the question, through Sync Gateway");
    let asked = poll(90, 500, || at(PHONE, "/rescues")["records"][0]["phase"] == "awaiting-approval");
    let rec = at(PHONE, "/rescues")["records"][0].clone();
    c.check("the phone holds the store's record: waiting for the duty manager, plan €10,500, verified", asked && rec["approval"]["planMinor"] == 1_050_000 && rec["signedBy"]["author"] == json!(store_id), rec["signedBy"].to_string());
    c.check("...the same run the store is waiting on", rec["run"] == json!(run), rec["run"].to_string());

    println!("What must not work");
    let (code, _) = act("/rescue/approve", json!({ "budget": "11000" }));
    c.check("the agent's HTTP approve is refused: it takes an approval from a duty manager's document", code == 403, code.to_string());
    // a head office is trusted by the store (it replicates with it), but is not a duty manager
    let (code, _) = decide(HQ, json!({ "store": store_id, "run": run, "approve": true, "budget": "11000" }));
    c.check("the head office signs an approval of the run, which reaches the store", code == 200, code.to_string());
    let ignored = poll(40, 500, || logged(&rescue(), "approval signed by e2e", None) || logged(&rescue(), "is not a duty manager", Some("only a duty manager approves")));
    c.check("the agent logs it as ignored: its signer is not a duty manager", ignored, "");
    sleep(3);
    c.check("...and goes on waiting", rescue()["phase"] == "awaiting-approval", rescue()["phase"].to_string());
    // an approval for a store the phone was not given: it never leaves the phone
    let (code, _) = decide(PHONE, json!({ "store": "some-other-store", "run": "r1", "approve": true, "budget": "11000" }));
    c.check("the phone signs an approval for another store (locally, it can)", code == 200, code.to_string());
    sleep(6);
    let (st, body) = http("GET", &format!("{ADMIN}/{DB}.a2a.approvals/some-other-store::r1::{phone_id}"), None, None)?;
    c.check("Sync Gateway refuses it: the phone was not given that store's channel", st == 404, format!("{st} {body}"));
    c.check("the store is still waiting", rescue()["phase"] == "awaiting-approval", rescue()["phase"].to_string());

    println!("The duty manager approves from the phone");
    let (code, _) = decide(PHONE, json!({ "store": store_id, "run": run, "approve": true, "budget": "11000" }));
    c.check("the phone signs the approval: raise the budget to €11,000", code == 200, code.to_string());
    let phase = wait_phase(&["done", "failed", "declined"], 180);
    let r = rescue();
    c.check("the agent sees it, acts on it, and the rescue completes", phase == "done", format!("{phase} {}", r["log"].as_array().and_then(|l| l.last()).cloned().unwrap_or_default()));
    c.check("the log names the duty manager and the signed document", logged(&r, &format!("duty manager {phone_id} approves the plan, in a signed document"), Some("a person approves what is over the limit")), "");
    c.check("six deals confirmed, €10,500 spent, every one audits", r["summary"]["confirmed"] == 6 && r["summary"]["spentMinor"] == 1_050_000 && r["summary"]["audited"] == 6, r["summary"].to_string());
    let (st, body) = http("GET", &format!("{ADMIN}/{DB}.a2a.approvals/{store_id}::{run}::{phone_id}"), None, None)?;
    c.check("the approval is a document in Sync Gateway, signed by the phone", st == 200 && body["trust"]["author"] == json!(phone_id) && body["approve"] == true, format!("{st} {body}"));
    let in_server = poll(30, 1000, || query(&format!("SELECT RAW COUNT(*) FROM `fleet`.`a2a`.`approvals` USE KEYS '{store_id}::{run}::{phone_id}'")).map(|v| v == ["1"]).unwrap_or(false));
    c.check("...and in Couchbase Server (fleet.a2a.approvals)", in_server, "");
    let kept = at(STORE, "/approvals")["approvals"].as_array().cloned().unwrap_or_default();
    c.check("the store holds the phone's approval, and the head office's, each with its signer", kept.iter().any(|a| a["signedBy"]["author"] == json!(phone_id)) && kept.iter().any(|a| a["signedBy"]["author"] == "hq"), format!("{kept:?}"));
    let (code, _) = act("/rescue/approve", json!({}));
    c.check("nothing is waiting for approval any more", code == 403 || code == 400, code.to_string());

    store.kill();
    phone.kill();
    for n in &mut nodes {
        n.kill();
    }
    purge_store_docs();
    for n in [&store_id, &phone_id] {
        let _ = http("DELETE", &format!("{ADMIN}/{DB}/_user/{n}"), None, None);
    }
    Ok(c.finish())
}
