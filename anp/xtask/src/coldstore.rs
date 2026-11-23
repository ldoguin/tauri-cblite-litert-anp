//! `cargo xtask e2e-coldstore`: the simulated store of the cold-stock rescue scenario. The store's node (`store.test`) runs the cold room
//! and logs every unit's temperature into the replicated, signed `telemetry` collection; the head office (`hq.test`) replicates with it
//! over TLS with DID admission. A freezer's controller sticks in defrost: the rules flag its products at risk, then unsafe. The link is
//! cut: the store keeps assessing and logging, the head office sees nothing new, then catches up when the link comes back.

use crate::harness::*;
use serde_json::{json, Value};

const STORE: u16 = 18991;
const HQ: u16 = 18992;

fn base(name: &str) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.test"), "--tls", "--admit"])
}

fn sim(body: Value, action: &str) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{STORE}/store/sim/{action}"), &body.to_string())
}

fn state() -> Value {
    get_json(&format!("http://127.0.0.1:{STORE}/store/sim"))
}

fn product(s: &Value, sku: &str) -> Value {
    s["assessment"].as_array().and_then(|a| a.iter().find(|p| p["sku"] == sku).cloned()).unwrap_or(Value::Null)
}

fn log_at(port: u16, id: &str) -> Value {
    get_json(&format!("http://127.0.0.1:{port}/telemetry"))["logs"].as_array().and_then(|a| a.iter().find(|l| l["id"] == id).cloned()).unwrap_or(Value::Null)
}

/// The minute of the last reading `port` holds for that unit's log.
fn last_minute(port: u16, id: &str) -> i64 {
    log_at(port, id)["readings"].as_array().and_then(|r| r.last()).and_then(|r| r["minute"].as_i64()).unwrap_or(-1)
}

fn link(port: u16, up: bool) -> u16 {
    post_json(&format!("http://127.0.0.1:{port}/link"), &json!({ "up": up }).to_string()).0
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node"])?;
    let work = work_dir("xtask-coldstore");
    fresh_dir(&work);
    let mut c = Checks::default();

    println!("The store and its head office");
    let store_did = did_for(&work, "store", "store.test", "store");
    let hq_did = did_for(&work, "hq", "hq.test", "hq");
    let mut store = Node::start(&work, "store", "store", STORE, &[base("store"), strs(&["--trust-did", &hq_did, "--store-sim", "0"])].concat());
    let port = store.p2p_port().ok_or("the store printed no P2P port")?;
    let connect = strs(&["--connect", &format!("wss://127.0.0.1:{port}/a2a"), "--pin-cert", &work.join("store").join("tls.cert.pem").display().to_string()]);
    let mut hq = Node::start(&work, "hq", "hq", HQ, &[base("hq"), strs(&["--trust-did", &store_did]), connect].concat());

    let s = state();
    let products = s["assessment"].as_array().map_or(0, |a| a.len());
    c.check("the store runs its cold room: 4 units, 8 products, all safe", s["units"].as_array().map_or(0, |u| u.len()) == 4 && products == 8 && s["assessment"].as_array().unwrap().iter().all(|p| p["status"] == "safe"), s.to_string());
    c.check("about €40,000 of stock, none lost", s["valueMinor"] == json!({ "sellable": 4_030_000, "lost": 0 }), s["valueMinor"].to_string());
    c.check(
        "the head office receives the store's temperature log, one document per unit",
        poll(60, 500, || ["frz-1", "frz-2", "chl-1", "chl-2"].iter().all(|u| last_minute(HQ, &format!("store::{u}")) == 0)),
        get_json(&format!("http://127.0.0.1:{HQ}/telemetry")).to_string(),
    );
    let l = log_at(HQ, "store::frz-2");
    c.check("...signed by the store's DID, and verified on arrival", l["signedBy"]["author"] == "store" && l["signedBy"]["did"] == json!(store_did), l["signedBy"].to_string());

    println!("A freezer's controller sticks in defrost at 02:10");
    let (code, _) = sim(json!({ "minutes": 20 }), "advance");
    c.check("the clock moves on to 02:10", code == 200 && state()["clock"] == "02:10", state()["clock"].to_string());
    let (code, _) = sim(json!({ "unit": "frz-2", "fault": "defrost-stuck" }), "fault");
    c.check("frz-2 is stuck in defrost", code == 200 && state()["units"][1]["fault"] == "defrost-stuck", code.to_string());
    let (code, s) = sim(json!({ "minutes": 10 }), "advance");
    c.check("ten minutes later it is warming", code == 200 && s["units"][1]["tempC"].as_f64().map_or(false, |t| t > -16.0), s["units"][1].to_string());
    let meat = product(&s, "FZ-MEAT");
    c.check("the frozen meat in it is at risk, with the minutes it has left", meat["status"] == "at-risk" && meat["minutesLeft"].as_u64().map_or(false, |m| (20..50).contains(&m)), meat.to_string());
    c.check("the failing freezer's products come first in the ranking", s["assessment"][0]["unit"] == "frz-2" && s["assessment"][1]["unit"] == "frz-2", s["assessment"].to_string());
    c.check("the rest of the store is safe", s["assessment"].as_array().unwrap().iter().filter(|p| p["unit"] != "frz-2").all(|p| p["status"] == "safe"), "");
    c.check("the head office sees the warming in the log", poll(60, 500, || last_minute(HQ, "store::frz-2") == 30), last_minute(HQ, "store::frz-2").to_string());
    c.check("...and the fault", log_at(HQ, "store::frz-2")["fault"] == "defrost-stuck", "");

    println!("The link is cut");
    c.check("the head office's link to the store is cut", link(HQ, false) == 200, "");
    sleep(2);
    let (code, s) = sim(json!({ "minutes": 60 }), "advance");
    c.check("the store keeps running and logging on its own", code == 200 && s["minute"] == 90, s["minute"].to_string());
    let meat = product(&s, "FZ-MEAT");
    c.check("the frozen meat is now unsafe: past its hard limit", meat["status"] == "unsafe" && meat["reason"].as_str().map_or(false, |r| r.contains("hard limit")), meat.to_string());
    c.check("its value counts as lost", s["valueMinor"]["lost"].as_u64().map_or(false, |v| v >= 1_780_000), s["valueMinor"].to_string());
    sleep(3);
    c.check("the head office, cut off, still has the reading of minute 30", last_minute(HQ, "store::frz-2") == 30, last_minute(HQ, "store::frz-2").to_string());
    c.check("the link comes back", link(HQ, true) == 200, "");
    c.check("the head office catches up with everything logged meanwhile", poll(80, 500, || last_minute(HQ, "store::frz-2") == 90), last_minute(HQ, "store::frz-2").to_string());
    let n = log_at(HQ, "store::frz-2")["readings"].as_array().map_or(0, |r| r.len());
    c.check("...a reading every five minutes, none missing", n == 19, format!("{n} readings"));

    println!("The freezer is repaired");
    let (code, _) = sim(json!({ "unit": "frz-2", "fault": null }), "fault");
    c.check("the fault is cleared", code == 200, code.to_string());
    let (_, s) = sim(json!({ "minutes": 240 }), "advance");
    c.check("the freezer is cold again", s["units"][1]["tempC"].as_f64().map_or(false, |t| t < -19.0), s["units"][1].to_string());
    c.check("what was lost stays lost", product(&s, "FZ-MEAT")["status"] == "unsafe", "");

    println!("Guards");
    let r = http_get(&format!("http://127.0.0.1:{HQ}/store/sim"));
    c.check("the head office runs no simulation", r.status == 404, r.status.to_string());
    let proxied = ureq::post(&format!("http://127.0.0.1:{STORE}/store/sim/fault"))
        .set("content-type", "application/json")
        .set("x-forwarded-for", "203.0.113.7")
        .send_string(&json!({ "unit": "frz-1", "fault": "defrost-stuck" }).to_string());
    let pcode = match proxied {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(_) => 0,
    };
    c.check("the simulation's controls refuse a request that came through a proxy", pcode == 403, pcode.to_string());
    let (code, _) = sim(json!({ "unit": "frz-9", "fault": "defrost-stuck" }), "fault");
    c.check("an unknown unit is refused", code == 400, code.to_string());
    c.check("no document was refused anywhere", rejections(STORE).is_empty() && rejections(HQ).is_empty(), format!("{:?} {:?}", rejections(STORE), rejections(HQ)));

    store.kill();
    hq.kill();
    Ok(c.finish())
}
