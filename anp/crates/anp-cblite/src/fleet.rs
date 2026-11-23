//! The head office's view of the fleet: every store whose signed records this node holds (its own and replicated ones, as verified), with
//! its cold-room units, its rescue agent's phase and what it has spent. Built only from the replicated `telemetry` and `rescue`
//! collections, so a head office needs nothing from a store but the replication link (peer to peer or through Sync Gateway).
//!
//! * `GET /fleet`       the view as JSON (this machine's operator only)
//! * `GET /demo/fleet`  the page that shows it (`fleet.html`)

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::docs::Docs;

/// A unit warmer than its setpoint by this many degrees is warming, even with no fault flagged (a door left open, a failing seal).
const WARMING_DELTA_C: f64 = 3.0;

fn unit_view(log: &Value) -> Value {
    let last = log["readings"].as_array().and_then(|r| r.last()).cloned().unwrap_or(Value::Null);
    let temp = last["tempC"].as_f64();
    let setpoint = log["setpointC"].as_f64();
    let state = match (log["fault"].as_str(), temp, setpoint) {
        (Some(_), _, _) => "fault",
        (None, Some(t), Some(s)) if t - s > WARMING_DELTA_C => "warming",
        _ => "ok",
    };
    json!({
        "id": log["unit"], "name": log["name"], "kind": log["kind"], "setpointC": setpoint, "tempC": temp,
        "fault": log["fault"], "state": state, "minute": last["minute"],
        "readings": log["readings"].as_array().map(|r| r.iter().rev().take(24).rev().filter_map(|x| x["tempC"].as_f64()).collect::<Vec<_>>()).unwrap_or_default(),
    })
}

/// What a rescue record says about the agent: its phase, what it has bought and spent.
fn rescue_view(rec: &Value) -> Value {
    let plan = rec["plan"].as_array().cloned().unwrap_or_default();
    let planned: u64 = plan.iter().filter_map(|p| p["amountMinor"].as_u64()).sum();
    let spent = rec["summary"]["spentMinor"].as_u64().unwrap_or(0);
    json!({
        "run": rec["run"], "phase": rec["phase"], "started": rec["started"], "clock": rec["clock"],
        "deals": rec["summary"]["confirmed"].as_u64().unwrap_or(0),
        "plannedMinor": planned, "spentMinor": spent,
        "waiting": rec["phase"] == "awaiting-approval",
        "lines": rec["log"].as_array().map_or(0, |l| l.len()),
    })
}

/// The fleet: a store per node that signed telemetry, worst first.
pub async fn view(docs: &Docs) -> Result<Value, String> {
    let logs = crate::coldstore::telemetry(docs).await?;
    let records = crate::rescue::records(docs).await?; // newest first
    let mut by_node: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for l in logs {
        if let Some(n) = l["node"].as_str() {
            by_node.entry(n.to_string()).or_default().push(l);
        }
    }
    let mut stores: Vec<Value> = by_node
        .into_iter()
        .map(|(node, logs)| {
            let units: Vec<Value> = logs.iter().map(unit_view).collect();
            let failing = units.iter().filter(|u| u["state"] != "ok").count();
            let rescue = records.iter().find(|r| r["node"] == json!(node)).map(rescue_view);
            json!({
                "node": node, "site": logs[0]["site"], "clock": logs.iter().filter_map(|l| l["clock"].as_str()).max(),
                "signedBy": logs[0]["signedBy"],
                "units": units, "failing": failing,
                "rescue": rescue,
            })
        })
        .collect();
    // worst first: waiting for the duty manager, then most units failing, then by name
    stores.sort_by(|a, b| {
        let key = |s: &Value| (std::cmp::Reverse(s["rescue"]["waiting"].as_bool().unwrap_or(false)), std::cmp::Reverse(s["failing"].as_u64().unwrap_or(0)), s["node"].as_str().unwrap_or("").to_string());
        key(a).cmp(&key(b))
    });
    let failing_stores = stores.iter().filter(|s| s["failing"].as_u64().unwrap_or(0) > 0).count();
    let failing_units: u64 = stores.iter().map(|s| s["failing"].as_u64().unwrap_or(0)).sum();
    let spent: u64 = stores.iter().map(|s| s["rescue"]["spentMinor"].as_u64().unwrap_or(0)).sum();
    let rescuing = stores.iter().filter(|s| !matches!(s["rescue"]["phase"].as_str(), None | Some("idle" | "done" | "failed" | "declined"))).count();
    Ok(json!({
        "stores": stores,
        "totals": { "stores": stores.len(), "failingStores": failing_stores, "failingUnits": failing_units, "rescuing": rescuing, "spentMinor": spent },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_is_ok_warming_or_faulted() {
        let log = |fault: Option<&str>, t: f64| json!({ "unit": "frz-1", "name": "Freezer 1", "kind": "freezer", "setpointC": -20.0, "fault": fault, "readings": [{ "minute": 5, "tempC": t }] });
        assert_eq!(unit_view(&log(None, -19.5))["state"], "ok");
        assert_eq!(unit_view(&log(None, -15.0))["state"], "warming", "warmer than the setpoint by more than 3 degrees");
        assert_eq!(unit_view(&log(Some("defrost-stuck"), -19.9))["state"], "fault", "a fault counts at once, before the temperature moves");
        assert_eq!(unit_view(&json!({ "unit": "x", "setpointC": -20.0 }))["state"], "ok", "no reading yet");
    }

    #[test]
    fn a_rescue_record_becomes_a_phase_and_a_spend() {
        let rec = json!({ "run": "r1", "phase": "awaiting-approval", "log": [1, 2, 3], "plan": [{ "amountMinor": 1200 }, { "amountMinor": 300 }], "summary": null });
        let v = rescue_view(&rec);
        assert_eq!((v["phase"].clone(), v["plannedMinor"].clone(), v["waiting"].clone(), v["lines"].clone()), (json!("awaiting-approval"), json!(1500), json!(true), json!(3)));
        let done = rescue_view(&json!({ "run": "r1", "phase": "done", "summary": { "confirmed": 6, "spentMinor": 10500 }, "plan": [] }));
        assert_eq!((done["spentMinor"].clone(), done["deals"].clone(), done["waiting"].clone()), (json!(10500), json!(6), json!(false)));
    }
}
