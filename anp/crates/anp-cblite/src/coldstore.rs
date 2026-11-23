//! A node that runs the simulated cold room of its store (`--store-sim SPEED`, see `anp-coldstore`) and publishes its temperature
//! log to the mesh.
//!
//! Every five simulated minutes each unit's reading is added to its log, and the log (the last twelve hours) is written as one
//! document per unit in the replicated `telemetry` collection, `<node>::<unit>`: signed by this node like every document it writes,
//! checked by every node that reads it, and only this node may write it. A head office node that replicates with the store sees the
//! log as it is written, and catches up when a cut link comes back (`POST /link`); the store keeps logging while it is cut off.
//!
//! The clock runs at SPEED simulated minutes per second (0: only when told to, `POST /store/sim/advance`, which is how tests drive
//! it). The simulation's state lives in memory: a restart starts the scenario again.
//!
//! * `GET  /store/sim`                      the units, the assessment of every product, what is sellable and what is lost
//! * `POST /store/sim/fault`  `{"unit": "frz-1", "fault": "defrost-stuck" | "compressor-off" | null}`
//! * `POST /store/sim/advance` `{"minutes": 30}`
//! * `GET  /telemetry`                      every unit's log this node holds, its own and replicated ones, as verified
//!
//! All of them answer only this machine (see `server::local_caller`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anp_coldstore::{Fault, Store};
use serde_json::{json, Value};

use crate::docs::{Coll, Docs};

/// A reading every this many simulated minutes.
pub const READING_EVERY_MIN: u32 = 5;
/// How many readings a unit's log keeps (twelve hours).
pub const LOG_READINGS: usize = 144;

pub struct ColdStoreSim {
    node: String,
    docs: Docs,
    speed: u32,
    store: Mutex<Store>,
    readings: Mutex<HashMap<String, Vec<Value>>>,
    /// One change of the store at a time, readings published in order.
    busy: tokio::sync::Mutex<()>,
}

impl ColdStoreSim {
    /// The store-0412 scenario, run by `node` (its readings are `<node>::<unit>`), at `speed` simulated minutes per second.
    pub fn new(node: &str, docs: Docs, speed: u32) -> ColdStoreSim {
        let store = Store::scenario_0412();
        let readings = store.units.iter().map(|u| (u.id.clone(), vec![reading(&store, u.temp_c)])).collect();
        ColdStoreSim { node: node.to_string(), docs, speed, store: Mutex::new(store), readings: Mutex::new(readings), busy: tokio::sync::Mutex::new(()) }
    }

    /// Publish the first readings, then let the clock run (if it runs on its own).
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.publish().await {
                log::warn!("store simulation: could not publish the readings: {e}");
            }
            if me.speed == 0 {
                return;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                if let Err(e) = me.advance(me.speed).await {
                    log::warn!("store simulation: {e}");
                }
            }
        });
    }

    pub fn state(&self) -> Value {
        let mut v = self.store.lock().unwrap().to_json();
        v["speedMinPerSec"] = json!(self.speed);
        v["node"] = json!(self.node);
        v
    }

    /// Move the clock on, logging a reading per unit every [`READING_EVERY_MIN`] minutes, and publish the logs.
    pub async fn advance(&self, minutes: u32) -> Result<Value, String> {
        if minutes > 24 * 60 {
            return Err("advance at most a day at a time".into());
        }
        let _busy = self.busy.lock().await;
        {
            let mut s = self.store.lock().unwrap();
            let mut r = self.readings.lock().unwrap();
            for _ in 0..minutes {
                s.advance(1);
                if s.minute % READING_EVERY_MIN == 0 {
                    for u in &s.units {
                        let log = r.entry(u.id.clone()).or_default();
                        log.push(reading(&s, u.temp_c));
                        if log.len() > LOG_READINGS {
                            log.remove(0);
                        }
                    }
                }
            }
        }
        self.publish().await?;
        Ok(self.state())
    }

    /// Put a unit in a fault, or (`None`) back to normal; the change is logged at once.
    pub async fn set_fault(&self, unit: &str, fault: Option<Fault>) -> Result<Value, String> {
        let _busy = self.busy.lock().await;
        self.store.lock().unwrap().set_fault(unit, fault)?;
        log::info!("store simulation: {unit} is now {}", fault.map_or("working", Fault::name));
        self.publish().await?;
        Ok(self.state())
    }

    /// Write each unit's log to the replicated collection (signed by this node).
    async fn publish(&self) -> Result<(), String> {
        let docs: Vec<(String, Value)> = {
            let s = self.store.lock().unwrap();
            let r = self.readings.lock().unwrap();
            s.units
                .iter()
                .map(|u| {
                    let body = json!({
                        "node": self.node, "site": s.site, "unit": u.id, "name": u.name, "kind": u.kind,
                        "setpointC": u.setpoint_c, "fault": u.fault.map(Fault::name),
                        "minute": s.minute, "clock": s.clock(), "everyMin": READING_EVERY_MIN,
                        "readings": r.get(&u.id).cloned().unwrap_or_default(),
                    });
                    (format!("{}::{}", self.node, u.id), body)
                })
                .collect()
        };
        for (id, body) in docs {
            self.docs.put(Coll::Telemetry, &id, body).await?;
        }
        Ok(())
    }
}

fn reading(s: &Store, temp: f64) -> Value {
    json!({ "minute": s.minute, "clock": s.clock(), "tempC": (temp * 10.0).round() / 10.0 })
}

/// Every unit's log in this node's store, its own and replicated ones, as verified (a document that does not verify is not
/// shown: the store layer treats it as absent).
pub async fn telemetry(docs: &Docs) -> Result<Vec<Value>, String> {
    let mut out: Vec<Value> = docs
        .list(Coll::Telemetry)
        .await?
        .into_iter()
        .map(|(id, mut v)| {
            v["id"] = json!(id);
            // the signature block, verified already: say who signed, not the whole block (it carries the token and DID document)
            let signed = json!({ "author": v["trust"]["author"], "did": v["trust"]["did"], "seq": v["trust"]["seq"] });
            if let Some(o) = v.as_object_mut() {
                o.remove("trust");
            }
            v["signedBy"] = signed;
            v
        })
        .collect();
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(out)
}
