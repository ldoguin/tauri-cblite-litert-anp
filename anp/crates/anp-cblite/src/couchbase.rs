//! The Couchbase pieces a node is made of, as they are right now: its Couchbase Lite database (documents per collection), how it replicates
//! (peer to peer, or with a Sync Gateway), and, when there is a Sync Gateway, what that says (online, its update sequence, the documents it
//! holds for this node's user, which are the documents in Couchbase Server for the channels that user may read). Shown by `GET /couchbase`
//! and drawn on the control room and the fleet view, so what moves where can be seen, not told.

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

use crate::docs::Coll;
use crate::hub::Hub;

/// This node's Couchbase Lite database, its replication, and the gateway's state.
pub async fn describe(hub: &Hub) -> Value {
    let mut cols = serde_json::Map::new();
    let mut total = 0u64;
    for c in Coll::ALL {
        let n = hub.docs.list(c).await.map(|l| l.len() as u64).unwrap_or(0);
        total += n;
        cols.insert(c.name().to_string(), json!(n));
    }
    json!({
        "node": hub.node_id,
        "database": { "engine": "Couchbase Lite", "scope": crate::docs::SCOPE, "collections": cols, "total": total },
        "replication": hub.replication(),
        "linkUp": hub.link().map(|l| l.is_up()),
        "gateway": hub.gateway_state(),
    })
}

/// `ws://host:4984/db` as `http://host:4984/db`.
fn http_base(ws_url: &str) -> String {
    ws_url.replacen("wss://", "https://", 1).replacen("ws://", "http://", 1).trim_end_matches('/').to_string()
}

fn get(url: &str, auth: &str) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
    let res = agent.get(url).set("Authorization", auth).call().map_err(|e| e.to_string())?;
    let text = res.into_string().map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// Ask the Sync Gateway as this node's user: is the database online, at which sequence, and how many documents each collection holds for it.
fn probe(base: &str, user: &str, password: &str, only: &[String]) -> Value {
    let auth = format!("Basic {}", B64.encode(format!("{user}:{password}")));
    let info = match get(&format!("{base}/"), &auth) {
        Ok(v) => v,
        Err(e) => return json!({ "url": base, "online": false, "error": e }),
    };
    let mut docs = serde_json::Map::new();
    let mut total = 0u64;
    for c in Coll::ALL {
        // `_all_docs` lists what this user may read; a collection with none (or that the user may not list) counts 0
        // (with `only`, just the documents whose id starts with one of those prefixes: a demo's own, not what earlier runs left)
        let n = get(&format!("{base}.{}.{}/_all_docs", crate::docs::SCOPE, c.name()), &auth)
            .ok()
            .and_then(|v| v["rows"].as_array().map(|r| r.iter().filter(|row| only.is_empty() || row["id"].as_str().map_or(false, |id| only.iter().any(|p| id.starts_with(p.as_str())))).count() as u64))
            .unwrap_or(0);
        total += n;
        docs.insert(c.name().to_string(), json!(n));
    }
    json!({
        "url": base, "online": info["state"] == "Online", "state": info["state"], "database": info["db_name"], "updateSeq": info["update_seq"],
        "user": user, "docs": docs, "total": total, "checkedAt": chrono::Utc::now().to_rfc3339(),
    })
}

/// Poll the gateway this node replicates with every two seconds and keep what it says in the hub.
pub fn follow_gateway(hub: Arc<Hub>, ws_url: String, user: String, password: String, only: Vec<String>) {
    let base = http_base(&ws_url);
    tokio::spawn(async move {
        loop {
            let (b, u, p, o) = (base.clone(), user.clone(), password.clone(), only.clone());
            if let Ok(state) = tokio::task::spawn_blocking(move || probe(&b, &u, &p, &o)).await {
                hub.set_gateway_state(state);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_websocket_url_becomes_the_gateways_http_address() {
        assert_eq!(http_base("ws://127.0.0.1:4984/anp"), "http://127.0.0.1:4984/anp");
        assert_eq!(http_base("wss://sg.example.com:4984/anp/"), "https://sg.example.com:4984/anp");
    }

    #[test]
    fn an_unreachable_gateway_is_reported_offline_not_an_error() {
        let v = probe("http://127.0.0.1:1/anp", "u", "p", &[]);
        assert_eq!(v["online"], false);
        assert!(v["error"].is_string());
    }
}
