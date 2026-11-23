//! Finding companies through a search agent (ANP-08 passive discovery, `anp-search`), instead of being handed a directory.
//!
//! * A company's node registers its own signed agent description with the search agent when it starts (`--register-with`). The search
//!   agent fetches it over HTTPS, resolves the company's `did:wba` over HTTPS, checks the description's proof against it, and only then
//!   indexes it. A description says what the company does in its own words; a counterparty's says it with its role's phrase
//!   ([`anp_counterparty::role_phrase`]).
//! * The store's agent (`--rescue-search`) asks the search agent for each role it needs, keeps the results whose verified description
//!   has that role's phrase, and calls them by their DIDs: the node resolves each one over HTTPS from its own domain before talking to it.

use std::time::Duration;

use serde_json::{json, Value};

use crate::rescue::Company;

/// A counterparty profile's description (what its agent description says it does), if it is one.
pub fn profile_description(profile: &str) -> Option<String> {
    anp_counterparty::Profile::builtin(profile).map(|p| p.description())
}

/// A counterparty profile's company name (the name its agent description gives), if it is one.
pub fn profile_name(profile: &str) -> Option<String> {
    anp_counterparty::Profile::builtin(profile).map(|p| p.name)
}

fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let text = match ureq::post(url).timeout(Duration::from_secs(20)).set("content-type", "application/json").send_string(&body) {
        Ok(r) => r.into_string().map_err(|e| e.to_string())?,
        Err(ureq::Error::Status(c, r)) => return Err(format!("the search agent answered HTTP {c}: {}", r.into_string().unwrap_or_default())),
        Err(e) => return Err(e.to_string()),
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("the search agent's answer: {e}"))?;
    match v.get("error") {
        Some(e) => Err(format!("the search agent refused {method}: {}", e["message"].as_str().unwrap_or(""))),
        None => Ok(v["result"].clone()),
    }
}

/// Register the description at `ad_url` with the search agent at `search_url`, trying again for a while (the search agent, or this
/// node's own HTTPS front, may not be up yet).
pub async fn register_until_done(search_url: String, ad_url: String) {
    for attempt in 1..=60 {
        let (s, a) = (search_url.clone(), ad_url.clone());
        match tokio::task::spawn_blocking(move || rpc(&s, "register", json!({ "url": a }))).await {
            Ok(Ok(e)) => {
                log::info!("registered {ad_url} with the search agent as {}", e["name"]);
                return;
            }
            Ok(Err(e)) => log::warn!("registration with the search agent, attempt {attempt}: {e}"),
            Err(e) => log::warn!("registration task: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    log::warn!("gave up registering {ad_url} with the search agent");
}

/// The companies the search agent knows for `role`: those whose verified description has the role's phrase.
pub async fn find(search_url: &str, role: &str) -> Result<Vec<Company>, String> {
    let phrase = anp_counterparty::role_phrase(role).ok_or_else(|| format!("no search phrase for the role {role}"))?;
    let url = search_url.to_string();
    let found = tokio::task::spawn_blocking(move || rpc(&url, "search", json!({ "query": phrase, "limit": 20 }))).await.map_err(|e| e.to_string())??;
    Ok(found["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["description"].as_str().map_or(false, |d| d.to_lowercase().contains(phrase)))
        .filter_map(|r| Some(Company { did: r["did"].as_str()?.to_string(), role: role.to_string(), name: r["name"].as_str().unwrap_or("").to_string() }))
        .collect())
}
