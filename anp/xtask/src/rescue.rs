//! `cargo xtask e2e-rescue`: the whole cold-stock rescue, run by the store's agent on its own, on ten nodes: the store (its cold room, its
//! buying desk, its agent), eight companies on their own domains, and a group host. Freezer 1 and the dairy chiller fail first (the ice
//! cream is lost before anyone acts); then freezer 2. The agent assesses, asks every company at once, chooses through its rules (a carrier
//! that arrives in time, the cheapest; cold storage re-planned when the cheapest warehouse has room for only two of three pallets; the
//! dairy to the food bank; the lost pallets restocked), finds the plan over its budget and asks the duty manager, then commits, opens an
//! encrypted group with every company that confirmed, posts the plan there, and audits every deal.

use crate::harness::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const HOST: u16 = 19101;
const STORE: u16 = 19102;
const SELLERS: [(&str, &str, u16); 8] = [
    ("frostline", "carrier", 19103),
    ("polar", "carrier", 19104),
    ("coldchain", "carrier", 19105),
    ("rungis-cold", "warehouse", 19106),
    ("orly-freeze", "warehouse", 19107),
    ("foodbank", "foodbank", 19108),
    ("insurer", "insurer", 19109),
    ("supplier", "supplier", 19110),
];

fn host_url() -> String {
    format!("http://127.0.0.1:{HOST}")
}

fn base(name: &str, port: u16) -> Vec<String> {
    strs(&["--did-host", &format!("{name}.test"), "--e2ee", "--direct-messaging", "--require-auth", "--public-origin", &format!("http://127.0.0.1:{port}"), "--group-member", &host_url()])
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

fn rescue() -> Value {
    get_json(&format!("http://127.0.0.1:{STORE}/rescue"))
}

fn act(path: &str, body: Value) -> (u16, Value) {
    post_json(&format!("http://127.0.0.1:{STORE}{path}"), &body.to_string())
}

fn wait_phase(phases: &[&str], secs: u32) -> String {
    let mut p = String::new();
    poll(secs * 2, 500, || {
        p = rescue()["phase"].as_str().unwrap_or_default().to_string();
        phases.contains(&p.as_str())
    });
    p
}

/// Does the agent's log have a line containing `text` (and, if given, decided by `rule`)?
fn logged(r: &Value, text: &str, rule: Option<&str>) -> bool {
    r["log"].as_array().map_or(false, |l| l.iter().any(|e| e["text"].as_str().map_or(false, |t| t.contains(text)) && rule.map_or(true, |ru| e["rule"] == ru)))
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub fn run() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin"])?;
    let work = work_dir("xtask-rescue");
    fresh_dir(&work);
    let mut c = Checks::default();
    let night = bring_up(&work)?;
    c.check("the retailer's authority gives the store €6,000 per commitment, for store 0412", night.token_issued.0 == 0, &night.token_issued.1);
    let (mut store, mut nodes, sellers) = (night.store, night.others, night.sellers);
    c.check("the store's agent is idle, with eight companies in its directory", rescue()["phase"] == "idle" && rescue()["directory"].as_array().map_or(0, |d| d.len()) == 8, rescue().to_string());
    play(&mut c, &sellers);
    store.kill();
    for n in &mut nodes {
        n.kill();
    }
    Ok(c.finish())
}

/// The ten nodes of the night, running.
pub struct Night {
    pub store: Node,
    pub others: Vec<Node>,
    /// `(profile, role, did, document file, port)` of each company.
    pub sellers: Vec<(String, String, String, PathBuf, u16)>,
    /// What `anp-admin issue` answered for the store's spending token.
    pub token_issued: (i32, String),
}

/// The store's port (its control room is `http://127.0.0.1:<STORE>/demo/rescue`).
pub const STORE_PORT: u16 = STORE;

/// Bring up the night's ten nodes: the retailer's authority and the store's spending token (€6,000 per commitment), eight companies on
/// their own domains, a group host, and the store with its cold room (clock stopped), buying desk and agent.
pub fn bring_up(work: &Path) -> Result<Night, String> {
    println!("Ten nodes: the store, eight companies, a group host");
    let root = root_key(work, "retailer");
    let work = work.to_path_buf();
    let (store_did, store_doc) = document(&work, "store", STORE)?;
    let store_key = std::fs::read_to_string(work.join("store").join("node.pub")).map_err(|e| e.to_string())?.trim().to_string();
    let token = work.join("store.token");
    let token_issued = run_tool(
        "anp-admin",
        &strs(&[
            "issue", "--root", &work.join("retailer.key").display().to_string(), "--node", "store", "--key", &store_key, "--did", &store_did, "--days", "1",
            "--spend-cap", "6000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", "store-0412",
            "--out", &token.display().to_string(),
        ]),
    );
    let mut sellers: Vec<(String, String, String, PathBuf, u16)> = vec![];
    for (name, role, port) in SELLERS {
        let (did, doc) = document(&work, name, port)?;
        sellers.push((name.to_string(), role.to_string(), did, doc, port));
    }
    let directory: Vec<Value> = sellers.iter().map(|(n, r, d, _, _)| json!({ "did": d, "role": r, "name": anp_name(n) })).collect();
    let dir_file = work.join("directory.json");
    std::fs::write(&dir_file, Value::Array(directory).to_string()).map_err(|e| e.to_string())?;

    let mut host_args = strs(&["--did-host", "groups.test", "--group-host", "--require-auth", "--public-origin", &host_url(), "--allow-caller", &store_doc.display().to_string()]);
    for (_, _, _, doc, _) in &sellers {
        host_args.extend(strs(&["--allow-caller", &doc.display().to_string()]));
    }
    let mut nodes = vec![Node::start(&work, "groups", "groups", HOST, &host_args)];
    for (name, _, _, _, port) in &sellers {
        let extra = [base(name, *port), peer(&store_doc, &store_did, STORE), strs(&["--counterparty", name, "--buyer-root", &root, "--agent", "echo"])].concat();
        nodes.push(Node::start(&work, name, name, *port, &extra));
    }
    let mut store_args = [
        base("store", STORE),
        strs(&["--store-sim", "0", "--spend-token", &token.display().to_string(), "--spend-root", &root, "--budget", "6000", "--site", "store-0412", "--rescue", &dir_file.display().to_string()]),
    ]
    .concat();
    for (_, _, did, doc, port) in &sellers {
        store_args.extend(peer(doc, did, *port));
    }
    let store = Node::start(&work, "store", "store", STORE, &store_args);
    Ok(Night { store, others: nodes, sellers, token_issued })
}

/// The search agent's port (plain HTTP JSON-RPC at `/`).
pub const SEARCH_PORT: u16 = 19111;

/// Where a node's HTTPS front listens (its DID names `localhost:<this port>`).
fn tls(port: u16) -> u16 {
    port + 100
}

fn search_rpc(method: &str, params: Value) -> Value {
    post_json(&format!("http://127.0.0.1:{SEARCH_PORT}/"), &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string()).1
}

/// The same night with nothing handed out in advance: every node is a `did:wba` on its own HTTPS origin (`localhost:<port>`, behind a TLS
/// front with a CA made for the run), the companies register their signed descriptions with a search agent, and the store's agent finds
/// them there. Every node resolves the DIDs it meets over HTTPS. The one thing every resolver is given is the test CA.
pub fn bring_up_discovered(work: &Path) -> Result<Night, String> {
    bring_up_discovered_with(work, &[])
}

/// [`bring_up_discovered`], with more options for the store's node (an adviser model, ...).
pub fn bring_up_discovered_with(work: &Path, extra_store: &[String]) -> Result<Night, String> {
    println!("Ten nodes and a search agent; every DID resolved over HTTPS, nothing handed out");
    let root = root_key(work, "retailer");
    let work = work.to_path_buf();
    let ca = crate::tlsfront::test_ca(&work)?;
    let ports: Vec<u16> = [HOST, STORE].into_iter().chain(SELLERS.iter().map(|s| s.2)).collect();
    for p in &ports {
        ca.front(tls(*p), *p)?;
    }
    let pem = ca.pem_file.display().to_string();
    let mut trust = strs(&["--resolver-roots", &pem, "--resolver-allow-private"]);
    for p in &ports {
        trust.extend(strs(&["--trust-domain", &format!("localhost:{}", tls(*p))]));
    }
    // a node: its DID on its HTTPS origin; requests to it signed (ANP-02) for its plain port, where its message service is
    let node = |port: u16| -> Vec<String> {
        [
            strs(&[
                "--did-host", &format!("localhost:{}", tls(port)), "--e2ee", "--direct-messaging", "--require-auth", "--public-origin", &format!("http://127.0.0.1:{port}"),
                "--message-endpoint", &format!("http://127.0.0.1:{port}/anp/direct"), "--group-member", &host_url(),
            ]),
            trust.clone(),
        ]
        .concat()
    };

    let store_did = did_for(&work, "store", &format!("localhost:{}", tls(STORE)), "store");
    let store_key = std::fs::read_to_string(work.join("store").join("node.pub")).map_err(|e| e.to_string())?.trim().to_string();
    let token = work.join("store.token");
    let token_issued = run_tool(
        "anp-admin",
        &strs(&[
            "issue", "--root", &work.join("retailer.key").display().to_string(), "--node", "store", "--key", &store_key, "--did", &store_did, "--days", "1",
            "--spend-cap", "6000", "--currency", "EUR", "--spend-category", "transport,storage,donation,coverage,restock", "--spend-for", "store-0412",
            "--out", &token.display().to_string(),
        ]),
    );

    let search_url = format!("http://127.0.0.1:{SEARCH_PORT}/");
    let mut nodes = vec![Node::start_program(
        &work,
        "anp-search",
        "search",
        &strs(&["--data", &work.join("search").display().to_string(), "--http-port", &SEARCH_PORT.to_string(), "--did-host", &format!("localhost:{SEARCH_PORT}"), "--resolver-roots", &pem, "--resolver-allow-private"]),
    )];
    let host_args = [strs(&["--did-host", &format!("localhost:{}", tls(HOST)), "--group-host", "--require-auth", "--public-origin", &host_url()]), trust.clone()].concat();
    nodes.push(Node::start(&work, "groups", "groups", HOST, &host_args));
    let mut sellers: Vec<(String, String, String, PathBuf, u16)> = vec![];
    for (name, role, port) in SELLERS {
        let extra = [node(port), strs(&["--counterparty", name, "--buyer-root", &root, "--agent", "echo", "--register-with", &search_url])].concat();
        nodes.push(Node::start(&work, name, name, port, &extra));
        sellers.push((name.to_string(), role.to_string(), String::new(), PathBuf::new(), port));
    }
    let store_args = [
        node(STORE),
        strs(&["--store-sim", "0", "--spend-token", &token.display().to_string(), "--spend-root", &root, "--budget", "6000", "--site", "store-0412", "--rescue-search", &search_url]),
        extra_store.to_vec(),
    ]
    .concat();
    let store = Node::start(&work, "store", "store", STORE, &store_args);
    // the companies register themselves; the search agent verifies each description before it lists it
    poll(120, 500, || search_rpc("list", json!({}))["result"]["total"] == 8);
    Ok(Night { store, others: nodes, sellers, token_issued })
}

/// `cargo xtask e2e-discovery`: the night with discovery, checked.
pub fn run_discovered() -> Result<i32, String> {
    require_bins(&["anp-node", "anp-admin", "anp-search"])?;
    let work = work_dir("xtask-discovery");
    fresh_dir(&work);
    let mut c = Checks::default();
    let night = bring_up_discovered(&work)?;
    c.check("the retailer's authority gives the store €6,000 per commitment, for store 0412", night.token_issued.0 == 0, &night.token_issued.1);
    let (mut store, mut nodes, sellers) = (night.store, night.others, night.sellers);

    println!("Discovery");
    let listed = search_rpc("list", json!({}))["result"].clone();
    c.check("the eight companies registered their signed descriptions, and the search agent verified and listed them", listed["total"] == 8, listed.to_string());
    let entries = listed["entries"].as_array().cloned().unwrap_or_default();
    c.check(
        "each listing is a did:wba on its own HTTPS origin, with the company's name and what it does",
        entries.iter().all(|e| e["did"].as_str().map_or(false, |d| d.starts_with("did:wba:localhost%3A")) && e["url"].as_str().map_or(false, |u| u.starts_with("https://localhost:"))),
        Value::Array(entries.clone()).to_string(),
    );
    let found = search_rpc("search", json!({ "query": "refrigerated transport" }))["result"]["results"].clone();
    let names: Vec<&str> = found.as_array().into_iter().flatten().filter_map(|r| r["name"].as_str()).collect();
    c.check("a search for refrigerated transport finds the three carriers first", names.len() >= 3 && names[..3].iter().all(|n| ["FrostLine Logistics", "Polar Express", "ColdChain Rungis"].contains(n)), format!("{names:?}"));
    let r = rescue();
    c.check("the store's agent starts with no directory: it will search", r["phase"] == "idle" && r["discovery"] == "search agent" && r["directory"].as_array().map_or(true, |d| d.is_empty()), r.to_string());

    play(&mut c, &sellers);
    let r = rescue();
    for (role, n) in [("carrier", 3), ("warehouse", 2), ("foodbank", 1), ("insurer", 1), ("supplier", 1)] {
        c.check(&format!("the agent found {n} {role}(s) through the search agent"), logged(&r, &format!("{n} {role}(s) found"), None), "");
    }
    c.check("and talked to all eight without having been given any DID document (resolved over HTTPS)", r["directory"].as_array().map_or(0, |d| d.len()) == 8, r["directory"].to_string());

    store.kill();
    for n in &mut nodes {
        n.kill();
    }
    Ok(c.finish())
}

/// `cargo xtask e2e-model --model FILE.litertlm`: the night with discovery and an on-device model advising the agent (a LiteRT build of the
/// node: Linux or macOS, for example in WSL). The model proposes the carrier and the cold storage; the rules decide. It may choose otherwise
/// than the rules would, so this checks the protocol around it, not its taste: it was asked; its proposal was either followed with every rule
/// holding, or set aside with the rule it broke; and every deal the agent made was confirmed by its company and audits.
pub fn run_model(args: &[String]) -> Result<i32, String> {
    let model = opt(args, "--model").ok_or("give the model: --model FILE.litertlm")?;
    require_bins(&["anp-node", "anp-admin", "anp-search"])?;
    let work = work_dir("xtask-model");
    fresh_dir(&work);
    let mut c = Checks::default();
    let night = bring_up_discovered_with(&work, &strs(&["--rescue-model", &model]))?;
    let (mut store, mut nodes) = (night.store, night.others);
    // the node loads the model before it serves anything: that takes a while
    let up = poll(600, 500, || rescue()["phase"] == "idle");
    let r = rescue();
    c.check("the store's agent is up with the model as its adviser", up && r["advisor"].is_string(), format!("{}", r["advisor"]));

    println!("The night");
    act("/store/sim/fault", json!({ "unit": "frz-1", "fault": "defrost-stuck" }));
    act("/store/sim/fault", json!({ "unit": "chl-1", "fault": "compressor-off" }));
    act("/store/sim/advance", json!({ "minutes": 50 }));
    act("/store/sim/fault", json!({ "unit": "frz-2", "fault": "defrost-stuck" }));
    act("/store/sim/advance", json!({ "minutes": 1 }));
    let (code, _) = act("/rescue/start", json!({}));
    c.check("the agent starts", code == 200, code.to_string());
    let phase = wait_phase(&["awaiting-approval", "done", "failed"], 900);
    let r = rescue();
    const RULE: &str = "the model proposes, the rules decide";
    c.check("it asked the on-device model for a plan", logged(&r, "asking the on-device model", None), "");
    let verdict = r["log"].as_array().and_then(|l| l.iter().find(|e| e["rule"] == RULE && !e["text"].as_str().unwrap_or("").contains("not chosen")).cloned()).unwrap_or(Value::Null);
    let followed = verdict["text"].as_str().map_or(false, |t| t.contains("every rule holds"));
    let set_aside = verdict["text"].as_str().map_or(false, |t| t.contains("the rules choose"));
    c.check("the model's answer went through the rules: followed with every rule holding, or set aside with the reason", followed || set_aside, verdict.to_string());
    c.note(&format!("the model said: {}", verdict["data"]["answer"].as_str().unwrap_or("(nothing)").replace('\n', " ")));
    c.note(&format!("{} in {:.0} s", if followed { "followed" } else { "set aside" }, verdict["data"]["seconds"].as_f64().unwrap_or(0.0)));
    c.check("the plan still went to the duty manager over the budget", phase == "awaiting-approval", phase.clone());
    let (code, _) = act("/rescue/approve", json!({ "budget": "20000" }));
    c.check("the duty manager approves", code == 200, code.to_string());
    let phase = wait_phase(&["done", "failed"], 300);
    let r = rescue();
    c.check("the rescue completes", phase == "done", format!("{phase} {}", r["log"].as_array().and_then(|l| l.last()).cloned().unwrap_or_default()));
    let s = &r["summary"];
    c.check("every deal the agent made was confirmed by its company, and audits", s["confirmed"].as_u64().unwrap_or(0) >= 4 && s["audited"] == s["confirmed"], s.to_string());
    c.note(&format!("spent €{}", s["spentMinor"].as_u64().unwrap_or(0) / 100));

    store.kill();
    for n in &mut nodes {
        n.kill();
    }
    Ok(c.finish())
}

/// The night, checked step by step.
fn play(c: &mut Checks, sellers: &[(String, String, String, PathBuf, u16)]) {
    println!("The night: freezer 1 and the dairy chiller fail at 01:50, freezer 2 at 02:40");
    act("/store/sim/fault", json!({ "unit": "frz-1", "fault": "defrost-stuck" }));
    act("/store/sim/fault", json!({ "unit": "chl-1", "fault": "compressor-off" }));
    act("/store/sim/advance", json!({ "minutes": 50 }));
    act("/store/sim/fault", json!({ "unit": "frz-2", "fault": "defrost-stuck" }));
    let (_, s) = act("/store/sim/advance", json!({ "minutes": 1 }));
    let status = |sku: &str| s["assessment"].as_array().and_then(|a| a.iter().find(|p| p["sku"] == sku)).map(|p| p["status"].clone()).unwrap_or(Value::Null);
    c.check("by 02:41 the ice cream is lost, the frozen meat and the dairy are at risk", status("FZ-ICE") == "unsafe" && status("FZ-MEAT") == "at-risk" && status("CH-MILK") == "at-risk", s["assessment"].to_string());

    println!("The agent takes over");
    let (code, _) = act("/rescue/start", json!({}));
    c.check("the agent starts", code == 200, code.to_string());
    let phase = wait_phase(&["awaiting-approval", "done", "failed"], 150);
    let r = rescue();
    c.check("it assesses: 3 frozen pallets at risk, 3 chilled, 2 products lost", logged(&r, "3 frozen pallet(s) at risk", None) && logged(&r, "3 chilled pallet(s) at risk", None), r["log"][0].to_string());
    c.check("it keeps the lost ice cream out of every plan", logged(&r, "FZ-ICE is past its safety limit", Some("nothing unsafe is kept")) && !r["log"][0]["data"]["frozen"].to_string().contains("FZ-ICE"), "");
    c.check("it asks every company at once: Polar declines (no truck before 06:00)", logged(&r, "Polar Express declines: no refrigerated truck free before 06:00", None), "");
    c.check("ColdChain is chosen; FrostLine, which also arrives in time, costs €4,000 more", logged(&r, "FrostLine Logistics costs €4,000 more than ColdChain Rungis", Some("cheapest carrier that arrives in time")), "");
    c.check("Rungis has room for only 2 of the 3 pallets: the agent re-plans", logged(&r, "Rungis Cold Store has room for 2 of the 3 pallets", Some("re-plan when an offer falls short")), "");
    c.check("...and Orly Freeze takes the last pallet (asked again, for 1 pallet: €1,500)", logged(&r, "Orly Freeze takes the remaining 1 pallet(s)", Some("re-plan when an offer falls short")), "");
    c.check("moving is worth it: €8,700 to save €17,800 of frozen stock", logged(&r, "costs €8,700 and saves €17,800", Some("only move what is worth more than moving it")), "");
    c.check("the dairy goes to the food bank (room for 2 pallets)", logged(&r, "go to Banque Alimentaire 94", Some("give away what cannot be kept cold")), "");
    c.check("the lost pallets are restocked for the morning", logged(&r, "Grossiste Frais IDF restocks them", Some("replace what cannot be saved")), "");
    c.check("the plan costs €10,500, over the €6,000 budget: the agent stops and asks the duty manager", phase == "awaiting-approval" && r["approval"]["planMinor"] == 1_050_000, format!("{phase} {}", r["approval"]));
    c.check("...with the plan, what it saves and what doing nothing loses", r["approval"]["savesMinor"] == 1_780_000 && r["approval"]["options"].as_array().map_or(0, |o| o.len()) == 2, r["approval"].to_string());
    let q = get_json(&format!("http://127.0.0.1:{STORE}/anp/quotes"))["buyer"].clone();
    c.check("nothing is signed while it waits", q["acceptances"].as_object().map_or(true, |a| a.is_empty()), q["acceptances"].to_string());
    let (code, _) = act("/rescue/start", json!({}));
    c.check("a second rescue cannot start meanwhile", code == 400, code.to_string());

    println!("The duty manager approves from a phone");
    let (code, _) = act("/rescue/approve", json!({ "budget": "11000" }));
    c.check("the duty manager raises the budget to €11,000", code == 200, code.to_string());
    let phase = wait_phase(&["done", "failed"], 180);
    let r = rescue();
    c.check("the rescue completes", phase == "done", format!("{phase} {}", r["log"].as_array().and_then(|l| l.last()).cloned().unwrap_or_default()));
    c.check("six deals confirmed by their companies, €10,500 spent", r["summary"]["confirmed"] == 6 && r["summary"]["spentMinor"] == 1_050_000, r["summary"].to_string());
    c.check("every one audits, as the insurer will check it", r["summary"]["audited"] == 6, r["summary"].to_string());
    let group = r["group"].as_str().unwrap_or_default().to_string();
    // the group DID is on the group host's domain (groups.test, or its HTTPS origin when every DID is resolved over HTTPS)
    c.check("the agent opened an encrypted group for the rescue", group.starts_with("did:wba:") && group.contains(":groups:rescue-"), group.clone());
    let joined: Vec<&str> = ["coldchain", "rungis-cold", "orly-freeze", "foodbank", "insurer", "supplier"].into_iter().filter(|n| logged(&r, &format!("{} joins the group", anp_name(n)), None)).collect();
    c.check("the six companies that confirmed joined it (not FrostLine, not Polar)", joined.len() == 6 && !logged(&r, "FrostLine Logistics joins", None), format!("{joined:?}"));
    for (name, _, _, _, port) in sellers.iter().filter(|s| ["coldchain", "rungis-cold", "foodbank"].contains(&s.0.as_str())) {
        let got = poll(60, 500, || {
            get_json(&format!("http://127.0.0.1:{port}/anp/groups/member?group={}", urlencode(&group)))["events"]
                .as_array()
                .map_or(false, |e| e.iter().any(|x| x["kind"] == "message" && x["plaintext"]["text"].as_str().map_or(false, |t| t.contains("Cold-stock rescue for store-0412"))))
        });
        c.check(&format!("{} reads the plan in the group", anp_name(name)), got, "");
    }
    let ledger = get_json(&format!("http://127.0.0.1:{STORE}/anp/quotes"))["buyer"]["ledger"].clone();
    c.check("the ledger: €10,500 committed of €11,000", ledger["committedMinor"] == 1_050_000 && ledger["remainingMinor"] == 50_000, ledger.to_string());
    let (code, _) = act("/rescue/approve", json!({}));
    c.check("nothing is waiting for approval any more", code == 400, code.to_string());
}

/// The company names the profiles carry (as the agent's log uses them).
fn anp_name(id: &str) -> &'static str {
    match id {
        "frostline" => "FrostLine Logistics",
        "polar" => "Polar Express",
        "coldchain" => "ColdChain Rungis",
        "rungis-cold" => "Rungis Cold Store",
        "orly-freeze" => "Orly Freeze",
        "foodbank" => "Banque Alimentaire 94",
        "insurer" => "Mutuelle du Commerce",
        "supplier" => "Grossiste Frais IDF",
        _ => "?",
    }
}
