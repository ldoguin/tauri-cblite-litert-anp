//! The store's agent: it runs the cold-stock rescue on its own, with the node's tools (the store's assessment, the quote desk, the
//! group membership), and a rule layer between what it plans and what it signs.
//!
//! 1. **Assess.** From the cold room's assessment (`coldstore`): the frozen pallets at risk (to move to cold storage), the chilled
//!    ones at risk (to give to the food bank before they are lost), and the most urgent deadline.
//! 2. **Ask.** Every company of the right role in its directory, at once, for a quote (signed messages in encrypted conversations).
//! 3. **Choose**, through the rules: a carrier must arrive before the first product is lost; the cheapest that can wins. Cold storage
//!    is filled cheapest per pallet first; when a warehouse has less room than asked, the agent **re-plans**: it asks the others for
//!    the remaining pallets. A pallet is only moved if it is worth more than moving and storing it costs. Nothing past its safety
//!    limit is moved or given away.
//! 4. **Escalate.** A plan over the token's cap per commitment or over the budget is not signed: the agent writes the duty manager a
//!    short decision (the plan, what it costs, what it saves, what doing nothing loses) and waits (`POST /rescue/approve` with a new
//!    budget and/or a new token from the authority, or `POST /rescue/decline`).
//! 5. **Commit.** It accepts each chosen offer, one per need; a refusal (a warehouse that filled up meanwhile) makes it re-plan.
//! 6. **Coordinate.** With group membership, it opens an encrypted group with every company that confirmed, and posts the plan.
//! 7. **Prove.** Every confirmed deal is audited, as the insurer would.
//!
//! Every step and every decision is in the log (`GET /rescue`), with the rule that made it. The planner is rule-based: it runs the
//! same everywhere. The directory (`--rescue DIRECTORY.json`: `[{"did", "role", "name"}]`) names the companies the agent may call on.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::coldstore::ColdStoreSim;
use crate::docs::{Coll, Docs};
use crate::group_member::GroupMember;
use crate::quotes::QuoteBuyer;

/// How long the agent waits for the answers to its requests (quotes, and the confirmation of an acceptance). The wait ends as soon as the
/// answers are in, so it only costs time when a company never answers. 40 s was too short for a busy machine: a confirmation that came at
/// 45 s was counted as no answer while the ledger committed it, and the plan ended a deal short.
const ANSWER_WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct Company {
    pub did: String,
    pub role: String,
    pub name: String,
}

/// Read a directory: `[{"did", "role", "name"}]`, roles `carrier`, `warehouse`, `foodbank`, `insurer`, `supplier`.
pub fn read_directory(v: &Value) -> Result<Vec<Company>, String> {
    let arr = v.as_array().ok_or("the directory is a JSON array of {did, role, name}")?;
    arr.iter()
        .map(|e| {
            let s = |k: &str| e[k].as_str().map(str::to_string);
            Ok(Company { did: s("did").ok_or("a directory entry without a did")?, role: s("role").ok_or("a directory entry without a role")?, name: s("name").unwrap_or_default() })
        })
        .collect()
}

/// One frozen pallet at risk: what it is, what it is worth.
#[derive(Debug, Clone)]
struct Pallet {
    sku: String,
    value_minor: u64,
}

/// What the assessment asks for.
#[derive(Debug, Clone, Default)]
struct Needs {
    /// Frozen pallets at risk, most valuable first.
    frozen: Vec<Pallet>,
    /// Chilled pallets at risk (for the food bank).
    chilled: u32,
    /// Minutes until the first frozen product at risk is lost.
    deadline_min: Option<u64>,
    /// Products already lost (never moved, never given away), and their pallets (restocked for the morning).
    lost: Vec<String>,
    lost_pallets: u32,
}

fn needs(state: &Value) -> Needs {
    let kind = |unit: &str| state["units"].as_array().and_then(|u| u.iter().find(|x| x["id"] == unit)).and_then(|x| x["kind"].as_str()).unwrap_or("").to_string();
    let mut n = Needs::default();
    for a in state["assessment"].as_array().into_iter().flatten() {
        let unit = a["unit"].as_str().unwrap_or("");
        match a["status"].as_str().unwrap_or("") {
            "at-risk" if kind(unit) == "freezer" => {
                let pallets = a["pallets"].as_u64().unwrap_or(1).max(1);
                for _ in 0..pallets {
                    n.frozen.push(Pallet { sku: a["sku"].as_str().unwrap_or("").into(), value_minor: a["valueMinor"].as_u64().unwrap_or(0) / pallets });
                }
                let left = a["minutesLeft"].as_u64().unwrap_or(0);
                n.deadline_min = Some(n.deadline_min.map_or(left, |d| d.min(left)));
            }
            "at-risk" => n.chilled += a["pallets"].as_u64().unwrap_or(1) as u32,
            "unsafe" => {
                n.lost.push(a["sku"].as_str().unwrap_or("").into());
                n.lost_pallets += a["pallets"].as_u64().unwrap_or(1) as u32;
            }
            _ => {}
        }
    }
    n.frozen.sort_by(|a, b| b.value_minor.cmp(&a.value_minor));
    n
}

/// `"40 min"` -> 40.
fn minutes_of(s: &str) -> Option<u64> {
    s.split_whitespace().next()?.parse().ok()
}

fn euros(minor: u64) -> String {
    let (e, c) = (minor / 100, minor % 100);
    let mut digits = e.to_string();
    let mut out = String::new();
    while digits.len() > 3 {
        let tail = digits.split_off(digits.len() - 3);
        out = format!(",{tail}{out}");
    }
    if c == 0 { format!("€{digits}{out}") } else { format!("€{digits}{out}.{c:02}") }
}

// ── an on-device model's advice ─────────────────────────────────────────────────────────────────────────────

/// A model that can advise the planner: one completion for a system instruction and a prompt. Implemented by the node when it is built
/// with LiteRT (`--rescue-model`), so nothing here depends on a model runtime. Blocking: called off the async workers.
pub trait Advisor: Send + Sync {
    fn name(&self) -> String;
    fn complete(&self, system: &str, prompt: &str) -> Result<String, String>;
}

const ADVICE_SYSTEM: &str = "You plan the rescue of a supermarket's frozen stock. Answer with one JSON object and nothing else.";

/// What the model proposes: a carrier offer and the cold-storage offers to use, in order, by quote id, and why.
#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    carrier: String,
    storage: Vec<String>,
    why: String,
}

/// The prompt: the need, the deadline, every carrier and warehouse offer by quote id, and the answer's shape.
fn advice_prompt(carriers: &[(Company, Value)], warehouses: &[(Company, Value)], frozen: u32, deadline: u64) -> String {
    let mut s = format!("{frozen} pallets of frozen food must be moved to cold storage; the first of them is lost in {deadline} minutes.\n\nCarrier offers:\n");
    for (c, q) in carriers {
        s.push_str(&format!(
            "- id {}: {}, {}, takes {} pallets, arrives in {}\n",
            q["id"].as_str().unwrap_or(""), c.name, euros(q["amountMinor"].as_u64().unwrap_or(0)), q["terms"]["pallets"], q["terms"]["arrivesIn"].as_str().unwrap_or("?")
        ));
    }
    s.push_str("\nCold storage offers:\n");
    for (c, q) in warehouses {
        let pallets = q["terms"]["pallets"].as_u64().unwrap_or(1).max(1);
        let amount = q["amountMinor"].as_u64().unwrap_or(0);
        s.push_str(&format!("- id {}: {}, {} for {pallets} pallets ({} a pallet)\n", q["id"].as_str().unwrap_or(""), c.name, euros(amount), euros(amount / pallets)));
    }
    s.push_str("\nChoose one carrier that arrives in time and takes all the pallets, the cheapest such one unless there is a reason not to, and the cold storage offers to use, cheapest per pallet first, until the pallets are covered.\n");
    s.push_str("Answer exactly in this form: {\"carrier\": \"<carrier offer id>\", \"storage\": [\"<storage offer id>\", ...], \"why\": \"<one short sentence>\"}");
    s
}

/// Read the model's answer: the first JSON object in it.
fn parse_proposal(text: &str) -> Result<Proposal, String> {
    let (start, end) = (text.find('{').ok_or("no JSON object in the answer")?, text.rfind('}').ok_or("no JSON object in the answer")?);
    if end < start {
        return Err("no JSON object in the answer".into());
    }
    let v: Value = serde_json::from_str(&text[start..=end]).map_err(|e| format!("not JSON: {e}"))?;
    let carrier = v["carrier"].as_str().filter(|s| !s.is_empty()).ok_or("no carrier")?.to_string();
    let storage = v["storage"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    Ok(Proposal { carrier, storage, why: v["why"].as_str().unwrap_or("").trim().to_string() })
}

/// The rules a proposal must pass before the agent follows it. Every broken rule is named.
fn vet(p: &Proposal, carriers: &[(Company, Value)], warehouses: &[(Company, Value)], frozen: u32, deadline: u64) -> Result<(), Vec<String>> {
    let mut broken = vec![];
    match carriers.iter().find(|(_, q)| q["id"].as_str() == Some(p.carrier.as_str())) {
        None => broken.push(format!("{} is not one of the carrier offers", p.carrier)),
        Some((c, q)) => {
            let arrives = q["terms"]["arrivesIn"].as_str().and_then(minutes_of).unwrap_or(u64::MAX);
            if arrives > deadline {
                broken.push(format!("{} arrives in {arrives} min, after the first loss ({deadline} min)", c.name));
            }
            if (q["terms"]["pallets"].as_u64().unwrap_or(0) as u32) < frozen {
                broken.push(format!("{} cannot take all {frozen} pallets", c.name));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for id in &p.storage {
        if !warehouses.iter().any(|(_, q)| q["id"].as_str() == Some(id.as_str())) {
            broken.push(format!("{id} is not one of the cold storage offers"));
        }
        if !seen.insert(id) {
            broken.push(format!("{id} is used twice"));
        }
    }
    if broken.is_empty() { Ok(()) } else { Err(broken) }
}

/// Every rescue record this node holds, its own and replicated ones, as verified (a document that does not verify is not shown),
/// newest first: what a head office reads. `signedBy` says who signed, in place of the whole signature block.
pub async fn records(docs: &Docs) -> Result<Vec<Value>, String> {
    let mut out: Vec<Value> = docs
        .list(Coll::Rescue)
        .await?
        .into_iter()
        .map(|(id, mut v)| {
            v["id"] = json!(id);
            let signed = json!({ "author": v["trust"]["author"], "did": v["trust"]["did"], "seq": v["trust"]["seq"] });
            if let Some(o) = v.as_object_mut() {
                o.remove("trust");
            }
            v["signedBy"] = signed;
            v
        })
        .collect();
    out.sort_by(|a, b| b["started"].as_str().cmp(&a["started"].as_str()));
    Ok(out)
}

/// An offer the agent means to accept.
#[derive(Debug, Clone)]
struct Pick {
    quote_id: String,
    company: String,
    role: String,
    category: String,
    pallets: u32,
    amount_minor: u64,
}

struct State {
    /// This run's name, in the id of its record (`<node>::<run>`); empty until the first run.
    run: String,
    started: String,
    phase: String,
    log: Vec<Value>,
    plan: Vec<Pick>,
    approval: Option<Value>,
    group: Option<String>,
    summary: Option<Value>,
}

pub struct Rescue {
    /// The companies it may call on: given (`--rescue DIRECTORY.json`), or found through the search agent at the start of each rescue.
    directory: Mutex<Vec<Company>>,
    /// The search agent's JSON-RPC URL, when companies are found there (`--rescue-search`).
    search: Option<String>,
    store: Arc<ColdStoreSim>,
    buyer: Arc<QuoteBuyer>,
    group: Option<Arc<GroupMember>>,
    state: Mutex<State>,
    /// The duty manager's answer: `Some(true)` approve, `Some(false)` decline.
    decision: Mutex<Option<bool>>,
    /// A demo's pace: how long the agent dwells on each phase it enters (a third of it between repeated steps), so that a viewer
    /// and the captions can follow. 0 (tests, real use): no pause.
    pace_ms: std::sync::atomic::AtomicU64,
    /// An on-device model that proposes the carrier and the cold storage; the rules decide whether to follow it.
    advisor: Mutex<Option<Arc<dyn Advisor>>>,
    decided: tokio::sync::Notify,
    /// The run's state changed: its record is written again (see [`Rescue::persist`]).
    dirty: tokio::sync::Notify,
    /// One write of the record at a time, so the signing sequence only goes forward.
    writing: tokio::sync::Mutex<()>,
    /// The nodes whose signed approvals this agent acts on (`--duty-manager`). When there are any, the agent takes its approval from a signed
    /// document in the replicated `approvals` collection and from nothing else: the HTTP approve and decline are refused.
    duty_managers: Mutex<Vec<String>>,
    /// Approvals already reported as ignored (`<doc id>|<signer>`), so each is logged once.
    ignored: Mutex<std::collections::HashSet<String>>,
}

impl Rescue {
    /// `directory`: the companies it may call on; with `search`, they are found through that search agent instead, at each start.
    pub fn new(directory: Vec<Company>, search: Option<String>, store: Arc<ColdStoreSim>, buyer: Arc<QuoteBuyer>, group: Option<Arc<GroupMember>>) -> Rescue {
        Rescue {
            directory: Mutex::new(directory),
            search,
            store,
            buyer,
            group,
            state: Mutex::new(State { run: String::new(), started: String::new(), phase: "idle".into(), log: vec![], plan: vec![], approval: None, group: None, summary: None }),
            decision: Mutex::new(None),
            pace_ms: std::sync::atomic::AtomicU64::new(0),
            advisor: Mutex::new(None),
            decided: tokio::sync::Notify::new(),
            dirty: tokio::sync::Notify::new(),
            writing: tokio::sync::Mutex::new(()),
            duty_managers: Mutex::new(vec![]),
            ignored: Mutex::new(Default::default()),
        }
    }

    pub fn status(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({
            "phase": s.phase, "log": s.log, "approval": s.approval, "group": s.group, "summary": s.summary,
            "plan": s.plan.iter().map(|p| json!({ "company": p.company, "role": p.role, "category": p.category, "pallets": p.pallets, "amountMinor": p.amount_minor, "quote": p.quote_id })).collect::<Vec<_>>(),
            "directory": self.directory.lock().unwrap().iter().map(|c| json!({ "did": c.did, "role": c.role, "name": c.name })).collect::<Vec<_>>(),
            "discovery": if self.search.is_some() { "search agent" } else { "directory" },
            "advisor": self.advisor.lock().unwrap().as_ref().map(|a| a.name()),
        })
    }

    fn phase(&self, p: &str) {
        self.state.lock().unwrap().phase = p.into();
        self.dirty.notify_one();
    }

    /// The run as one signed document in the replicated `rescue` collection, `<node>::<run>`: the phase, the log with the rule behind each
    /// decision, the plan, the approval, the confirmed deals and the ledger. Written only by this node, again at every step, so a head
    /// office that was cut off finds the whole run when the link returns.
    async fn persist(&self) -> bool {
        let _one = self.writing.lock().await;
        let (id, body, terminal) = {
            let s = self.state.lock().unwrap();
            if s.run.is_empty() {
                return true;
            }
            let buyer = self.buyer.state();
            let deals: Vec<Value> = buyer["acceptances"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(_, a)| a["status"] == "confirmed")
                .map(|(id, a)| json!({ "acceptance": id, "status": a["status"], "answer": a["answer"] }))
                .collect();
            let node = self.store.node().to_string();
            let body = json!({
                "node": node, "run": s.run, "site": buyer["site"], "started": s.started,
                "phase": s.phase, "clock": self.store.state()["clock"], "log": s.log, "approval": s.approval, "group": s.group, "summary": s.summary,
                "plan": s.plan.iter().map(|p| json!({ "company": p.company, "role": p.role, "category": p.category, "pallets": p.pallets, "amountMinor": p.amount_minor, "quote": p.quote_id })).collect::<Vec<_>>(),
                "deals": deals, "ledger": buyer["ledger"],
            });
            (format!("{node}::{}", s.run), body, matches!(s.phase.as_str(), "done" | "failed" | "declined"))
        };
        if let Err(e) = self.store.docs().put(Coll::Rescue, &id, body).await {
            log::warn!("could not write the rescue record {id}: {e}");
        }
        terminal
    }

    /// Write the run's record whenever it changes, until the run has ended (its last state is written first).
    async fn keep_record(self: Arc<Self>) {
        loop {
            self.dirty.notified().await;
            if self.persist().await {
                return;
            }
        }
    }

    /// Log a step: `step` is the phase it belongs to, `rule` (when there is one) the rule that decided it.
    fn note(&self, step: &str, text: &str, rule: Option<&str>, data: Value) {
        log::info!("rescue [{step}] {text}");
        let mut s = self.state.lock().unwrap();
        let clock = self.store.state()["clock"].clone();
        s.log.push(json!({ "step": step, "text": text, "rule": rule, "data": data, "clock": clock, "at": chrono::Utc::now().format("%H:%M:%S").to_string() }));
        drop(s);
        self.dirty.notify_one();
    }

    fn name_of(&self, did: &str) -> String {
        self.directory.lock().unwrap().iter().find(|c| c.did == did).map(|c| c.name.clone()).unwrap_or_else(|| did.to_string())
    }

    fn of_role(&self, role: &str) -> Vec<Company> {
        self.directory.lock().unwrap().iter().filter(|c| c.role == role).cloned().collect()
    }

    /// Find the companies through the search agent, role by role, and make them the directory.
    async fn discover(&self, search: &str) {
        let mut found: Vec<Company> = vec![];
        for role in anp_counterparty::ROLES {
            match crate::discovery::find(search, role).await {
                Ok(cs) if cs.is_empty() => self.note("discovering", &format!("the search agent knows no {role}"), None, Value::Null),
                Ok(cs) => {
                    let names: Vec<&str> = cs.iter().map(|c| c.name.as_str()).collect();
                    self.note("discovering", &format!("{} {role}(s) found: {}", cs.len(), names.join(", ")), None, json!({ "dids": cs.iter().map(|c| &c.did).collect::<Vec<_>>() }));
                    found.extend(cs);
                }
                Err(e) => self.note("discovering", &format!("could not search for a {role}: {e}"), None, Value::Null),
            }
        }
        *self.directory.lock().unwrap() = found;
    }

    /// Let an on-device model propose the carrier and the cold storage (the rules still decide).
    pub fn set_advisor(&self, a: Arc<dyn Advisor>) {
        *self.advisor.lock().unwrap() = Some(a);
    }

    /// Ask the model for a proposal and put it through the rules: `Some` only for one that passes every rule. Anything else (no
    /// model, a failure, an answer that is not a plan, a plan that breaks a rule) is logged and the rules choose on their own.
    async fn advise(&self, carriers: &[(Company, Value)], warehouses: &[(Company, Value)], frozen: u32, deadline: u64) -> Option<Proposal> {
        const RULE: &str = "the model proposes, the rules decide";
        let adv = self.advisor.lock().unwrap().clone()?;
        let prompt = advice_prompt(carriers, warehouses, frozen, deadline);
        self.note("choosing", &format!("asking the on-device model ({}) for a plan", adv.name()), None, json!({ "prompt": prompt }));
        let started = std::time::Instant::now();
        let a = adv.clone();
        let answer = tokio::task::spawn_blocking(move || a.complete(ADVICE_SYSTEM, &prompt)).await.map_err(|e| e.to_string()).and_then(|r| r);
        let secs = started.elapsed().as_secs_f32();
        let text = match answer {
            Ok(t) => t,
            Err(e) => {
                self.note("choosing", &format!("the model failed ({e}): the rules choose"), Some(RULE), Value::Null);
                return None;
            }
        };
        let p = match parse_proposal(&text) {
            Ok(p) => p,
            Err(e) => {
                self.note("choosing", &format!("the model's answer is not a plan ({e}): the rules choose"), Some(RULE), json!({ "answer": text, "seconds": secs }));
                return None;
            }
        };
        let name = |id: &str, offers: &[(Company, Value)]| offers.iter().find(|(_, q)| q["id"].as_str() == Some(id)).map(|(c, _)| c.name.clone()).unwrap_or_else(|| id.to_string());
        let storage: Vec<String> = p.storage.iter().map(|id| name(id, warehouses)).collect();
        match vet(&p, carriers, warehouses, frozen, deadline) {
            Ok(()) => {
                self.note(
                    "choosing",
                    &format!("the model proposes {} with {} ({:.0} s): \"{}\"; every rule holds, the agent follows it", name(&p.carrier, carriers), if storage.is_empty() { "no storage named".to_string() } else { storage.join(" then ") }, secs, p.why),
                    Some(RULE),
                    json!({ "answer": text, "seconds": secs }),
                );
                Some(p)
            }
            Err(broken) => {
                self.note("choosing", &format!("the model proposed {}, but {}: the rules choose", name(&p.carrier, carriers), broken.join("; ")), Some(RULE), json!({ "answer": text, "seconds": secs }));
                None
            }
        }
    }

    /// Enter a phase and, at a demo's pace, dwell on it before working.
    async fn enter(&self, p: &str) {
        self.phase(p);
        let ms = self.pace_ms.load(std::sync::atomic::Ordering::Relaxed);
        if ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }

    /// Between repeated steps (each confirmation, each member added), at a demo's pace.
    async fn beat(&self) {
        let ms = self.pace_ms.load(std::sync::atomic::Ordering::Relaxed) / 3;
        if ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }

    /// Start the rescue, unless one is running. `pace_ms` slows it down for a viewer (a demo); 0 runs it at full speed.
    pub fn start(self: &Arc<Self>, pace_ms: u64) -> Result<(), String> {
        self.pace_ms.store(pace_ms.min(30_000), std::sync::atomic::Ordering::Relaxed);
        {
            let mut s = self.state.lock().unwrap();
            if !matches!(s.phase.as_str(), "idle" | "done" | "failed" | "declined") {
                return Err(format!("a rescue is already under way ({})", s.phase));
            }
            *s = State {
                run: uuid::Uuid::new_v4().simple().to_string()[..8].to_string(),
                started: chrono::Utc::now().to_rfc3339(),
                phase: "starting".into(),
                log: vec![],
                plan: vec![],
                approval: None,
                group: None,
                summary: None,
            };
        }
        *self.decision.lock().unwrap() = None;
        tokio::spawn(self.clone().keep_record());
        self.dirty.notify_one();
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.run().await {
                me.note("failed", &e, None, Value::Null);
                me.phase("failed");
            }
        });
        Ok(())
    }

    /// Act only on approvals signed by these nodes, and only as documents (see `duty_managers`).
    pub fn set_duty_managers(&self, nodes: Vec<String>) {
        *self.duty_managers.lock().unwrap() = nodes;
    }

    /// Does this agent take its approval from signed documents only?
    pub fn documents_only(&self) -> bool {
        !self.duty_managers.lock().unwrap().is_empty()
    }

    /// While waiting: look in the replicated `approvals` for a decision on this run of this store. One signed by a duty manager is acted
    /// on; one signed by anyone else (a peer that is trusted for other things) is logged once and left alone. A document for another store
    /// or another run is not this agent's business.
    async fn check_approvals(&self) {
        let managers = self.duty_managers.lock().unwrap().clone();
        if managers.is_empty() {
            return;
        }
        let run = self.state.lock().unwrap().run.clone();
        let node = self.store.node().to_string();
        let Ok(list) = self.store.docs().list(Coll::Approvals).await else { return };
        for (id, doc) in list {
            if doc["store"] != json!(node) || doc["run"] != json!(run) {
                continue;
            }
            let author = doc["trust"]["author"].as_str().unwrap_or("").to_string();
            if !managers.contains(&author) {
                if self.ignored.lock().unwrap().insert(format!("{id}|{author}")) {
                    self.note("awaiting-approval", &format!("an approval signed by {author} is ignored: {author} is not a duty manager"), Some("only a duty manager approves"), Value::Null);
                }
                continue;
            }
            let approve = doc["approve"].as_bool().unwrap_or(false);
            self.note(
                "awaiting-approval",
                &format!("duty manager {author} {} the plan, in a signed document ({id})", if approve { "approves" } else { "declines" }),
                Some("a person approves what is over the limit"),
                json!({ "approval": id, "by": author, "budgetMinor": doc["budgetMinor"] }),
            );
            match self.decide(approve, doc["token"].as_str(), doc["budgetMinor"].as_u64()) {
                Ok(()) => return,
                Err(e) => self.note("awaiting-approval", &format!("the approval from {author} could not be applied: {e}"), None, Value::Null),
            }
        }
    }

    /// The duty manager's answer to an escalation.
    pub fn decide(&self, approve: bool, token: Option<&str>, budget_minor: Option<u64>) -> Result<(), String> {
        if self.state.lock().unwrap().phase != "awaiting-approval" {
            return Err("nothing is waiting for a decision".into());
        }
        if approve {
            self.buyer.set_authority(token, budget_minor)?;
        }
        *self.decision.lock().unwrap() = Some(approve);
        self.decided.notify_one();
        Ok(())
    }

    // ── the tools ──────────────────────────────────────────────────────────────────────────────────────────

    /// Ask every company in `who` for `pallets` of `category`; wait for their answers. Returns `(company, quote)` for each offer.
    async fn ask_all(&self, who: &[Company], category: &str, pallets: u32) -> Vec<(Company, Value)> {
        let mut asked = vec![];
        for c in who {
            match self.buyer.request(&c.did, category, pallets, json!({ "reason": "cold-stock rescue" })).await {
                Ok(id) => asked.push((c.clone(), id)),
                Err(e) => self.note("asking", &format!("could not reach {}: {e}", c.name), None, Value::Null),
            }
        }
        let deadline = tokio::time::Instant::now() + ANSWER_WAIT;
        loop {
            let st = self.buyer.state();
            let done = asked.iter().all(|(_, id)| st["requests"][id]["answers"].as_array().map_or(false, |a| !a.is_empty()));
            if done || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let st = self.buyer.state();
        let mut offers = vec![];
        for (c, id) in asked {
            let quote = st["quotes"].as_object().and_then(|q| q.values().find(|q| q["requestId"] == json!(id)).map(|q| q["quote"].clone()));
            match quote {
                Some(q) => {
                    self.note("asking", &format!("{} offers {} pallet(s) of {category} for {}", c.name, q["terms"]["pallets"], euros(q["amountMinor"].as_u64().unwrap_or(0))), None, json!({ "quote": q["id"], "terms": q["terms"] }));
                    offers.push((c, q));
                }
                None => {
                    let answer = st["requests"][&id]["answers"][0].clone();
                    let reason = st["refusals"].as_array().and_then(|r| r.iter().find(|x| x["id"] == answer)).and_then(|x| x["reason"].as_str()).unwrap_or("no answer in time").to_string();
                    self.note("asking", &format!("{} declines: {reason}", c.name), None, Value::Null);
                }
            }
        }
        offers
    }

    /// Accept one pick and wait for the company's answer: confirmed, refused (with the reason), or the error before sending.
    async fn commit(&self, p: &Pick) -> Result<bool, anp_quote::QuoteError> {
        let id = self.buyer.accept(&p.quote_id).await?;
        let deadline = tokio::time::Instant::now() + ANSWER_WAIT;
        loop {
            let a = self.buyer.state()["acceptances"][&id].clone();
            match a["status"].as_str() {
                Some("confirmed") => {
                    self.note("committing", &format!("{} confirms: {} for {}", p.company, p.category, euros(p.amount_minor)), None, json!({ "acceptance": id, "reference": a["answer"]["reference"] }));
                    return Ok(true);
                }
                Some("refused") => {
                    self.note("committing", &format!("{} refuses our acceptance: {}", p.company, a["answer"]["reason"].as_str().unwrap_or("")), None, Value::Null);
                    return Ok(false);
                }
                _ if tokio::time::Instant::now() >= deadline => {
                    self.note("committing", &format!("{} has not answered", p.company), None, Value::Null);
                    return Ok(false);
                }
                _ => tokio::time::sleep(Duration::from_millis(300)).await,
            }
        }
    }

    fn pick(c: &Company, q: &Value, category: &str) -> Pick {
        Pick {
            quote_id: q["id"].as_str().unwrap_or("").into(),
            company: c.name.clone(),
            role: c.role.clone(),
            category: category.into(),
            pallets: q["terms"]["pallets"].as_u64().unwrap_or(0) as u32,
            amount_minor: q["amountMinor"].as_u64().unwrap_or(0),
        }
    }

    // ── the loop ───────────────────────────────────────────────────────────────────────────────────────────

    async fn run(self: &Arc<Self>) -> Result<(), String> {
        // 0. who can help: found through the search agent, when there is one
        if let Some(s) = self.search.clone() {
            self.enter("discovering").await;
            self.discover(&s).await;
        }
        // 1. assess
        self.enter("assessing").await;
        let st = self.store.state();
        let n = needs(&st);
        let at_stake: u64 = n.frozen.iter().map(|p| p.value_minor).sum();
        self.note(
            "assessing",
            &format!("{} frozen pallet(s) at risk worth {}, first loss in {} min; {} chilled pallet(s) at risk; {} product(s) already lost", n.frozen.len(), euros(at_stake), n.deadline_min.map_or("-".into(), |d| d.to_string()), n.chilled, n.lost.len()),
            None,
            json!({ "frozen": n.frozen.iter().map(|p| &p.sku).collect::<Vec<_>>(), "lost": n.lost }),
        );
        for sku in &n.lost {
            self.note("assessing", &format!("{sku} is past its safety limit: it is not moved or given away"), Some("nothing unsafe is kept"), Value::Null);
        }
        if n.frozen.is_empty() && n.chilled == 0 {
            self.note("done", "nothing at risk: no rescue needed", None, Value::Null);
            self.phase("done");
            return Ok(());
        }
        let frozen = n.frozen.len() as u32;
        let deadline = n.deadline_min.unwrap_or(u64::MAX);

        // 2. ask, everyone at once per need
        self.enter("asking").await;
        let carriers = if frozen > 0 { self.ask_all(&self.of_role("carrier"), "transport", frozen).await } else { vec![] };
        let warehouses = if frozen > 0 { self.ask_all(&self.of_role("warehouse"), "storage", frozen).await } else { vec![] };
        let banks = if n.chilled > 0 { self.ask_all(&self.of_role("foodbank"), "donation", n.chilled).await } else { vec![] };
        let insurers = self.ask_all(&self.of_role("insurer"), "coverage", frozen.max(1)).await;
        let suppliers = if n.lost_pallets > 0 { self.ask_all(&self.of_role("supplier"), "restock", n.lost_pallets).await } else { vec![] };

        // 3. choose, through the rules
        self.enter("choosing").await;
        let mut plan: Vec<Pick> = vec![];
        let mut moved = 0u32;
        if frozen > 0 {
            let mut fit: Vec<&(Company, Value)> = vec![];
            for o in &carriers {
                let arrives = o.1["terms"]["arrivesIn"].as_str().and_then(minutes_of).unwrap_or(u64::MAX);
                if arrives > deadline {
                    self.note("choosing", &format!("{} arrives in {arrives} min, after the first loss ({deadline} min): out", o.0.name), Some("arrive before the goods are lost"), Value::Null);
                } else if (o.1["terms"]["pallets"].as_u64().unwrap_or(0) as u32) < frozen {
                    self.note("choosing", &format!("{} cannot take all {frozen} pallets: out", o.0.name), Some("one truck for the whole load"), Value::Null);
                } else {
                    fit.push(o);
                }
            }
            fit.sort_by_key(|o| o.1["amountMinor"].as_u64().unwrap_or(u64::MAX));
            let Some(cheapest) = fit.first().copied() else {
                self.note("choosing", "no carrier can arrive in time: the frozen stock cannot be moved", Some("arrive before the goods are lost"), Value::Null);
                return self.finish(plan, at_stake).await;
            };
            // the on-device model, if there is one, proposes; only a proposal that passes every rule is followed
            let advice = self.advise(&carriers, &warehouses, frozen, deadline).await;
            let carrier = advice.as_ref().and_then(|a| fit.iter().find(|o| o.1["id"].as_str() == Some(a.carrier.as_str())).copied()).unwrap_or(cheapest);
            for o in fit.iter().filter(|o| o.1["id"] != carrier.1["id"]) {
                let (theirs, ours) = (o.1["amountMinor"].as_u64().unwrap_or(0), carrier.1["amountMinor"].as_u64().unwrap_or(0));
                let text = if theirs >= ours {
                    format!("{} costs {} more than {}: not chosen", o.0.name, euros(theirs - ours), carrier.0.name)
                } else {
                    format!("{} costs {} less than {}, which the model chose: not chosen", o.0.name, euros(ours - theirs), carrier.0.name)
                };
                let rule = if advice.is_some() { "the model proposes, the rules decide" } else { "cheapest carrier that arrives in time" };
                self.note("choosing", &text, Some(rule), Value::Null);
            }
            let transport = Self::pick(&carrier.0, &carrier.1, "transport");

            // storage: cheapest per pallet first (or in the model's order); if the room offered falls short, ask the others for the rest
            let per_pallet = |q: &Value| q["amountMinor"].as_u64().unwrap_or(0) / q["terms"]["pallets"].as_u64().unwrap_or(1).max(1);
            let mut offers: Vec<(Company, Value)> = warehouses.clone();
            offers.sort_by_key(|o| per_pallet(&o.1));
            if let Some(a) = &advice {
                let rank = |q: &Value| a.storage.iter().position(|id| q["id"].as_str() == Some(id.as_str())).unwrap_or(usize::MAX);
                offers.sort_by_key(|o| rank(&o.1)); // stable: offers the model did not name keep their order, after the ones it did
            }
            let mut storage: Vec<Pick> = vec![];
            let mut covered = 0u32;
            let mut used: Vec<String> = vec![];
            for (c, q) in &offers {
                if covered >= frozen {
                    break;
                }
                let room = q["terms"]["pallets"].as_u64().unwrap_or(0) as u32;
                // the cheapest offer is taken whole; after it, only offers that do not exceed what is still needed (a bigger one is
                // asked again, below, for exactly the rest, so it is not paid for room that is not used)
                if covered == 0 || room <= frozen - covered {
                    storage.push(Self::pick(c, q, "storage"));
                    covered += room;
                    used.push(c.did.clone());
                    if q["terms"]["partial"] == true {
                        self.note("choosing", &format!("{} has room for {room} of the {frozen} pallets: re-planning the rest", c.name), Some("re-plan when an offer falls short"), Value::Null);
                    }
                }
            }
            if covered < frozen {
                let rest = frozen - covered;
                let others: Vec<Company> = self.of_role("warehouse").into_iter().filter(|c| !used.contains(&c.did)).collect();
                let mut more = self.ask_all(&others, "storage", rest).await;
                more.sort_by_key(|o| per_pallet(&o.1));
                if let Some((c, q)) = more.into_iter().next() {
                    let room = q["terms"]["pallets"].as_u64().unwrap_or(0) as u32;
                    storage.push(Self::pick(&c, &q, "storage"));
                    covered += room;
                    self.note("choosing", &format!("{} takes the remaining {room} pallet(s)", c.name), Some("re-plan when an offer falls short"), Value::Null);
                }
            }
            moved = covered.min(frozen);
            // worth it? the pallets moved, most valuable first, against what moving and storing them costs
            let cost: u64 = transport.amount_minor + storage.iter().map(|s| s.amount_minor).sum::<u64>();
            let saved: u64 = n.frozen.iter().take(moved as usize).map(|p| p.value_minor).sum();
            if moved == 0 || cost >= saved {
                self.note("choosing", &format!("moving {moved} pallet(s) would cost {} to save {}: not worth it", euros(cost), euros(saved)), Some("only move what is worth more than moving it"), Value::Null);
            } else {
                self.note("choosing", &format!("moving {moved} pallet(s) costs {} and saves {}", euros(cost), euros(saved)), Some("only move what is worth more than moving it"), Value::Null);
                plan.push(transport);
                plan.extend(storage);
            }
            if moved < frozen {
                self.note("choosing", &format!("{} pallet(s) cannot be stored anywhere: they will be lost", frozen - moved), None, Value::Null);
            }
        }
        if let Some((c, q)) = banks.first() {
            plan.push(Self::pick(c, q, "donation"));
            self.note("choosing", &format!("{} chilled pallet(s) at risk go to {} before they are lost", q["terms"]["pallets"], c.name), Some("give away what cannot be kept cold"), Value::Null);
        }
        if let Some((c, q)) = insurers.first() {
            if q["terms"]["covered"] == true {
                plan.push(Self::pick(c, q, "coverage"));
            }
        }
        let mut restock: Vec<&(Company, Value)> = suppliers.iter().collect();
        restock.sort_by_key(|o| o.1["amountMinor"].as_u64().unwrap_or(u64::MAX));
        if let Some((c, q)) = restock.first() {
            plan.push(Self::pick(c, q, "restock"));
            self.note("choosing", &format!("{} pallet(s) lost: {} restocks them for the morning", n.lost_pallets, c.name), Some("replace what cannot be saved"), Value::Null);
        }
        self.state.lock().unwrap().plan = plan.clone();
        let saved: u64 = n.frozen.iter().take(moved as usize).map(|p| p.value_minor).sum();

        // 4. within the limits? the buyer desk would refuse to sign; the agent asks first, with the whole picture
        let total: u64 = plan.iter().map(|p| p.amount_minor).sum();
        let ledger = self.buyer.state()["ledger"].clone();
        let remaining = ledger["remainingMinor"].as_u64().unwrap_or(0);
        if total > remaining {
            let decision = json!({
                "question": format!("Approve a rescue plan of {} (the budget has {} left)?", euros(total), euros(remaining)),
                "planMinor": total, "remainingMinor": remaining, "savesMinor": saved, "lossIfNothingMinor": at_stake,
                "options": [
                    { "option": "approve", "cost": euros(total), "saves": euros(saved) },
                    { "option": "decline", "cost": euros(0), "loses": euros(at_stake) },
                ],
                "plan": plan.iter().map(|p| format!("{}: {} ({} pallet(s)) {}", p.company, p.category, p.pallets, euros(p.amount_minor))).collect::<Vec<_>>(),
            });
            self.note("awaiting-approval", &format!("the plan costs {}, over the {} left in the budget: asking the duty manager", euros(total), euros(remaining)), Some("a person approves what is over the limit"), decision.clone());
            self.state.lock().unwrap().approval = Some(decision);
            self.phase("awaiting-approval");
            loop {
                self.check_approvals().await;
                if let Some(d) = *self.decision.lock().unwrap() {
                    if !d {
                        self.note("declined", "the duty manager declined: nothing is committed", None, Value::Null);
                        self.phase("declined");
                        return Ok(());
                    }
                    break;
                }
                // woken by an answer over HTTP, or look again at the replicated documents
                let _ = tokio::time::timeout(Duration::from_millis(500), self.decided.notified()).await;
            }
            self.note("committing", "the duty manager approved", None, self.buyer.state()["ledger"].clone());
        }

        // 5. commit, one acceptance per need
        self.enter("committing").await;
        let mut confirmed: Vec<Pick> = vec![];
        for p in &plan {
            self.beat().await;
            match self.commit(p).await {
                Ok(true) => confirmed.push(p.clone()),
                Ok(false) => {}
                Err(e) => {
                    // the desk's own refusal to sign: a token cap the approval did not lift
                    self.note("committing", &format!("{} not accepted: {e}", p.company), Some("sign nothing outside the token"), Value::Null);
                }
            }
        }
        self.state.lock().unwrap().plan = confirmed.clone();
        self.finish(confirmed, at_stake).await
    }

    /// 6. coordinate, 7. prove.
    async fn finish(&self, confirmed: Vec<Pick>, at_stake: u64) -> Result<(), String> {
        if let (Some(g), false) = (&self.group, confirmed.is_empty()) {
            self.enter("coordinating").await;
            let name = format!("rescue-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            match g.create(&name, None).await {
                Ok(group) => {
                    self.state.lock().unwrap().group = Some(group.clone());
                    self.note("coordinating", &format!("opened an encrypted group, {group}"), None, Value::Null);
                    let directory = self.directory.lock().unwrap().clone();
                    let dids: Vec<String> = confirmed.iter().filter_map(|p| directory.iter().find(|c| c.name == p.company).map(|c| c.did.clone())).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                    for did in dids {
                        self.beat().await;
                        match g.add(&group, &did, None).await {
                            Ok(()) => self.note("coordinating", &format!("{} joins the group", self.name_of(&did)), None, Value::Null),
                            Err(e) => self.note("coordinating", &format!("could not add {}: {e}", self.name_of(&did)), None, Value::Null),
                        }
                    }
                    let lines: Vec<String> = confirmed.iter().map(|p| format!("{}: {} ({} pallet(s))", p.company, p.category, p.pallets)).collect();
                    let text = format!("Cold-stock rescue for {}, store clock {}. Confirmed: {}.", self.buyer.state()["site"].as_str().unwrap_or(""), self.store.state()["clock"].as_str().unwrap_or(""), lines.join("; "));
                    match g.send(&group, &json!({ "application_content_type": "text/plain", "text": text })).await {
                        Ok(_) => self.note("coordinating", "posted the plan to the group", None, json!({ "text": text })),
                        Err(e) => self.note("coordinating", &format!("could not post the plan: {e}"), None, Value::Null),
                    }
                }
                Err(e) => self.note("coordinating", &format!("could not open a group: {e}"), None, Value::Null),
            }
        }
        // prove: every confirmed deal audits
        self.enter("proving").await;
        let st = self.buyer.state();
        let mut audited = 0;
        for (id, a) in st["acceptances"].as_object().into_iter().flatten() {
            if a["status"] == "confirmed" {
                match self.buyer.audit(id) {
                    Ok(_) => audited += 1,
                    Err(e) => self.note("proving", &format!("{id} does not audit: {e}"), None, Value::Null),
                }
            }
        }
        let spent: u64 = confirmed.iter().map(|p| p.amount_minor).sum();
        let summary = json!({ "confirmed": confirmed.len(), "audited": audited, "spentMinor": spent, "atStakeMinor": at_stake, "ledger": self.buyer.state()["ledger"] });
        self.note("done", &format!("{} deal(s) confirmed, {} spent, {audited} record(s) audited", confirmed.len(), euros(spent)), None, summary.clone());
        self.state.lock().unwrap().summary = Some(summary);
        self.phase("done");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_split_frozen_chilled_and_lost_and_rank_by_value() {
        let st = json!({
            "units": [{ "id": "frz-2", "kind": "freezer" }, { "id": "chl-1", "kind": "chiller" }, { "id": "frz-1", "kind": "freezer" }],
            "assessment": [
                { "sku": "FZ-FISH", "unit": "frz-2", "pallets": 1, "valueMinor": 630_000, "status": "at-risk", "minutesLeft": 44 },
                { "sku": "FZ-MEAT", "unit": "frz-2", "pallets": 2, "valueMinor": 1_150_000, "status": "at-risk", "minutesLeft": 44 },
                { "sku": "CH-MILK", "unit": "chl-1", "pallets": 1, "valueMinor": 210_000, "status": "at-risk", "minutesLeft": 90 },
                { "sku": "FZ-ICE", "unit": "frz-1", "pallets": 2, "valueMinor": 680_000, "status": "unsafe" },
                { "sku": "CH-CHEESE", "unit": "chl-1", "pallets": 1, "valueMinor": 390_000, "status": "safe" },
            ],
        });
        let n = needs(&st);
        assert_eq!(n.frozen.iter().map(|p| p.sku.as_str()).collect::<Vec<_>>(), ["FZ-FISH", "FZ-MEAT", "FZ-MEAT"], "most valuable pallet first: fish 6,300, meat 5,750");
        assert_eq!(n.chilled, 1);
        assert_eq!(n.deadline_min, Some(44));
        assert_eq!(n.lost, ["FZ-ICE"]);
        assert_eq!(n.lost_pallets, 2);
    }

    fn offers() -> (Vec<(Company, Value)>, Vec<(Company, Value)>) {
        let c = |name: &str, role: &str| Company { did: format!("did:wba:x:{name}"), role: role.into(), name: name.into() };
        let carriers = vec![
            (c("FrostLine", "carrier"), json!({ "id": "q-frost", "amountMinor": 940_000, "terms": { "pallets": 3, "arrivesIn": "35 min" } })),
            (c("ColdChain", "carrier"), json!({ "id": "q-cold", "amountMinor": 540_000, "terms": { "pallets": 3, "arrivesIn": "40 min" } })),
            (c("SlowVan", "carrier"), json!({ "id": "q-slow", "amountMinor": 100_000, "terms": { "pallets": 3, "arrivesIn": "90 min" } })),
        ];
        let warehouses = vec![
            (c("Rungis", "warehouse"), json!({ "id": "q-rungis", "amountMinor": 180_000, "terms": { "pallets": 2, "partial": true } })),
            (c("Orly", "warehouse"), json!({ "id": "q-orly", "amountMinor": 450_000, "terms": { "pallets": 3 } })),
        ];
        (carriers, warehouses)
    }

    #[test]
    fn a_proposal_is_read_from_the_models_answer_whatever_surrounds_it() {
        let p = parse_proposal("Sure! {\"carrier\": \"q-cold\", \"storage\": [\"q-rungis\", \"q-orly\"], \"why\": \"cheapest in time\"} Done.").unwrap();
        assert_eq!(p, Proposal { carrier: "q-cold".into(), storage: vec!["q-rungis".into(), "q-orly".into()], why: "cheapest in time".into() });
        assert!(parse_proposal("I would pick ColdChain.").is_err());
        assert!(parse_proposal("{\"storage\": []}").is_err(), "no carrier");
        assert!(parse_proposal("{not json}").is_err());
    }

    #[test]
    fn a_proposal_must_pass_every_rule() {
        let (carriers, warehouses) = offers();
        let p = |carrier: &str, storage: &[&str]| Proposal { carrier: carrier.into(), storage: storage.iter().map(|s| s.to_string()).collect(), why: String::new() };
        assert!(vet(&p("q-cold", &["q-rungis", "q-orly"]), &carriers, &warehouses, 3, 44).is_ok());
        assert!(vet(&p("q-frost", &[]), &carriers, &warehouses, 3, 44).is_ok(), "a dearer carrier that arrives in time is the model's call");
        let late = vet(&p("q-slow", &["q-rungis"]), &carriers, &warehouses, 3, 44).unwrap_err();
        assert!(late[0].contains("after the first loss"), "{late:?}");
        assert!(vet(&p("q-cold", &[]), &carriers, &warehouses, 4, 44).unwrap_err()[0].contains("cannot take all 4"));
        assert!(vet(&p("q-made-up", &[]), &carriers, &warehouses, 3, 44).unwrap_err()[0].contains("not one of the carrier offers"));
        let twice = vet(&p("q-cold", &["q-orly", "q-orly", "q-nope"]), &carriers, &warehouses, 3, 44).unwrap_err();
        assert!(twice.iter().any(|b| b.contains("used twice")) && twice.iter().any(|b| b.contains("q-nope")), "{twice:?}");
    }

    #[test]
    fn the_prompt_lists_every_offer_by_id_with_what_the_rules_look_at() {
        let (carriers, warehouses) = offers();
        let s = advice_prompt(&carriers, &warehouses, 3, 44);
        assert!(s.contains("3 pallets") && s.contains("44 minutes"));
        for id in ["q-frost", "q-cold", "q-slow", "q-rungis", "q-orly"] {
            assert!(s.contains(id), "{id}");
        }
        assert!(s.contains("arrives in 40 min") && s.contains("€900 a pallet") && s.contains("\"carrier\""));
    }

    #[test]
    fn small_helpers() {
        assert_eq!(minutes_of("40 min"), Some(40));
        assert_eq!(minutes_of("soon"), None);
        assert_eq!(euros(720_000), "€7,200");
        assert_eq!(euros(1_234_567_89), "€1,234,567.89");
        assert_eq!(euros(0), "€0");
        assert!(read_directory(&json!([{ "did": "did:wba:x", "role": "carrier", "name": "X" }])).is_ok());
        assert!(read_directory(&json!([{ "role": "carrier" }])).is_err());
        assert!(read_directory(&json!({})).is_err());
    }
}
