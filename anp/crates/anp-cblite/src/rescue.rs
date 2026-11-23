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
use crate::group_member::GroupMember;
use crate::quotes::QuoteBuyer;

/// How long the agent waits for the answers to its requests.
const ANSWER_WAIT: Duration = Duration::from_secs(40);

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
    decided: tokio::sync::Notify,
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
            state: Mutex::new(State { phase: "idle".into(), log: vec![], plan: vec![], approval: None, group: None, summary: None }),
            decision: Mutex::new(None),
            decided: tokio::sync::Notify::new(),
        }
    }

    pub fn status(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({
            "phase": s.phase, "log": s.log, "approval": s.approval, "group": s.group, "summary": s.summary,
            "plan": s.plan.iter().map(|p| json!({ "company": p.company, "role": p.role, "category": p.category, "pallets": p.pallets, "amountMinor": p.amount_minor, "quote": p.quote_id })).collect::<Vec<_>>(),
            "directory": self.directory.lock().unwrap().iter().map(|c| json!({ "did": c.did, "role": c.role, "name": c.name })).collect::<Vec<_>>(),
            "discovery": if self.search.is_some() { "search agent" } else { "directory" },
        })
    }

    fn phase(&self, p: &str) {
        self.state.lock().unwrap().phase = p.into();
    }

    /// Log a step: `step` is the phase it belongs to, `rule` (when there is one) the rule that decided it.
    fn note(&self, step: &str, text: &str, rule: Option<&str>, data: Value) {
        log::info!("rescue [{step}] {text}");
        let mut s = self.state.lock().unwrap();
        let clock = self.store.state()["clock"].clone();
        s.log.push(json!({ "step": step, "text": text, "rule": rule, "data": data, "clock": clock, "at": chrono::Utc::now().format("%H:%M:%S").to_string() }));
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

    /// Start the rescue, unless one is running.
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        {
            let mut s = self.state.lock().unwrap();
            if !matches!(s.phase.as_str(), "idle" | "done" | "failed" | "declined") {
                return Err(format!("a rescue is already under way ({})", s.phase));
            }
            *s = State { phase: "starting".into(), log: vec![], plan: vec![], approval: None, group: None, summary: None };
        }
        *self.decision.lock().unwrap() = None;
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.run().await {
                me.note("failed", &e, None, Value::Null);
                me.phase("failed");
            }
        });
        Ok(())
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
            self.phase("discovering");
            self.discover(&s).await;
        }
        // 1. assess
        self.phase("assessing");
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
        self.phase("asking");
        let carriers = if frozen > 0 { self.ask_all(&self.of_role("carrier"), "transport", frozen).await } else { vec![] };
        let warehouses = if frozen > 0 { self.ask_all(&self.of_role("warehouse"), "storage", frozen).await } else { vec![] };
        let banks = if n.chilled > 0 { self.ask_all(&self.of_role("foodbank"), "donation", n.chilled).await } else { vec![] };
        let insurers = self.ask_all(&self.of_role("insurer"), "coverage", frozen.max(1)).await;
        let suppliers = if n.lost_pallets > 0 { self.ask_all(&self.of_role("supplier"), "restock", n.lost_pallets).await } else { vec![] };

        // 3. choose, through the rules
        self.phase("choosing");
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
            let Some(carrier) = fit.first() else {
                self.note("choosing", "no carrier can arrive in time: the frozen stock cannot be moved", Some("arrive before the goods are lost"), Value::Null);
                return self.finish(plan, at_stake).await;
            };
            for o in fit.iter().skip(1) {
                self.note("choosing", &format!("{} costs {} more than {}: not chosen", o.0.name, euros(o.1["amountMinor"].as_u64().unwrap_or(0) - carrier.1["amountMinor"].as_u64().unwrap_or(0)), carrier.0.name), Some("cheapest carrier that arrives in time"), Value::Null);
            }
            let transport = Self::pick(&carrier.0, &carrier.1, "transport");

            // storage: cheapest per pallet first; if the room offered falls short, ask the others for the rest
            let per_pallet = |q: &Value| q["amountMinor"].as_u64().unwrap_or(0) / q["terms"]["pallets"].as_u64().unwrap_or(1).max(1);
            let mut offers: Vec<(Company, Value)> = warehouses.clone();
            offers.sort_by_key(|o| per_pallet(&o.1));
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
                if let Some(d) = *self.decision.lock().unwrap() {
                    if !d {
                        self.note("declined", "the duty manager declined: nothing is committed", None, Value::Null);
                        self.phase("declined");
                        return Ok(());
                    }
                    break;
                }
                self.decided.notified().await;
            }
            self.note("committing", "the duty manager approved", None, self.buyer.state()["ledger"].clone());
        }

        // 5. commit, one acceptance per need
        self.phase("committing");
        let mut confirmed: Vec<Pick> = vec![];
        for p in &plan {
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
            self.phase("coordinating");
            let name = format!("rescue-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            match g.create(&name, None).await {
                Ok(group) => {
                    self.state.lock().unwrap().group = Some(group.clone());
                    self.note("coordinating", &format!("opened an encrypted group, {group}"), None, Value::Null);
                    let directory = self.directory.lock().unwrap().clone();
                    let dids: Vec<String> = confirmed.iter().filter_map(|p| directory.iter().find(|c| c.name == p.company).map(|c| c.did.clone())).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                    for did in dids {
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
        self.phase("proving");
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
