//! The quote protocol (`anp-quote`) on the node, over its encrypted direct messages: a **seller** desk for a counterparty and a
//! **buyer** desk for the store's agent.
//!
//! * **Seller** (`--counterparty PROFILE --buyer-root ROOT_PUBKEY...`): a quote-protocol message that arrives in a direct
//!   conversation goes to the desk, not to the agent. A request gets a signed quote or a signed refusal, decided by the profile's
//!   rules (`anp-counterparty`); an acceptance is checked by the seller itself ([`anp_quote::check_acceptance`]: the buyer's token
//!   from an authority it trusts, bound to the buyer's DID and key, covering the amount, the category and the site) and answered
//!   with a confirmation, or a refusal that says why. An over-limit acceptance is refused here, whatever the buyer's agent believes.
//! * **Buyer** (`--spend-token FILE --spend-root ROOT_PUBKEY --budget EUROS`): sends requests and acceptances signed with the
//!   node's DID key, verifies what comes back against the seller's DID document, keeps the [`anp_quote::Ledger`] (an acceptance
//!   reserves its amount; a confirmation commits it, a refusal frees it) and every completed deal as a record an insurer can audit
//!   offline. Its token caps each commitment; the budget caps them all. A new token or budget (the duty manager's approval) is
//!   given to the running node (`POST /anp/quotes/authority`).
//!
//! These are the tools the store's agent will use. Over HTTP, this machine only: `GET /anp/quotes`, `POST /anp/quotes/request`
//! `{to, category, pallets, need?}`, `POST /anp/quotes/accept` `{quote}`, `POST /anp/quotes/authority` `{token?, budget?}`,
//! `POST /anp/quotes/audit` `{acceptance}`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anp_counterparty::{Decision, Desk, Profile};
use anp_quote::{Kind, Ledger, QuoteError, Record};
use chrono::{Duration, Utc};
use serde_json::{json, Value};

use crate::direct_messaging::DirectMessaging;
use crate::trust::Trust;

fn write_private(file: &Path, v: &Value) {
    let tmp = file.with_extension("tmp");
    let r = std::fs::write(&tmp, v.to_string()).and_then(|_| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, file)
    });
    if let Err(e) = r {
        log::warn!("could not save {}: {e}", file.display());
    }
}

fn load(file: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()
}

fn short_id(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

/// Is this plaintext a quote-protocol message? Then it is the payload.
pub fn quote_message(plaintext: &Value) -> Option<&Value> {
    plaintext.get("payload").filter(|p| p["protocol"] == anp_quote::PROTOCOL)
}

// ── the seller ───────────────────────────────────────────────────────────────────────────────────────────────

pub struct QuoteSeller {
    trust: Arc<Trust>,
    roots: Vec<anp_authz::PublicKey>,
    desk: Mutex<Desk>,
    /// Quotes issued, by digest: the quote and the request it answers.
    issued: Mutex<HashMap<String, Value>>,
    /// Every answer given (newest last): what the counterparty said to whom.
    answers: Mutex<Vec<Value>>,
    file: PathBuf,
}

impl QuoteSeller {
    /// `profile` is a built-in profile id; `roots` the authorities whose spending tokens this counterparty accepts from buyers.
    pub fn new(trust: Arc<Trust>, profile: &str, roots: &[String], dir: &Path) -> Result<QuoteSeller, String> {
        trust.did().ok_or("a counterparty needs DID mode (--did-host)")?;
        let p = Profile::builtin(profile).ok_or_else(|| format!("no counterparty profile {profile}: one of {}", Profile::BUILTIN.join(", ")))?;
        if roots.is_empty() {
            return Err("a counterparty needs the authorities whose buyers' tokens it accepts (--buyer-root)".into());
        }
        let roots = roots.iter().map(|r| anp_authz::parse_public_key(r)).collect::<Result<Vec<_>, _>>()?;
        let file = dir.join("quotes-seller.json");
        let saved = load(&file).unwrap_or(Value::Null);
        let mut desk = Desk::new(p);
        desk.used_pallets = saved["usedPallets"].as_u64().unwrap_or(0) as u32;
        let issued = saved["issued"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
        let answers = saved["answers"].as_array().cloned().unwrap_or_default();
        Ok(QuoteSeller { trust, roots, desk: Mutex::new(desk), issued: Mutex::new(issued), answers: Mutex::new(answers), file })
    }

    fn save(&self) {
        let v = json!({ "usedPallets": self.desk.lock().unwrap().used_pallets, "issued": *self.issued.lock().unwrap(), "answers": *self.answers.lock().unwrap() });
        write_private(&self.file, &v);
    }

    pub fn state(&self) -> Value {
        let d = self.desk.lock().unwrap();
        json!({ "profile": d.profile.to_json(), "usedPallets": d.used_pallets, "freePallets": d.free_pallets(), "answers": *self.answers.lock().unwrap() })
    }

    fn me(&self) -> String {
        self.trust.did().unwrap_or_default().to_string()
    }

    /// Answer one quote-protocol message from `buyer` (its verified DID document). The answer is always a signed message: a quote
    /// or a confirmation, or a refusal with the reason.
    pub fn handle(&self, buyer: &anp_did::Verified, msg: &Value) -> Result<Value, String> {
        let (sk, me, now) = (self.trust.signing_key(), self.me(), Utc::now());
        let kind = anp_quote::verify(msg, buyer).map_err(|e| e.to_string())?;
        let reject = |why: String| anp_quote::reject(msg, &short_id("rej"), &why, sk, &me, now).map_err(|e| e.to_string());
        let answer = match kind {
            Kind::QuoteRequest => {
                let decision = self.desk.lock().unwrap().decide(msg);
                match decision {
                    Decision::Offer { amount_minor, valid_minutes, terms } => {
                        let offer = anp_quote::Offer { id: &short_id("q"), amount_minor, valid_until: now + Duration::minutes(valid_minutes as i64), terms };
                        let q = anp_quote::quote(msg, buyer, &offer, sk, &me, now).map_err(|e| e.to_string())?;
                        self.issued.lock().unwrap().insert(anp_quote::digest(&q).map_err(|e| e.to_string())?, json!({ "quote": q, "request": msg }));
                        q
                    }
                    Decision::Refuse(why) => reject(why)?,
                }
            }
            Kind::Acceptance => {
                let found = self.issued.lock().unwrap().get(msg["quote"].as_str().unwrap_or("")).cloned();
                match found {
                    None => reject("that is not a quote of ours".into())?,
                    Some(entry) => {
                        let quote = &entry["quote"];
                        // the buyer's authority: the first trusted root its token verifies against
                        let mut checked: Result<anp_quote::Accepted, QuoteError> = Err(QuoteError::Unauthorized("no authority".into()));
                        for root in &self.roots {
                            checked = anp_quote::check_acceptance(msg, buyer, quote, root, &|_| false, now);
                            if !matches!(&checked, Err(QuoteError::Unauthorized(_))) {
                                break;
                            }
                        }
                        match checked {
                            Err(e) => reject(e.to_string())?,
                            Ok(_) => {
                                let pallets = quote["terms"]["pallets"].as_u64().unwrap_or(0) as u32;
                                let room = self.desk.lock().unwrap().confirmed(pallets);
                                match room {
                                    Err(why) => reject(why)?,
                                    Ok(()) => anp_quote::confirm(msg, quote, &short_id("conf"), &short_id("REF").to_uppercase(), sk, &me, now).map_err(|e| e.to_string())?,
                                }
                            }
                        }
                    }
                }
            }
            other => return Err(format!("a seller does not take a {}", other.as_str())),
        };
        self.answers.lock().unwrap().push(json!({ "to": buyer.did_string, "in": msg["type"], "inId": msg["id"], "answer": answer["type"], "answerId": answer["id"],
                                                    "amountMinor": answer["amountMinor"], "reason": answer["reason"], "at": answer["created"] }));
        self.save();
        log::info!("quote desk: {} {} -> {}", msg["type"], msg["id"], answer["type"]);
        Ok(answer)
    }
}

// ── the buyer ────────────────────────────────────────────────────────────────────────────────────────────────

/// The buyer's standing: the token the authority issued it, the authority's key, and the budget.
struct Authority {
    token: String,
    root: anp_authz::PublicKey,
    root_b64: String,
}

pub struct QuoteBuyer {
    trust: Arc<Trust>,
    direct: Arc<DirectMessaging>,
    site: String,
    authority: Mutex<Authority>,
    ledger: Mutex<Ledger>,
    /// Requests sent, by id: `{to, request, answers: [ids of quotes and refusals]}`.
    requests: Mutex<HashMap<String, Value>>,
    /// Quotes received, by id: `{from, quote, requestId}`.
    quotes: Mutex<HashMap<String, Value>>,
    /// Acceptances sent, by id: `{to, quoteId, acceptance, status: pending|confirmed|refused, answer}`.
    acceptances: Mutex<HashMap<String, Value>>,
    /// Refusals received.
    refusals: Mutex<Vec<Value>>,
    file: PathBuf,
}

impl QuoteBuyer {
    /// `token_file` is the node's spending token (`anp-admin issue --spend-cap ... --did`), `root` the authority's public key,
    /// `budget_minor` the total the node may commit (in cents), `site` what it buys for.
    pub fn new(trust: Arc<Trust>, direct: Arc<DirectMessaging>, token: &str, root: &str, budget_minor: u64, site: &str, dir: &Path) -> Result<QuoteBuyer, String> {
        trust.did().ok_or("a buyer needs DID mode (--did-host)")?;
        let root_key = anp_authz::parse_public_key(root)?;
        let file = dir.join("quotes-buyer.json");
        let saved = load(&file).unwrap_or(Value::Null);
        let map = |k: &str| -> HashMap<String, Value> { saved[k].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default() };
        let ledger = match saved.get("ledger") {
            Some(l) => Ledger::from_json(l).map_err(|e| e.to_string())?,
            None => Ledger::new("EUR", budget_minor),
        };
        let token = saved["token"].as_str().map(str::to_string).unwrap_or_else(|| token.trim().to_string());
        Ok(QuoteBuyer {
            trust,
            direct,
            site: site.to_string(),
            authority: Mutex::new(Authority { token, root: root_key, root_b64: root.to_string() }),
            ledger: Mutex::new(ledger),
            requests: Mutex::new(map("requests")),
            quotes: Mutex::new(map("quotes")),
            acceptances: Mutex::new(map("acceptances")),
            refusals: Mutex::new(saved["refusals"].as_array().cloned().unwrap_or_default()),
            file,
        })
    }

    fn save(&self) {
        let v = json!({
            "token": self.authority.lock().unwrap().token, "ledger": self.ledger.lock().unwrap().to_json(),
            "requests": *self.requests.lock().unwrap(), "quotes": *self.quotes.lock().unwrap(),
            "acceptances": *self.acceptances.lock().unwrap(), "refusals": *self.refusals.lock().unwrap(),
        });
        write_private(&self.file, &v);
    }

    /// Follow the answers that arrive in direct conversations.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        let mut rx = self.direct.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(e) => {
                        if e["direction"] != "in" {
                            continue;
                        }
                        if let Some(msg) = quote_message(&e["plaintext"]) {
                            if let Err(err) = me.on_answer(e["peer"].as_str().unwrap_or(""), msg) {
                                log::warn!("quote buyer: an answer from {}: {err}", e["peer"]);
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => log::warn!("quote buyer: {n} messages missed"),
                    Err(_) => return,
                }
            }
        });
    }

    fn me(&self) -> String {
        self.trust.did().unwrap_or_default().to_string()
    }

    pub fn state(&self) -> Value {
        let l = self.ledger.lock().unwrap();
        json!({
            "site": self.site,
            "ledger": { "currency": l.currency, "budgetMinor": l.budget(), "outstandingMinor": l.outstanding(), "committedMinor": l.committed(), "remainingMinor": l.remaining(), "entries": l.to_json()["entries"] },
            "requests": *self.requests.lock().unwrap(), "quotes": *self.quotes.lock().unwrap(),
            "acceptances": *self.acceptances.lock().unwrap(), "refusals": *self.refusals.lock().unwrap(),
        })
    }

    /// Ask `to` for a quote: `category` (what the token must allow), `pallets`, more of the need in `need`. Returns the request id.
    pub async fn request(&self, to: &str, category: &str, pallets: u32, need: Value) -> Result<String, String> {
        let mut need = if need.is_object() { need } else { json!({}) };
        need["pallets"] = json!(pallets);
        let id = short_id("req");
        let spec = anp_quote::RequestSpec { id: &id, to, category, on_behalf_of: &self.site, currency: "EUR", need, respond_by: Utc::now() + Duration::minutes(15) };
        let msg = anp_quote::request(&spec, self.trust.signing_key(), &self.me(), Utc::now()).map_err(|e| e.to_string())?;
        self.direct.send(to, &crate::direct_messaging::plaintext_of(&id, None, Some(&msg))?).await?;
        self.requests.lock().unwrap().insert(id.clone(), json!({ "to": to, "request": msg, "answers": [] }));
        self.save();
        Ok(id)
    }

    /// Accept quote `quote_id`. Refused before anything is sent when the token does not cover it ([`QuoteError::Unauthorized`],
    /// checked first: only a new token from the authority helps) or when it would take the total over the budget
    /// ([`QuoteError::OverBudget`]: a person can raise it). Both are the cue to ask a person ([`QuoteBuyer::set_authority`]).
    pub async fn accept(&self, quote_id: &str) -> Result<String, QuoteError> {
        let entry = self.quotes.lock().unwrap().get(quote_id).cloned().ok_or_else(|| QuoteError::Mismatch(format!("no quote {quote_id}")))?;
        let (q, seller_did) = (entry["quote"].clone(), entry["from"].as_str().unwrap_or("").to_string());
        if self.acceptances.lock().unwrap().values().any(|a| a["quoteId"] == quote_id && a["status"] != "refused") {
            return Err(QuoteError::Mismatch(format!("{quote_id} is already accepted")));
        }
        let seller = self.direct.peer_document(&seller_did).ok_or_else(|| QuoteError::Signature(format!("no DID document for {seller_did}")))?;
        let id = short_id("acc");
        let amount = q["amountMinor"].as_u64().unwrap_or(0);
        // the token first: past its cap only the authority can help (a new token), whereas a person can raise the budget
        let acc = {
            let a = self.authority.lock().unwrap();
            let auth = anp_quote::Authority { node: self.trust.node_id(), token: &a.token, root: &a.root };
            anp_quote::accept(&q, &seller, &id, &auth, self.trust.signing_key(), &self.me(), Utc::now())?
        };
        // then the budget: an acceptance that would go over it is never sent
        self.ledger.lock().unwrap().reserve(&id, &seller_did, q["category"].as_str().unwrap_or(""), q["currency"].as_str().unwrap_or(""), amount)?;
        let sent = match crate::direct_messaging::plaintext_of(&id, None, Some(&acc)) {
            Ok(p) => self.direct.send(&seller_did, &p).await,
            Err(e) => Err(e),
        };
        if let Err(e) = sent {
            let _ = self.ledger.lock().unwrap().release(&id);
            self.save();
            return Err(QuoteError::Mismatch(format!("could not send the acceptance: {e}")));
        }
        self.acceptances.lock().unwrap().insert(id.clone(), json!({ "to": seller_did, "quoteId": quote_id, "acceptance": acc, "status": "pending", "amountMinor": amount }));
        self.save();
        Ok(id)
    }

    /// The duty manager's approval: a new token from the authority (a higher cap), a new budget, or both.
    pub fn set_authority(&self, token: Option<&str>, budget_minor: Option<u64>) -> Result<(), String> {
        if let Some(t) = token {
            let mut a = self.authority.lock().unwrap();
            // the token must be from the same authority (it is checked again by every seller)
            anp_authz::inspect(t.trim(), &a.root).map_err(|e| format!("not a token of this authority: {e}"))?;
            a.token = t.trim().to_string();
        }
        if let Some(b) = budget_minor {
            self.ledger.lock().unwrap().set_budget(b);
        }
        self.save();
        Ok(())
    }

    /// An answer from `from`: a quote or refusal for a request, a confirmation or refusal for an acceptance.
    fn on_answer(&self, from: &str, msg: &Value) -> Result<(), String> {
        let seller = self.direct.peer_document(from).ok_or_else(|| format!("no DID document for {from}"))?;
        let kind = anp_quote::verify(msg, &seller).map_err(|e| e.to_string())?;
        match kind {
            Kind::Quote => {
                let req_digest = msg["request"].as_str().unwrap_or("");
                let mut requests = self.requests.lock().unwrap();
                let (rid, r) = requests.iter_mut().find(|(_, r)| anp_quote::digest(&r["request"]).ok().as_deref() == Some(req_digest)).ok_or("a quote for a request we did not send")?;
                if r["to"] != json!(from) {
                    return Err("a quote from another seller than the one asked".into());
                }
                let qid = msg["id"].as_str().unwrap_or("").to_string();
                r["answers"].as_array_mut().map(|a| a.push(json!(qid)));
                let rid = rid.clone();
                drop(requests);
                self.quotes.lock().unwrap().insert(qid, json!({ "from": from, "quote": msg, "requestId": rid }));
            }
            Kind::Confirmation | Kind::Rejection => {
                // an answer to an acceptance, or a refusal of a request
                let in_reply = if kind == Kind::Confirmation { msg["acceptance"].as_str() } else { msg["inReplyTo"].as_str() }.unwrap_or("").to_string();
                let acc_id = self.acceptances.lock().unwrap().iter().find(|(_, a)| anp_quote::digest(&a["acceptance"]).ok().as_deref() == Some(in_reply.as_str())).map(|(k, _)| k.clone());
                match acc_id {
                    Some(id) => {
                        let acc = self.acceptances.lock().unwrap()[&id]["acceptance"].clone();
                        let confirmed = anp_quote::read_answer(msg, &seller, &acc).map_err(|e| e.to_string())?;
                        {
                            let mut l = self.ledger.lock().unwrap();
                            if confirmed { l.commit(&id) } else { l.release(&id) }.map_err(|e| e.to_string())?;
                        }
                        let mut accs = self.acceptances.lock().unwrap();
                        let a = accs.get_mut(&id).expect("found above");
                        a["status"] = json!(if confirmed { "confirmed" } else { "refused" });
                        a["answer"] = msg.clone();
                        if confirmed {
                            // the record: request, quote, acceptance, confirmation
                            let qid = a["quoteId"].as_str().unwrap_or("").to_string();
                            let q = self.quotes.lock().unwrap().get(&qid).cloned().unwrap_or(Value::Null);
                            let req = self.requests.lock().unwrap().get(q["requestId"].as_str().unwrap_or("")).map(|r| r["request"].clone()).unwrap_or(Value::Null);
                            a["record"] = Record { request: req, quote: q["quote"].clone(), acceptance: acc, confirmation: msg.clone() }.to_json();
                        }
                    }
                    None if kind == Kind::Rejection => {
                        let mut requests = self.requests.lock().unwrap();
                        if let Some(r) = requests.values_mut().find(|r| anp_quote::digest(&r["request"]).ok().as_deref() == Some(in_reply.as_str())) {
                            r["answers"].as_array_mut().map(|a| a.push(msg["id"].clone()));
                        }
                    }
                    None => return Err("a confirmation of an acceptance we did not send".into()),
                }
                if kind == Kind::Rejection {
                    self.refusals.lock().unwrap().push(json!({ "from": from, "id": msg["id"], "inReplyTo": in_reply, "reason": msg["reason"] }));
                }
            }
            other => return Err(format!("a buyer does not take a {}", other.as_str())),
        }
        self.save();
        Ok(())
    }

    /// Check a confirmed deal the way an insurer would, offline: every signature, the chain of digests, and the token at the time of
    /// the acceptance.
    pub fn audit(&self, acceptance_id: &str) -> Result<Value, String> {
        let rec = self.acceptances.lock().unwrap().get(acceptance_id).map(|a| a["record"].clone()).filter(|r| r.is_object()).ok_or("no confirmed deal under that acceptance")?;
        let rec = Record::from_json(&rec).map_err(|e| e.to_string())?;
        let root = self.authority.lock().unwrap().root;
        let direct = self.direct.clone();
        let mine = anp_did::verify_document(&self.trust.did_document().unwrap_or(Value::Null), None).ok();
        let docs = move |did: &str| direct.peer_document(did).or_else(|| mine.clone().filter(|m| m.did_string == did));
        let ok = anp_quote::audit(&rec, &docs, &root).map_err(|e| e.to_string())?;
        Ok(json!({ "valid": true, "buyer": ok.buyer, "amountMinor": ok.amount_minor, "currency": ok.currency, "category": ok.category, "onBehalfOf": ok.on_behalf_of, "authority": self.authority.lock().unwrap().root_b64 }))
    }
}
