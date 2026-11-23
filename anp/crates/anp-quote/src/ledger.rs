//! The buyer's own running total.
//!
//! A token caps each commitment, and a counterparty only ever sees its own deal, so no one but the buyer can hold the
//! total over several. The ledger does: the agent [`reserve`](Ledger::reserve)s an amount before it sends an
//! acceptance, [`commit`](Ledger::commit)s it on a confirmation and [`release`](Ledger::release)s it on a rejection
//! or when no answer comes. Reserved and committed amounts both count against the budget, so two acceptances in
//! flight cannot together go over it.
//!
//! The budget is set by the owner and raised only by a person (the duty manager's approval); the agent cannot change
//! it. It is plain JSON ([`Ledger::to_json`]) so it can live in the node's database and survive a restart.

use serde_json::{json, Value};

use crate::QuoteError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// An acceptance is out, no answer yet.
    Reserved,
    /// Confirmed by the seller.
    Committed,
    /// Rejected, or given up on: no longer counts.
    Released,
}

impl EntryState {
    fn as_str(self) -> &'static str {
        match self {
            EntryState::Reserved => "reserved",
            EntryState::Committed => "committed",
            EntryState::Released => "released",
        }
    }

    fn parse(s: &str) -> Option<EntryState> {
        [EntryState::Reserved, EntryState::Committed, EntryState::Released].into_iter().find(|e| e.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The acceptance's id.
    pub id: String,
    /// The seller's DID.
    pub counterparty: String,
    pub category: String,
    pub amount_minor: u64,
    pub state: EntryState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub currency: String,
    budget_minor: u64,
    entries: Vec<Entry>,
}

impl Ledger {
    pub fn new(currency: &str, budget_minor: u64) -> Ledger {
        Ledger { currency: currency.into(), budget_minor, entries: Vec::new() }
    }

    pub fn budget(&self) -> u64 {
        self.budget_minor
    }

    /// A person raised (or lowered) the budget. Entries already made stand, even if they now exceed it.
    pub fn set_budget(&mut self, budget_minor: u64) {
        self.budget_minor = budget_minor;
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn sum(&self, f: impl Fn(&Entry) -> bool) -> u64 {
        self.entries.iter().filter(|e| f(e)).map(|e| e.amount_minor).sum()
    }

    /// Reserved and committed together: what is spoken for.
    pub fn outstanding(&self) -> u64 {
        self.sum(|e| e.state != EntryState::Released)
    }

    pub fn committed(&self) -> u64 {
        self.sum(|e| e.state == EntryState::Committed)
    }

    pub fn remaining(&self) -> u64 {
        self.budget_minor.saturating_sub(self.outstanding())
    }

    /// Hold `amount_minor` for acceptance `id` before sending it. Refused when it would take the total over budget,
    /// when the currency is not the ledger's, or when `id` is already used.
    pub fn reserve(&mut self, id: &str, counterparty: &str, category: &str, currency: &str, amount_minor: u64) -> Result<(), QuoteError> {
        if currency != self.currency {
            return Err(QuoteError::Mismatch(format!("the ledger is in {}, not {currency}", self.currency)));
        }
        if self.entries.iter().any(|e| e.id == id) {
            return Err(QuoteError::Malformed(format!("'{id}' is already in the ledger")));
        }
        let remaining = self.remaining();
        if amount_minor > remaining {
            return Err(QuoteError::OverBudget { needed: amount_minor, remaining });
        }
        self.entries.push(Entry { id: id.into(), counterparty: counterparty.into(), category: category.into(), amount_minor, state: EntryState::Reserved });
        Ok(())
    }

    fn settle(&mut self, id: &str, to: EntryState) -> Result<(), QuoteError> {
        let e = self.entries.iter_mut().find(|e| e.id == id).ok_or_else(|| QuoteError::Mismatch(format!("no reservation '{id}'")))?;
        if e.state != EntryState::Reserved {
            return Err(QuoteError::Mismatch(format!("'{id}' is already {}", e.state.as_str())));
        }
        e.state = to;
        Ok(())
    }

    /// The seller confirmed acceptance `id`.
    pub fn commit(&mut self, id: &str) -> Result<(), QuoteError> {
        self.settle(id, EntryState::Committed)
    }

    /// The seller rejected acceptance `id`, or no answer came: the amount is free again.
    pub fn release(&mut self, id: &str) -> Result<(), QuoteError> {
        self.settle(id, EntryState::Released)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "currency": self.currency,
            "budgetMinor": self.budget_minor,
            "entries": self.entries.iter().map(|e| json!({
                "id": e.id, "counterparty": e.counterparty, "category": e.category,
                "amountMinor": e.amount_minor, "state": e.state.as_str(),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Result<Ledger, QuoteError> {
        let bad = |m: &str| QuoteError::Malformed(format!("ledger: {m}"));
        let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).map(str::to_owned).ok_or_else(|| bad(&format!("no '{k}'")));
        let n = |x: &Value, k: &str| x.get(k).and_then(Value::as_u64).ok_or_else(|| bad(&format!("no '{k}'")));
        let mut l = Ledger::new(&s(v, "currency")?, n(v, "budgetMinor")?);
        for e in v.get("entries").and_then(Value::as_array).ok_or_else(|| bad("no 'entries'"))? {
            l.entries.push(Entry {
                id: s(e, "id")?,
                counterparty: s(e, "counterparty")?,
                category: s(e, "category")?,
                amount_minor: n(e, "amountMinor")?,
                state: EntryState::parse(&s(e, "state")?).ok_or_else(|| bad("unknown state"))?,
            });
        }
        Ok(l)
    }
}
