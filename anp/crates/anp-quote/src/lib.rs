//! Signed quotes between agents that belong to different companies.
//!
//! Four messages, each a JSON object signed (`eddsa-jcs-2022`, `assertionMethod`) with the key bound to the
//! sender's `did:wba`, and each naming the one before it by digest, so the chain cannot be re-ordered or edited:
//!
//! ```text
//! buyer                                   seller
//!   QuoteRequest  what, for whom, by when  ->
//!               <-  Quote          a price, valid until, terms        (request: sha256 of the request)
//!   Acceptance    the price, + the buyer's token  ->                  (quote: sha256 of the quote)
//!               <-  Confirmation   or Rejection with a reason         (acceptance: sha256 of the acceptance)
//! ```
//!
//! ```json
//! { "protocol": "anp.quote.v1", "type": "Acceptance", "id": "acc-1",
//!   "from": "did:wba:store.test:agents:store-0412:e1_...", "to": "did:wba:carrier-b.test:agents:dispatch:e1_...",
//!   "created": "2026-11-23T02:31:00Z", "quote": "sha256:9f2c...",
//!   "amountMinor": 720000, "currency": "EUR", "category": "transport", "onBehalfOf": "store-0412",
//!   "node": "store-0412", "token": "<biscuit, base64>", "proof": { ... } }
//! ```
//!
//! The point of the acceptance is that **the seller can check the buyer's authority itself**: the token must come
//! from the authority the seller trusts for that buyer, be bound to the buyer's DID and key (the key that signed the
//! acceptance), and allow this amount, currency, category and site ([`anp_authz::authorize_commitment`]). What the
//! buyer's agent says or believes plays no part. [`accept`] runs the same check on the buyer's side before it signs,
//! so an agent never sends what the other side will refuse.
//!
//! Every message verifies with nothing but the signers' DID documents and the authority's public key, so a record
//! ([`audit`]) can be checked the next morning, offline, after the token has expired: the token is judged at the
//! time of the acceptance.
//!
//! The token caps each commitment; the buyer's running total over several is its own [`Ledger`].

use std::fmt;

use anp_authz::{authorize_commitment_at, Commitment, PublicKey};
use anp_did::{SigningKey, Verified};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub mod ledger;
pub use ledger::{Entry, EntryState, Ledger};

/// The value of every message's `protocol` member.
pub const PROTOCOL: &str = "anp.quote.v1";
/// The largest amount a message may carry, in minor units: what a JSON number holds exactly (2^53 - 1).
pub const MAX_AMOUNT_MINOR: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteError {
    /// Not a well-formed message of this protocol.
    Malformed(String),
    /// Not signed by the DID it claims to come from.
    Signature(String),
    /// Does not answer the message it claims to (wrong digest, party or terms).
    Mismatch(String),
    /// Too late: the quote is no longer valid.
    Expired(String),
    /// Outside the signer's authority: its token does not allow this commitment.
    Unauthorized(String),
    /// The signer's token has been revoked.
    Revoked(String),
    /// More than the buyer's remaining budget.
    OverBudget { needed: u64, remaining: u64 },
}

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteError::Malformed(m) => write!(f, "malformed: {m}"),
            QuoteError::Signature(m) => write!(f, "bad signature: {m}"),
            QuoteError::Mismatch(m) => write!(f, "mismatch: {m}"),
            QuoteError::Expired(m) => write!(f, "expired: {m}"),
            QuoteError::Unauthorized(m) => write!(f, "not authorized: {m}"),
            QuoteError::Revoked(m) => write!(f, "revoked: {m}"),
            QuoteError::OverBudget { needed, remaining } => write!(f, "over budget: needs {needed}, {remaining} left"),
        }
    }
}

impl std::error::Error for QuoteError {}

type R<T> = Result<T, QuoteError>;

fn malformed<T>(m: impl Into<String>) -> R<T> {
    Err(QuoteError::Malformed(m.into()))
}

fn mismatch<T>(m: impl Into<String>) -> R<T> {
    Err(QuoteError::Mismatch(m.into()))
}

/// 1-64 characters of `[A-Za-z0-9._:-]`: the names `anp-authz` accepts (ids, categories, sites, node names).
fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

fn currency_ok(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// An RFC 3339 timestamp in UTC, to the second, as messages carry them.
pub fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The kinds of message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    QuoteRequest,
    Quote,
    Acceptance,
    Confirmation,
    Rejection,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::QuoteRequest => "QuoteRequest",
            Kind::Quote => "Quote",
            Kind::Acceptance => "Acceptance",
            Kind::Confirmation => "Confirmation",
            Kind::Rejection => "Rejection",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        [Kind::QuoteRequest, Kind::Quote, Kind::Acceptance, Kind::Confirmation, Kind::Rejection].into_iter().find(|k| k.as_str() == s)
    }
}

// ── reading fields ──────────────────────────────────────────────────────────────────────────────────────────

fn str_of<'a>(m: &'a Value, k: &str) -> R<&'a str> {
    match m.get(k).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => malformed(format!("'{k}' must be a non-empty string")),
    }
}

fn ident_of<'a>(m: &'a Value, k: &str) -> R<&'a str> {
    let s = str_of(m, k)?;
    if !ident_ok(s) {
        return malformed(format!("'{k}' must be 1-64 characters of [A-Za-z0-9._:-]"));
    }
    Ok(s)
}

fn time_of(m: &Value, k: &str) -> R<DateTime<Utc>> {
    let s = str_of(m, k)?;
    DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&Utc)).or_else(|_| malformed(format!("'{k}' must be an RFC 3339 timestamp")))
}

fn amount_of(m: &Value) -> R<u64> {
    match m.get("amountMinor").and_then(Value::as_u64) {
        Some(a) if a <= MAX_AMOUNT_MINOR => Ok(a),
        _ => malformed(format!("'amountMinor' must be a whole number of minor units, at most {MAX_AMOUNT_MINOR}")),
    }
}

fn digest_of<'a>(m: &'a Value, k: &str) -> R<&'a str> {
    let s = str_of(m, k)?;
    match s.strip_prefix("sha256:") {
        Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) => Ok(s),
        _ => malformed(format!("'{k}' must be a digest, sha256:<64 hex>")),
    }
}

fn did_of<'a>(m: &'a Value, k: &str) -> R<&'a str> {
    let s = str_of(m, k)?;
    anp_did::WbaDid::parse(s).map_err(|e| QuoteError::Malformed(format!("'{k}': {e}")))?;
    Ok(s)
}

/// The kind of a message, after checking every member that kind requires. Does not look at the signature.
pub fn check_shape(m: &Value) -> R<Kind> {
    if !m.is_object() {
        return malformed("not an object");
    }
    if m.get("protocol").and_then(Value::as_str) != Some(PROTOCOL) {
        return malformed(format!("'protocol' must be \"{PROTOCOL}\""));
    }
    let kind = Kind::parse(str_of(m, "type")?).ok_or_else(|| QuoteError::Malformed("unknown 'type'".into()))?;
    ident_of(m, "id")?;
    did_of(m, "from")?;
    did_of(m, "to")?;
    time_of(m, "created")?;
    let terms = |m: &Value| -> R<()> {
        ident_of(m, "category")?;
        ident_of(m, "onBehalfOf")?;
        if !currency_ok(str_of(m, "currency")?) {
            return malformed("'currency' must be a three-letter ISO 4217 code such as EUR");
        }
        Ok(())
    };
    match kind {
        Kind::QuoteRequest => {
            terms(m)?;
            time_of(m, "respondBy")?;
            if !m.get("need").map_or(false, Value::is_object) {
                return malformed("'need' must be an object");
            }
        }
        Kind::Quote => {
            terms(m)?;
            digest_of(m, "request")?;
            amount_of(m)?;
            time_of(m, "validUntil")?;
            if !m.get("terms").map_or(false, Value::is_object) {
                return malformed("'terms' must be an object");
            }
        }
        Kind::Acceptance => {
            terms(m)?;
            digest_of(m, "quote")?;
            amount_of(m)?;
            ident_of(m, "node")?;
            str_of(m, "token")?;
        }
        Kind::Confirmation => {
            digest_of(m, "acceptance")?;
            digest_of(m, "quote")?;
            str_of(m, "reference")?;
        }
        Kind::Rejection => {
            digest_of(m, "inReplyTo")?;
            str_of(m, "reason")?;
        }
    }
    Ok(kind)
}

// ── signing and verifying ───────────────────────────────────────────────────────────────────────────────────

/// `sha256:<hex>` of the canonical JSON (RFC 8785) of a signed message, proof included: how the next message names it.
pub fn digest(m: &Value) -> R<String> {
    let c = anp_did::jcs(m).map_err(|e| QuoteError::Malformed(e.to_string()))?;
    let h = Sha256::digest(c.as_bytes());
    Ok(format!("sha256:{}", h.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// The verification method a message from `did` is signed with: the key the DID is bound to.
fn method_for(did: &str) -> R<String> {
    let parsed = anp_did::WbaDid::parse(did).map_err(|e| QuoteError::Malformed(e.to_string()))?;
    let fp = parsed.e1().ok_or_else(|| QuoteError::Malformed("only e1 DIDs can sign quotes".into()))?;
    Ok(format!("{did}#{fp}"))
}

fn sign(mut m: Value, sk: &SigningKey, did: &str, now: DateTime<Utc>) -> R<Value> {
    let vm = method_for(did)?;
    if vm.rsplit('#').next() != Some(anp_did::thumbprint(&sk.verifying_key().to_bytes()).as_str()) {
        return Err(QuoteError::Signature("the signing key is not the one this DID is bound to".into()));
    }
    check_shape(&m)?;
    anp_did::add_proof_legacy(&mut m, sk, &vm, "assertionMethod", &ts(now), &Map::new()).map_err(|e| QuoteError::Signature(e.to_string()))?;
    Ok(m)
}

/// Check a message's shape and that it was signed by `signer` (the verified DID document of its `from`), with the
/// key the DID is bound to. Returns its kind. This works offline, from a DID document fetched earlier.
pub fn verify(m: &Value, signer: &Verified) -> R<Kind> {
    let kind = check_shape(m)?;
    if m["from"].as_str() != Some(signer.did_string.as_str()) {
        return Err(QuoteError::Signature(format!("comes from {}, but the document is {}", m["from"], signer.did_string)));
    }
    let proof = m.get("proof").ok_or_else(|| QuoteError::Signature("not signed".into()))?;
    if proof["proofPurpose"] != "assertionMethod" {
        return Err(QuoteError::Signature("the proof's purpose must be assertionMethod".into()));
    }
    if proof["verificationMethod"].as_str() != Some(method_for(&signer.did_string)?.as_str()) {
        return Err(QuoteError::Signature("not signed with the key the DID is bound to".into()));
    }
    anp_did::verify_proof(m, &signer.key).map_err(|e| QuoteError::Signature(e.to_string()))?;
    Ok(kind)
}

fn expect(m: &Value, signer: &Verified, want: Kind) -> R<()> {
    let k = verify(m, signer)?;
    if k != want {
        return mismatch(format!("expected a {}, got a {}", want.as_str(), k.as_str()));
    }
    Ok(())
}

fn header(kind: Kind, id: &str, from: &str, to: &str, now: DateTime<Utc>) -> Value {
    json!({ "protocol": PROTOCOL, "type": kind.as_str(), "id": id, "from": from, "to": to, "created": ts(now) })
}

/// Copy the terms (category, site, currency) of `from` into `to`.
fn copy_terms(to: &mut Value, from: &Value) {
    for k in ["category", "onBehalfOf", "currency"] {
        to[k] = from[k].clone();
    }
}

fn same_terms(a: &Value, b: &Value, what: &str) -> R<()> {
    for k in ["category", "onBehalfOf", "currency"] {
        if a[k] != b[k] {
            return mismatch(format!("{what}: '{k}' differs"));
        }
    }
    Ok(())
}

// ── the four steps ──────────────────────────────────────────────────────────────────────────────────────────

/// What a buyer asks for.
#[derive(Debug, Clone)]
pub struct RequestSpec<'a> {
    pub id: &'a str,
    /// The seller's DID.
    pub to: &'a str,
    /// What kind of purchase (`transport`, `storage`): checked against the buyer's token at acceptance.
    pub category: &'a str,
    /// The site it is for.
    pub on_behalf_of: &'a str,
    pub currency: &'a str,
    /// What is needed, free form (pallets, temperature, pick-up address, ...).
    pub need: Value,
    /// Quotes after this are of no use.
    pub respond_by: DateTime<Utc>,
}

/// Step 1, buyer: a signed request for a quote.
pub fn request(spec: &RequestSpec, sk: &SigningKey, my_did: &str, now: DateTime<Utc>) -> R<Value> {
    let mut m = header(Kind::QuoteRequest, spec.id, my_did, spec.to, now);
    m["category"] = json!(spec.category);
    m["onBehalfOf"] = json!(spec.on_behalf_of);
    m["currency"] = json!(spec.currency);
    m["need"] = spec.need.clone();
    m["respondBy"] = json!(ts(spec.respond_by));
    sign(m, sk, my_did, now)
}

/// What a seller offers.
#[derive(Debug, Clone)]
pub struct Offer<'a> {
    pub id: &'a str,
    pub amount_minor: u64,
    pub valid_until: DateTime<Utc>,
    /// Free form: arrival time, pallets, temperature range, ...
    pub terms: Value,
}

/// Step 2, seller: a signed quote answering `req` (verified with the buyer's DID document).
pub fn quote(req: &Value, buyer: &Verified, offer: &Offer, sk: &SigningKey, my_did: &str, now: DateTime<Utc>) -> R<Value> {
    expect(req, buyer, Kind::QuoteRequest)?;
    if req["to"].as_str() != Some(my_did) {
        return mismatch("the request is addressed to another agent");
    }
    let mut m = header(Kind::Quote, offer.id, my_did, buyer.did_string.as_str(), now);
    copy_terms(&mut m, req);
    m["request"] = json!(digest(req)?);
    m["amountMinor"] = json!(offer.amount_minor);
    m["validUntil"] = json!(ts(offer.valid_until));
    m["terms"] = offer.terms.clone();
    sign(m, sk, my_did, now)
}

/// The buyer's standing: the node name its token was issued to, the token, and the authority's key.
#[derive(Debug, Clone, Copy)]
pub struct Authority<'a> {
    pub node: &'a str,
    pub token: &'a str,
    pub root: &'a PublicKey,
}

fn commitment_of<'a>(m: &'a Value, node: &'a str, key_b64: &'a str) -> R<Commitment<'a>> {
    Ok(Commitment {
        node,
        key_b64,
        amount_minor: amount_of(m)?,
        currency: str_of(m, "currency")?,
        category: str_of(m, "category")?,
        on_behalf_of: str_of(m, "onBehalfOf")?,
    })
}

/// Step 3, buyer: accept `q` (verified with the seller's DID document), carrying the buyer's token. Refuses, before
/// signing anything, a quote that has expired or that the token does not cover: the same check the seller will run,
/// so an over-limit acceptance is never sent ([`QuoteError::Unauthorized`] is the agent's cue to ask a human).
pub fn accept(q: &Value, seller: &Verified, id: &str, auth: &Authority, sk: &SigningKey, my_did: &str, now: DateTime<Utc>) -> R<Value> {
    expect(q, seller, Kind::Quote)?;
    if q["to"].as_str() != Some(my_did) {
        return mismatch("the quote is addressed to another agent");
    }
    let until = time_of(q, "validUntil")?;
    if now > until {
        return Err(QuoteError::Expired(format!("the quote was valid until {}", ts(until))));
    }
    let key = B64.encode(sk.verifying_key().to_bytes());
    authorize_commitment_at(auth.token, auth.root, &commitment_of(q, auth.node, &key)?, Some(my_did), now.into()).map_err(QuoteError::Unauthorized)?;
    let mut m = header(Kind::Acceptance, id, my_did, seller.did_string.as_str(), now);
    copy_terms(&mut m, q);
    m["quote"] = json!(digest(q)?);
    m["amountMinor"] = q["amountMinor"].clone();
    m["node"] = json!(auth.node);
    m["token"] = json!(auth.token);
    sign(m, sk, my_did, now)
}

/// What a seller learns from an acceptance that passed [`check_acceptance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub buyer: String,
    pub amount_minor: u64,
    pub currency: String,
    pub category: String,
    pub on_behalf_of: String,
    /// The token's revocation ids (to look up again later against newer revocations).
    pub revocation_ids: Vec<String>,
}

/// Step 3, seller: may it rely on acceptance `acc` of its own quote `my_quote`? `buyer` is the buyer's verified DID
/// document, `root` the authority the seller trusts for that buyer, `is_revoked` the seller's deny-list.
///
/// Checks that the acceptance is signed by the buyer, answers exactly `my_quote` (same digest, amount and terms),
/// arrives while the quote is valid, and that the buyer's token, bound to the buyer's DID and to the key that signed
/// the acceptance, allows this commitment and is not revoked.
pub fn check_acceptance(
    acc: &Value,
    buyer: &Verified,
    my_quote: &Value,
    root: &PublicKey,
    is_revoked: &dyn Fn(&str) -> bool,
    now: DateTime<Utc>,
) -> R<Accepted> {
    expect(acc, buyer, Kind::Acceptance)?;
    check_shape(my_quote)?;
    if acc["to"] != my_quote["from"] || acc["from"] != my_quote["to"] {
        return mismatch("the acceptance is not between the parties of the quote");
    }
    if acc["quote"].as_str() != Some(digest(my_quote)?.as_str()) {
        return mismatch("the acceptance answers another quote");
    }
    if acc["amountMinor"] != my_quote["amountMinor"] {
        return mismatch("the amount differs from the quote");
    }
    same_terms(acc, my_quote, "the acceptance")?;
    let until = time_of(my_quote, "validUntil")?;
    if now > until {
        return Err(QuoteError::Expired(format!("the quote was valid until {}", ts(until))));
    }
    // the key that signed the acceptance is the key the token must name
    let key = B64.encode(buyer.key.to_bytes());
    let node = ident_of(acc, "node")?;
    let ok = authorize_commitment_at(str_of(acc, "token")?, root, &commitment_of(acc, node, &key)?, Some(&buyer.did_string), now.into())
        .map_err(QuoteError::Unauthorized)?;
    if let Some(id) = ok.revocation_ids.iter().find(|id| is_revoked(id)) {
        return Err(QuoteError::Revoked(format!("token {}", &id[..id.len().min(16)])));
    }
    Ok(Accepted {
        buyer: buyer.did_string.clone(),
        amount_minor: amount_of(acc)?,
        currency: str_of(acc, "currency")?.into(),
        category: str_of(acc, "category")?.into(),
        on_behalf_of: str_of(acc, "onBehalfOf")?.into(),
        revocation_ids: ok.revocation_ids,
    })
}

/// Step 4, seller: confirm an acceptance it checked ([`check_acceptance`]). `reference` is the seller's own booking
/// reference.
pub fn confirm(acc: &Value, my_quote: &Value, id: &str, reference: &str, sk: &SigningKey, my_did: &str, now: DateTime<Utc>) -> R<Value> {
    if acc["to"].as_str() != Some(my_did) {
        return mismatch("the acceptance is addressed to another agent");
    }
    let mut m = header(Kind::Confirmation, id, my_did, str_of(acc, "from")?, now);
    m["acceptance"] = json!(digest(acc)?);
    m["quote"] = json!(digest(my_quote)?);
    m["reference"] = json!(reference);
    sign(m, sk, my_did, now)
}

/// Either side: a signed refusal of `msg` (a request it will not quote, an acceptance it will not honour), with a
/// reason for the other agent and for the record.
pub fn reject(msg: &Value, id: &str, reason: &str, sk: &SigningKey, my_did: &str, now: DateTime<Utc>) -> R<Value> {
    if msg["to"].as_str() != Some(my_did) {
        return mismatch("the message is addressed to another agent");
    }
    let mut m = header(Kind::Rejection, id, my_did, str_of(msg, "from")?, now);
    m["inReplyTo"] = json!(digest(msg)?);
    m["reason"] = json!(reason);
    sign(m, sk, my_did, now)
}

/// Buyer: check the seller's answer to `my_acceptance` and say whether it was confirmed (`Ok(true)`) or rejected
/// (`Ok(false)`, the reason in the message).
pub fn read_answer(answer: &Value, seller: &Verified, my_acceptance: &Value) -> R<bool> {
    let kind = verify(answer, seller)?;
    if answer["to"] != my_acceptance["from"] || answer["from"] != my_acceptance["to"] {
        return mismatch("the answer is not between the parties of the acceptance");
    }
    let d = digest(my_acceptance)?;
    match kind {
        Kind::Confirmation if answer["acceptance"].as_str() == Some(d.as_str()) && answer["quote"] == my_acceptance["quote"] => Ok(true),
        Kind::Rejection if answer["inReplyTo"].as_str() == Some(d.as_str()) => Ok(false),
        Kind::Confirmation | Kind::Rejection => mismatch("the answer is about another acceptance"),
        k => mismatch(format!("a {} is not an answer to an acceptance", k.as_str())),
    }
}

// ── the record ──────────────────────────────────────────────────────────────────────────────────────────────

/// The four signed messages of one deal.
#[derive(Debug, Clone)]
pub struct Record {
    pub request: Value,
    pub quote: Value,
    pub acceptance: Value,
    pub confirmation: Value,
}

impl Record {
    pub fn to_json(&self) -> Value {
        json!({ "request": self.request, "quote": self.quote, "acceptance": self.acceptance, "confirmation": self.confirmation })
    }

    pub fn from_json(v: &Value) -> R<Record> {
        let part = |k: &str| v.get(k).cloned().ok_or_else(|| QuoteError::Malformed(format!("record: no '{k}'")));
        Ok(Record { request: part("request")?, quote: part("quote")?, acceptance: part("acceptance")?, confirmation: part("confirmation")? })
    }
}

/// Check a whole deal after the fact, offline: every message is signed by its sender (`did_doc` returns the verified
/// DID document of a DID, from a cache), each answers the one before it, the terms carry through unchanged, the
/// quote was still valid when accepted and confirmed afterwards, and the buyer's token allowed the commitment **at
/// the time of the acceptance** (so an expired token does not fail an old record). Revocations are not looked at:
/// the caller judges whether one issued before the acceptance matters.
pub fn audit(rec: &Record, did_doc: &dyn Fn(&str) -> Option<Verified>, root: &PublicKey) -> R<Accepted> {
    let doc = |m: &Value| -> R<Verified> {
        let d = str_of(m, "from")?;
        did_doc(d).ok_or_else(|| QuoteError::Signature(format!("no DID document for {d}")))
    };
    let (buyer, seller) = (doc(&rec.request)?, doc(&rec.quote)?);
    expect(&rec.request, &buyer, Kind::QuoteRequest)?;
    expect(&rec.quote, &seller, Kind::Quote)?;
    expect(&rec.confirmation, &seller, Kind::Confirmation)?;
    if rec.request["to"] != rec.quote["from"] || rec.request["from"] != rec.quote["to"] {
        return mismatch("the quote is not between the parties of the request");
    }
    if rec.quote["request"].as_str() != Some(digest(&rec.request)?.as_str()) {
        return mismatch("the quote answers another request");
    }
    same_terms(&rec.quote, &rec.request, "the quote")?;
    let at = time_of(&rec.acceptance, "created")?;
    let ok = check_acceptance(&rec.acceptance, &buyer, &rec.quote, root, &|_| false, at)?;
    if rec.confirmation["to"] != rec.acceptance["from"] {
        return mismatch("the confirmation is addressed to someone else");
    }
    if rec.confirmation["acceptance"].as_str() != Some(digest(&rec.acceptance)?.as_str()) || rec.confirmation["quote"] != rec.acceptance["quote"] {
        return mismatch("the confirmation is about another acceptance");
    }
    if time_of(&rec.confirmation, "created")? < at {
        return mismatch("confirmed before it was accepted");
    }
    Ok(ok)
}

#[cfg(test)]
mod tests;
