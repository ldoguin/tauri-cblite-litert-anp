use std::time::SystemTime;

use anp_authz::{Grant, Spend};
use chrono::Duration;

use super::*;

struct Party {
    did: String,
    sk: SigningKey,
    doc: Verified,
}

fn party(host: &str, name: &str, seed: u8) -> Party {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let did = anp_did::did_for_key(host, None, &["agents", name], &sk.verifying_key().to_bytes());
    let doc = anp_did::build_document(&did, &sk, &[], "2026-11-23T00:00:00Z").unwrap();
    let doc = anp_did::verify_document(&doc, Some(&did)).unwrap();
    Party { did, sk, doc }
}

struct World {
    store: Party,
    carrier: Party,
    thief: Party,
    authority: anp_authz::Authority,
    root: PublicKey,
    token: String,
    t0: DateTime<Utc>,
}

/// A store whose token allows up to `cap` cents for transport or storage at store-0412, valid from `t0` for 8 hours.
fn token_for(authority: &anp_authz::Authority, store: &Party, cap: u64, t0: DateTime<Utc>) -> String {
    authority
        .issue(&Grant {
            node: "store-0412".into(),
            node_key_b64: B64.encode(store.sk.verifying_key().to_bytes()),
            inbox_targets: vec![],
            expires: Some(SystemTime::from(t0 + Duration::hours(8))),
            did: Some(store.did.clone()),
            spend: Some(Spend {
                currency: "EUR".into(),
                cap_minor: cap,
                categories: vec!["transport".into(), "storage".into()],
                on_behalf_of: Some("store-0412".into()),
            }),
        })
        .unwrap()
}

fn world() -> World {
    world_at(Utc::now())
}

fn world_at(t0: DateTime<Utc>) -> World {
    let store = party("store.test", "store-0412", 1);
    let carrier = party("carrier-b.test", "dispatch", 2);
    let thief = party("mallory.test", "store-0412", 3);
    let authority = anp_authz::Authority::generate();
    let root = authority.public_key();
    let token = token_for(&authority, &store, 600_000, t0);
    World { store, carrier, thief, authority, root, token, t0 }
}

impl World {
    fn auth(&self) -> Authority<'_> {
        Authority { node: "store-0412", token: &self.token, root: &self.root }
    }

    fn request(&self, category: &str) -> Value {
        let spec = RequestSpec {
            id: "req-1",
            to: &self.carrier.did,
            category,
            on_behalf_of: "store-0412",
            currency: "EUR",
            need: json!({ "pallets": 3, "tempMaxC": -18, "pickup": "store 0412 loading bay" }),
            respond_by: self.t0 + Duration::minutes(15),
        };
        request(&spec, &self.store.sk, &self.store.did, self.t0).unwrap()
    }

    fn quote(&self, req: &Value, amount_minor: u64) -> Value {
        let offer = Offer { id: "q-1", amount_minor, valid_until: self.t0 + Duration::minutes(30), terms: json!({ "arrivesBy": "03:05" }) };
        quote(req, &self.store.doc, &offer, &self.carrier.sk, &self.carrier.did, self.t0 + Duration::minutes(2)).unwrap()
    }

    fn accept(&self, q: &Value) -> R<Value> {
        accept(q, &self.carrier.doc, "acc-1", &self.auth(), &self.store.sk, &self.store.did, self.t0 + Duration::minutes(4))
    }

    fn check(&self, acc: &Value, q: &Value) -> R<Accepted> {
        check_acceptance(acc, &self.store.doc, q, &self.root, &|_| false, self.t0 + Duration::minutes(5))
    }

    fn docs(&self) -> impl Fn(&str) -> Option<Verified> + '_ {
        move |d: &str| [&self.store, &self.carrier, &self.thief].into_iter().find(|p| p.did == d).map(|p| p.doc.clone())
    }
}

/// An acceptance built by hand and signed by `who`, skipping the buyer-side check in [`accept`]: what a buggy or
/// subverted agent could send.
fn forged_acceptance(w: &World, who: &Party, q: &Value, amount_minor: u64, token: &str) -> Value {
    let mut m = header(Kind::Acceptance, "acc-x", &who.did, &w.carrier.did, w.t0 + Duration::minutes(4));
    copy_terms(&mut m, q);
    m["quote"] = json!(digest(q).unwrap());
    m["amountMinor"] = json!(amount_minor);
    m["node"] = json!("store-0412");
    m["token"] = json!(token);
    sign(m, &who.sk, &who.did, w.t0 + Duration::minutes(4)).unwrap()
}

#[test]
fn a_deal_within_the_cap_goes_through_and_audits() {
    let w = world();
    let req = w.request("transport");
    let q = w.quote(&req, 540_000);
    let acc = w.accept(&q).unwrap();
    let ok = w.check(&acc, &q).unwrap();
    assert_eq!(ok.amount_minor, 540_000);
    assert_eq!(ok.buyer, w.store.did);
    assert_eq!((ok.currency.as_str(), ok.category.as_str(), ok.on_behalf_of.as_str()), ("EUR", "transport", "store-0412"));
    let conf = confirm(&acc, &q, "conf-1", "CB-20261123-0042", &w.carrier.sk, &w.carrier.did, w.t0 + Duration::minutes(5)).unwrap();
    assert!(read_answer(&conf, &w.carrier.doc, &acc).unwrap());

    let rec = Record { request: req, quote: q, acceptance: acc, confirmation: conf };
    let again = Record::from_json(&rec.to_json()).unwrap();
    assert_eq!(audit(&again, &w.docs(), &w.root).unwrap(), ok);
}

#[test]
fn a_record_still_audits_after_the_token_expired() {
    // the whole deal happened ten hours ago; the 8-hour token is long dead
    let w = world_at(Utc::now() - Duration::hours(10));
    let req = w.request("transport");
    let q = w.quote(&req, 100_000);
    let acc = w.accept(&q).unwrap();
    w.check(&acc, &q).unwrap();
    let conf = confirm(&acc, &q, "conf-1", "ref", &w.carrier.sk, &w.carrier.did, w.t0 + Duration::minutes(5)).unwrap();
    let rec = Record { request: req, quote: q.clone(), acceptance: acc.clone(), confirmation: conf };
    audit(&rec, &w.docs(), &w.root).unwrap();
    // but it would not be accepted today
    assert!(matches!(check_acceptance(&acc, &w.store.doc, &q, &w.root, &|_| false, Utc::now()), Err(QuoteError::Expired(_)) | Err(QuoteError::Unauthorized(_))));
}

#[test]
fn over_the_cap_the_buyer_will_not_sign_and_the_seller_would_refuse() {
    let w = world();
    let req = w.request("transport");
    let q = w.quote(&req, 720_000);
    // the buyer's own check stops it: the cue to ask the duty manager
    assert!(matches!(w.accept(&q), Err(QuoteError::Unauthorized(_))));
    // an agent that skips that check is stopped by the carrier anyway
    let acc = forged_acceptance(&w, &w.store, &q, 720_000, &w.token);
    assert!(matches!(w.check(&acc, &q), Err(QuoteError::Unauthorized(_))));
    let no = reject(&acc, "rej-1", "above the buyer's spending limit", &w.carrier.sk, &w.carrier.did, w.t0 + Duration::minutes(5)).unwrap();
    assert!(!read_answer(&no, &w.carrier.doc, &acc).unwrap());
    // the manager approves: the authority issues a new token with a higher cap, and the same quote now goes through
    let bigger = token_for(&w.authority, &w.store, 800_000, w.t0);
    let auth = Authority { node: "store-0412", token: &bigger, root: &w.root };
    let acc = accept(&q, &w.carrier.doc, "acc-2", &auth, &w.store.sk, &w.store.did, w.t0 + Duration::minutes(6)).unwrap();
    assert_eq!(w.check(&acc, &q).unwrap().amount_minor, 720_000);
}

#[test]
fn a_narrowed_token_cannot_be_used_above_its_narrower_cap() {
    let w = world();
    let low = anp_authz::attenuate(&w.token, &w.root, &anp_authz::Attenuation { spend_cap_minor: Some(150_000), ..Default::default() }).unwrap();
    let q = w.quote(&w.request("transport"), 200_000);
    let auth = Authority { node: "store-0412", token: &low, root: &w.root };
    assert!(matches!(accept(&q, &w.carrier.doc, "a", &auth, &w.store.sk, &w.store.did, w.t0), Err(QuoteError::Unauthorized(_))));
    assert!(matches!(w.check(&forged_acceptance(&w, &w.store, &q, 200_000, &low), &q), Err(QuoteError::Unauthorized(_))));
}

#[test]
fn the_token_must_allow_the_category() {
    let w = world();
    let q = w.quote(&w.request("catering"), 1_000);
    assert!(matches!(w.accept(&q), Err(QuoteError::Unauthorized(_))));
}

#[test]
fn a_stolen_token_is_useless_to_another_agent() {
    let w = world();
    let req = w.request("transport");
    let q = w.quote(&req, 100_000);
    // mallory signs an acceptance with her own DID and key but the store's token
    let mut stolen = forged_acceptance(&w, &w.thief, &q, 100_000, &w.token);
    assert!(check_acceptance(&stolen, &w.thief.doc, &q, &w.root, &|_| false, w.t0).is_err());
    // nor can she claim to be the store: the signature is checked against the store's document
    stolen["from"] = json!(w.store.did);
    assert!(matches!(w.check(&stolen, &q), Err(QuoteError::Signature(_))));
    // a token from an authority the carrier does not trust
    let other = anp_authz::Authority::generate();
    let foreign = token_for(&other, &w.store, 600_000, w.t0);
    assert!(matches!(w.check(&forged_acceptance(&w, &w.store, &q, 100_000, &foreign), &q), Err(QuoteError::Unauthorized(_))));
}

#[test]
fn a_revoked_token_is_refused() {
    let w = world();
    let q = w.quote(&w.request("transport"), 100_000);
    let acc = w.accept(&q).unwrap();
    let rev = w.authority.revoke(&w.token, "tablet lost").unwrap();
    let r = check_acceptance(&acc, &w.store.doc, &q, &w.root, &|id| id == rev.revoked, w.t0);
    assert!(matches!(r, Err(QuoteError::Revoked(_))));
}

#[test]
fn an_acceptance_must_answer_exactly_this_quote() {
    let w = world();
    let req = w.request("transport");
    let q = w.quote(&req, 300_000);
    // a different amount than quoted (signed properly, within the cap)
    assert!(matches!(w.check(&forged_acceptance(&w, &w.store, &q, 250_000, &w.token), &q), Err(QuoteError::Mismatch(_))));
    // an acceptance of another quote
    let other = w.quote(&req, 310_000);
    let acc = w.accept(&other).unwrap();
    assert!(matches!(w.check(&acc, &q), Err(QuoteError::Mismatch(_))));
    // a confirmation of another acceptance is not an answer to this one
    let acc_q = w.accept(&q).unwrap();
    let conf_other = confirm(&acc, &other, "c", "r", &w.carrier.sk, &w.carrier.did, w.t0).unwrap();
    assert!(matches!(read_answer(&conf_other, &w.carrier.doc, &acc_q), Err(QuoteError::Mismatch(_))));
}

#[test]
fn an_expired_quote_cannot_be_accepted() {
    let w = world();
    let q = w.quote(&w.request("transport"), 100_000);
    let late = w.t0 + Duration::minutes(31);
    assert!(matches!(accept(&q, &w.carrier.doc, "a", &w.auth(), &w.store.sk, &w.store.did, late), Err(QuoteError::Expired(_))));
    let acc = w.accept(&q).unwrap();
    assert!(matches!(check_acceptance(&acc, &w.store.doc, &q, &w.root, &|_| false, late), Err(QuoteError::Expired(_))));
}

#[test]
fn any_change_to_a_signed_message_breaks_it() {
    let w = world();
    let q = w.quote(&w.request("transport"), 100_000);
    let acc = w.accept(&q).unwrap();
    let mut cheaper = q.clone();
    cheaper["amountMinor"] = json!(1);
    assert!(matches!(verify(&cheaper, &w.carrier.doc), Err(QuoteError::Signature(_))));
    let mut more = acc.clone();
    more["amountMinor"] = json!(100_001);
    assert!(matches!(w.check(&more, &q), Err(QuoteError::Signature(_))));
    let mut unsigned = acc.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    assert!(matches!(verify(&unsigned, &w.store.doc), Err(QuoteError::Signature(_))));
    // the right signature, the wrong document
    assert!(matches!(verify(&acc, &w.carrier.doc), Err(QuoteError::Signature(_))));
    // a quote addressed to someone else
    let req_thief = request(
        &RequestSpec { id: "r", to: &w.carrier.did, category: "transport", on_behalf_of: "store-0412", currency: "EUR", need: json!({}), respond_by: w.t0 },
        &w.thief.sk,
        &w.thief.did,
        w.t0,
    )
    .unwrap();
    let qt = quote(&req_thief, &w.thief.doc, &Offer { id: "q", amount_minor: 1, valid_until: w.t0 + Duration::hours(1), terms: json!({}) }, &w.carrier.sk, &w.carrier.did, w.t0).unwrap();
    assert!(matches!(w.accept(&qt), Err(QuoteError::Mismatch(_))));
}

#[test]
fn an_audit_catches_a_swapped_or_edited_record() {
    let w = world();
    let req = w.request("transport");
    let q = w.quote(&req, 100_000);
    let acc = w.accept(&q).unwrap();
    let conf = confirm(&acc, &q, "c", "r", &w.carrier.sk, &w.carrier.did, w.t0 + Duration::minutes(5)).unwrap();
    let good = Record { request: req.clone(), quote: q.clone(), acceptance: acc.clone(), confirmation: conf.clone() };
    audit(&good, &w.docs(), &w.root).unwrap();

    // a quote for another request
    let other_req = request(
        &RequestSpec { id: "req-2", to: &w.carrier.did, category: "transport", on_behalf_of: "store-0412", currency: "EUR", need: json!({ "pallets": 1 }), respond_by: w.t0 },
        &w.store.sk,
        &w.store.did,
        w.t0,
    )
    .unwrap();
    assert!(audit(&Record { request: other_req, ..good.clone() }, &w.docs(), &w.root).is_err());
    // a confirmation made before the acceptance
    let early = confirm(&acc, &q, "c", "r", &w.carrier.sk, &w.carrier.did, w.t0).unwrap();
    assert!(matches!(audit(&Record { confirmation: early, ..good.clone() }, &w.docs(), &w.root), Err(QuoteError::Mismatch(_))));
    // a confirmation signed by the buyer, not the seller
    let mut by_store = header(Kind::Confirmation, "c", &w.store.did, &w.store.did, w.t0 + Duration::minutes(6));
    by_store["acceptance"] = json!(digest(&acc).unwrap());
    by_store["quote"] = json!(digest(&q).unwrap());
    by_store["reference"] = json!("r");
    let by_store = sign(by_store, &w.store.sk, &w.store.did, w.t0).unwrap();
    assert!(audit(&Record { confirmation: by_store, ..good.clone() }, &w.docs(), &w.root).is_err());
    // an unknown signer
    assert!(audit(&good, &|_| None, &w.root).is_err());
}

#[test]
fn malformed_messages_are_refused() {
    let w = world();
    let req = w.request("transport");
    for (k, v) in [
        ("protocol", json!("anp.quote.v0")),
        ("type", json!("Invoice")),
        ("id", json!("has space")),
        ("from", json!("did:web:example.com")),
        ("created", json!("yesterday")),
        ("currency", json!("eur")),
        ("category", json!("x\"); allow if true; //")),
        ("need", json!("three pallets")),
    ] {
        let mut m = req.clone();
        m[k] = v;
        assert!(matches!(check_shape(&m), Err(QuoteError::Malformed(_))), "{k}");
    }
    let q = w.quote(&req, 1);
    let mut m = q.clone();
    m["request"] = json!("sha256:XYZ");
    assert!(check_shape(&m).is_err());
    m = q.clone();
    m["amountMinor"] = json!(-5);
    assert!(check_shape(&m).is_err());
    m["amountMinor"] = json!(MAX_AMOUNT_MINOR + 1);
    assert!(check_shape(&m).is_err());
    assert!(check_shape(&json!([1, 2])).is_err());
    // a key that is not the DID's own cannot sign for it
    assert!(matches!(sign(req.clone(), &w.thief.sk, &w.store.did, w.t0), Err(QuoteError::Signature(_))));
}

#[test]
fn the_ledger_keeps_the_total_under_the_budget() {
    let mut l = Ledger::new("EUR", 1_000_000);
    l.reserve("a1", "did:wba:carrier-b.test:x", "transport", "EUR", 600_000).unwrap();
    // two acceptances in flight cannot together exceed the budget
    assert_eq!(l.reserve("a2", "did:wba:cold-1.test:x", "storage", "EUR", 500_000), Err(QuoteError::OverBudget { needed: 500_000, remaining: 400_000 }));
    l.reserve("a2", "did:wba:cold-1.test:x", "storage", "EUR", 400_000).unwrap();
    assert_eq!(l.remaining(), 0);
    l.commit("a1").unwrap();
    l.release("a2").unwrap(); // the warehouse said no
    assert_eq!((l.committed(), l.outstanding(), l.remaining()), (600_000, 600_000, 400_000));
    assert!(l.commit("a2").is_err(), "already released");
    assert!(l.release("nope").is_err());
    assert!(l.reserve("a1", "x", "transport", "EUR", 1).is_err(), "id reused");
    assert!(l.reserve("a3", "x", "transport", "USD", 1).is_err(), "currency");
    // the manager raises the budget
    l.set_budget(1_400_000);
    l.reserve("a3", "did:wba:cold-2.test:x", "storage", "EUR", 800_000).unwrap();
    assert_eq!(Ledger::from_json(&l.to_json()).unwrap(), l);
    assert!(Ledger::from_json(&json!({ "currency": "EUR" })).is_err());
}
