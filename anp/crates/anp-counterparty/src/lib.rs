//! Rule-based counterparties for the cold-stock rescue scenario.
//!
//! Each company the store's agent may deal with has a [`Profile`]: what it sells (the categories of a quote request it answers), how
//! it prices, whether it is available tonight, how much room it has. [`Desk::decide`] turns a quote request into an offer or a
//! refusal; [`Desk::confirmed`] takes the room an accepted offer uses. Nothing here signs or checks anything: that is the protocol's
//! job (`anp-quote`), done by the node around it. These are a demonstration's companies and prices, all fictional.
//!
//! | profile | role | tonight |
//! |---|---|---|
//! | `frostline` | carrier | available, expensive: €4,000 + €1,800 a pallet (3 pallets: €9,400) |
//! | `polar` | carrier | no truck before 06:00 |
//! | `coldchain` | carrier | available: €1,500 + €1,300 a pallet (3 pallets: €5,400) |
//! | `rungis-cold` | warehouse | room for 2 pallets only, €900 a pallet |
//! | `orly-freeze` | warehouse | room for 10, €1,500 a pallet |
//! | `foodbank` | food bank | takes up to 2 pallets of chilled food, free, collected by 04:00 |
//! | `insurer` | insurer | says whether a rescue plan is covered and what evidence it wants |
//! | `supplier` | wholesaler | rush restock for the morning, €600 a pallet |

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    /// `carrier`, `warehouse`, `foodbank`, `insurer`, `supplier`.
    pub role: String,
    /// The categories of request it answers (a quote's category is checked against the buyer's token at acceptance).
    pub categories: Vec<String>,
    pub currency: String,
    /// A fixed part and a part per pallet, in cents.
    pub base_minor: u64,
    pub per_pallet_minor: u64,
    /// How many pallets it can take in all (`None`: no limit).
    pub capacity_pallets: Option<u32>,
    /// Why it cannot serve tonight, if it cannot.
    pub unavailable: Option<String>,
    /// How long its offers stand, in minutes.
    pub valid_minutes: u32,
    /// What it adds to every offer (arrival times, conditions).
    pub terms: Value,
}

impl Profile {
    fn new(id: &str, name: &str, role: &str, categories: &[&str]) -> Profile {
        Profile {
            id: id.into(),
            name: name.into(),
            role: role.into(),
            categories: categories.iter().map(|s| s.to_string()).collect(),
            currency: "EUR".into(),
            base_minor: 0,
            per_pallet_minor: 0,
            capacity_pallets: None,
            unavailable: None,
            valid_minutes: 30,
            terms: json!({}),
        }
    }

    /// A built-in profile by id (see the table in the crate's documentation).
    pub fn builtin(id: &str) -> Option<Profile> {
        let euros = |e: u64| e * 100;
        Some(match id {
            "frostline" => Profile { base_minor: euros(4_000), per_pallet_minor: euros(1_800), terms: json!({ "arrivesIn": "35 min", "vehicle": "reefer -25 °C" }), ..Profile::new(id, "FrostLine Logistics", "carrier", &["transport"]) },
            "polar" => Profile { unavailable: Some("no refrigerated truck free before 06:00".into()), ..Profile::new(id, "Polar Express", "carrier", &["transport"]) },
            "coldchain" => Profile { base_minor: euros(1_500), per_pallet_minor: euros(1_300), terms: json!({ "arrivesIn": "45 min", "vehicle": "reefer -25 °C" }), ..Profile::new(id, "ColdChain Rungis", "carrier", &["transport"]) },
            "rungis-cold" => Profile { per_pallet_minor: euros(900), capacity_pallets: Some(2), terms: json!({ "storage": "-24 °C", "for": "72 h" }), ..Profile::new(id, "Rungis Cold Store", "warehouse", &["storage"]) },
            "orly-freeze" => Profile { per_pallet_minor: euros(1_500), capacity_pallets: Some(10), terms: json!({ "storage": "-22 °C", "for": "72 h" }), ..Profile::new(id, "Orly Freeze", "warehouse", &["storage"]) },
            "foodbank" => Profile { capacity_pallets: Some(2), valid_minutes: 60, terms: json!({ "accepts": "chilled food within its use-by date", "collectBy": "04:00" }), ..Profile::new(id, "Banque Alimentaire 94", "foodbank", &["donation"]) },
            "insurer" => Profile { valid_minutes: 240, terms: json!({ "covered": true, "deductibleMinor": euros(500), "evidence": ["the signed temperature log", "every signed acceptance and confirmation", "the disposal record of lost stock"] }), ..Profile::new(id, "Mutuelle du Commerce", "insurer", &["coverage"]) },
            "supplier" => Profile { per_pallet_minor: euros(600), terms: json!({ "deliveryBy": "07:00" }), ..Profile::new(id, "Grossiste Frais IDF", "supplier", &["restock"]) },
            _ => return None,
        })
    }

    pub const BUILTIN: [&'static str; 8] = ["frostline", "polar", "coldchain", "rungis-cold", "orly-freeze", "foodbank", "insurer", "supplier"];

    pub fn to_json(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "role": self.role, "categories": self.categories, "currency": self.currency,
                "baseMinor": self.base_minor, "perPalletMinor": self.per_pallet_minor, "capacityPallets": self.capacity_pallets,
                "unavailable": self.unavailable, "validMinutes": self.valid_minutes, "terms": self.terms })
    }
}

/// What a desk answers to a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// An offer: the price, how long it stands, and the terms (always with `pallets`, the number it is for).
    Offer { amount_minor: u64, valid_minutes: u32, terms: Value },
    Refuse(String),
}

/// A counterparty at work: its profile and the room it has already given away.
#[derive(Debug, Clone, PartialEq)]
pub struct Desk {
    pub profile: Profile,
    pub used_pallets: u32,
}

impl Desk {
    pub fn new(profile: Profile) -> Desk {
        Desk { profile, used_pallets: 0 }
    }

    pub fn free_pallets(&self) -> Option<u32> {
        self.profile.capacity_pallets.map(|c| c.saturating_sub(self.used_pallets))
    }

    /// Decide on a quote request (the `anp-quote` message: its `category`, `currency` and `need.pallets`). A desk that has less room
    /// than asked offers what it has, and says so (`partial`).
    pub fn decide(&self, request: &Value) -> Decision {
        let p = &self.profile;
        let category = request["category"].as_str().unwrap_or("");
        if !p.categories.iter().any(|c| c == category) {
            return Decision::Refuse(format!("{} does not do {category}", p.name));
        }
        if request["currency"].as_str() != Some(p.currency.as_str()) {
            return Decision::Refuse(format!("{} quotes in {}", p.name, p.currency));
        }
        if let Some(why) = &p.unavailable {
            return Decision::Refuse(why.clone());
        }
        let asked = request["need"]["pallets"].as_u64().unwrap_or(1).clamp(1, 1_000) as u32;
        let pallets = match self.free_pallets() {
            Some(0) => return Decision::Refuse(format!("{} is full", p.name)),
            Some(free) => asked.min(free),
            None => asked,
        };
        let mut terms = p.terms.clone();
        terms["pallets"] = json!(pallets);
        if pallets < asked {
            terms["partial"] = json!(true);
            terms["note"] = json!(format!("room for {pallets} of the {asked} pallets asked"));
        }
        let amount_minor = if p.per_pallet_minor == 0 && p.base_minor == 0 { 0 } else { p.base_minor + p.per_pallet_minor * pallets as u64 };
        Decision::Offer { amount_minor, valid_minutes: p.valid_minutes, terms }
    }

    /// An offer for `pallets` was accepted and confirmed: that room is taken. Refused when it is no longer there.
    pub fn confirmed(&mut self, pallets: u32) -> Result<(), String> {
        if let Some(free) = self.free_pallets() {
            if pallets > free {
                return Err(format!("only {free} pallets of room left"));
            }
        }
        self.used_pallets += pallets;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(category: &str, pallets: u64) -> Value {
        json!({ "category": category, "currency": "EUR", "need": { "pallets": pallets } })
    }

    fn offer(d: &Desk, r: &Value) -> (u64, Value) {
        match d.decide(r) {
            Decision::Offer { amount_minor, terms, .. } => (amount_minor, terms),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_three_carriers_of_the_scenario() {
        let r = req("transport", 3);
        assert_eq!(offer(&Desk::new(Profile::builtin("frostline").unwrap()), &r).0, 940_000, "too expensive");
        assert_eq!(offer(&Desk::new(Profile::builtin("coldchain").unwrap()), &r).0, 540_000, "the right one");
        assert!(matches!(Desk::new(Profile::builtin("polar").unwrap()).decide(&r), Decision::Refuse(w) if w.contains("06:00")));
    }

    #[test]
    fn a_warehouse_short_of_room_offers_what_it_has_and_fills_up() {
        let mut w = Desk::new(Profile::builtin("rungis-cold").unwrap());
        let (amount, terms) = offer(&w, &req("storage", 3));
        assert_eq!(amount, 180_000);
        assert_eq!(terms["pallets"], 2);
        assert_eq!(terms["partial"], true);
        w.confirmed(2).unwrap();
        assert!(matches!(w.decide(&req("storage", 1)), Decision::Refuse(w) if w.contains("full")));
        assert!(w.confirmed(1).is_err());
        let orly = Desk::new(Profile::builtin("orly-freeze").unwrap());
        assert_eq!(offer(&orly, &req("storage", 3)), (450_000, json!({ "storage": "-22 °C", "for": "72 h", "pallets": 3 })));
    }

    #[test]
    fn the_best_plan_of_the_scenario_costs_7200_euros() {
        let carrier = offer(&Desk::new(Profile::builtin("coldchain").unwrap()), &req("transport", 3)).0;
        let storage = offer(&Desk::new(Profile::builtin("rungis-cold").unwrap()), &req("storage", 3)).0;
        assert_eq!(carrier + storage, 720_000);
    }

    #[test]
    fn free_services_and_the_wrong_counter() {
        let (amount, terms) = offer(&Desk::new(Profile::builtin("foodbank").unwrap()), &req("donation", 1));
        assert_eq!(amount, 0);
        assert_eq!(terms["collectBy"], "04:00");
        let (amount, terms) = offer(&Desk::new(Profile::builtin("insurer").unwrap()), &req("coverage", 3));
        assert_eq!((amount, terms["covered"].clone()), (0, json!(true)));
        assert!(matches!(Desk::new(Profile::builtin("coldchain").unwrap()).decide(&req("storage", 1)), Decision::Refuse(_)), "a carrier does not store");
        let mut usd = req("transport", 1);
        usd["currency"] = json!("USD");
        assert!(matches!(Desk::new(Profile::builtin("coldchain").unwrap()).decide(&usd), Decision::Refuse(_)));
        assert!(Profile::BUILTIN.iter().all(|id| Profile::builtin(id).is_some()));
        assert!(Profile::builtin("acme").is_none());
    }
}
