//! A simulated supermarket cold room, for the cold-stock rescue scenario.
//!
//! * **Units** (freezers and chillers) follow Newton's law of cooling towards a target: their setpoint while the controller
//!   works, or what a fault drives them to. Two faults: [`Fault::DefrostStuck`], the controller left in defrost with the heaters on
//!   (what the October 2026 attacks did: units reached about 50 °C in six hours), and [`Fault::CompressorOff`], which lets a unit
//!   warm towards the room.
//! * **Products** sit in a unit, with a value and a food-safety [`Rule`]: a limit it may exceed only for so many minutes in all,
//!   and a hard limit past which it is unsafe at once.
//! * The clock is the simulation's own ([`Store::advance`], in whole minutes), so a scenario runs the same at any speed and in tests.
//! * [`Store::assess`] says, product by product, whether it is still safe, and for how long under the current trend (by running
//!   the model forward), and ranks what is at stake.
//!
//! The rules are a demonstration's, chosen to be plausible (frozen food kept at -18 °C, chilled food at 4 to 6 °C), not regulatory
//! advice. The scenario's store is fictional.

use serde_json::{json, Value};

/// How many minutes the model looks ahead when it says how long a product stays safe.
pub const HORIZON_MIN: u32 = 24 * 60;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fault {
    /// The controller is stuck in defrost: heaters on, compressor off. The unit heads for about 50 °C.
    DefrostStuck,
    /// The compressor is off: the unit warms towards the room.
    CompressorOff,
}

impl Fault {
    pub fn name(self) -> &'static str {
        match self {
            Fault::DefrostStuck => "defrost-stuck",
            Fault::CompressorOff => "compressor-off",
        }
    }
    pub fn parse(s: &str) -> Option<Fault> {
        match s {
            "defrost-stuck" => Some(Fault::DefrostStuck),
            "compressor-off" => Some(Fault::CompressorOff),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub id: String,
    pub name: String,
    /// `freezer` or `chiller`.
    pub kind: String,
    pub setpoint_c: f64,
    pub temp_c: f64,
    pub fault: Option<Fault>,
}

/// The room around the units.
pub const AMBIENT_C: f64 = 20.0;
/// Where a unit stuck in defrost ends up.
pub const DEFROST_C: f64 = 50.0;

impl Unit {
    /// The temperature the unit is heading for, and how fast (the time constant, in minutes).
    fn target(&self) -> (f64, f64) {
        match self.fault {
            None => (self.setpoint_c, 20.0),
            // from -20 °C, about 45 °C after six hours
            Some(Fault::DefrostStuck) => (DEFROST_C, 136.0),
            // an insulated box with the door shut warms slowly
            Some(Fault::CompressorOff) => (AMBIENT_C, if self.kind == "freezer" { 480.0 } else { 300.0 }),
        }
    }

    /// One minute of the model.
    fn step(&mut self) {
        let (target, tau) = self.target();
        self.temp_c = target + (self.temp_c - target) * (-1.0 / tau).exp();
    }
}

/// A food-safety rule: above `limit_c` for more than `allowance_min` minutes in all, or above `hard_limit_c` at all, and the
/// product must be thrown away.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rule {
    pub limit_c: f64,
    pub allowance_min: u32,
    pub hard_limit_c: f64,
}

impl Rule {
    /// Frozen food stored at -18 °C: it may go above -12 °C for an hour; thawed (above 0 °C) it is lost.
    pub const FROZEN: Rule = Rule { limit_c: -12.0, allowance_min: 60, hard_limit_c: 0.0 };
    /// Fresh meat and fish: above 4 °C for an hour at most, never above 8 °C.
    pub const CHILLED_MEAT: Rule = Rule { limit_c: 4.0, allowance_min: 60, hard_limit_c: 8.0 };
    /// Dairy: above 6 °C for two hours at most, never above 10 °C.
    pub const DAIRY: Rule = Rule { limit_c: 6.0, allowance_min: 120, hard_limit_c: 10.0 };

    pub fn by_name(s: &str) -> Option<Rule> {
        match s {
            "frozen" => Some(Rule::FROZEN),
            "chilled-meat" => Some(Rule::CHILLED_MEAT),
            "dairy" => Some(Rule::DAIRY),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Product {
    pub sku: String,
    pub name: String,
    pub unit: String,
    /// The rule's name: `frozen`, `chilled-meat` or `dairy`.
    pub rule_name: String,
    pub rule: Rule,
    pub pallets: u32,
    /// What it is worth, in cents.
    pub value_minor: u64,
    /// Minutes spent above the rule's limit so far.
    pub exposure_min: u32,
    /// Thrown away: past its hard limit, or past its allowance.
    pub lost: bool,
}

/// Where a product stands.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Within its rule, and the unit is not heading past it within the horizon.
    Safe,
    /// Still safe, but under the current trend it will not be in `minutes_left` minutes.
    AtRisk { minutes_left: u32 },
    /// Past its rule: it must be thrown away.
    Unsafe { reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub sku: String,
    pub name: String,
    pub unit: String,
    pub pallets: u32,
    pub value_minor: u64,
    pub temp_c: f64,
    pub exposure_min: u32,
    pub status: Status,
}

impl Assessment {
    pub fn to_json(&self) -> Value {
        let (status, minutes_left, reason) = match &self.status {
            Status::Safe => ("safe", Value::Null, Value::Null),
            Status::AtRisk { minutes_left } => ("at-risk", json!(minutes_left), Value::Null),
            Status::Unsafe { reason } => ("unsafe", Value::Null, json!(reason)),
        };
        json!({ "sku": self.sku, "name": self.name, "unit": self.unit, "pallets": self.pallets, "valueMinor": self.value_minor,
                "tempC": round1(self.temp_c), "exposureMin": self.exposure_min, "status": status, "minutesLeft": minutes_left, "reason": reason })
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Apply one minute at `temp` to a product's record; returns whether it is (now) lost and why.
fn expose(p: &mut Product, temp: f64) -> Option<String> {
    if p.lost {
        return None;
    }
    if temp > p.rule.limit_c {
        p.exposure_min += 1;
    }
    let why = if temp > p.rule.hard_limit_c {
        Some(format!("reached {:.1} °C, above its hard limit of {} °C", temp, p.rule.hard_limit_c))
    } else if p.exposure_min > p.rule.allowance_min {
        Some(format!("more than {} minutes above {} °C", p.rule.allowance_min, p.rule.limit_c))
    } else {
        None
    };
    if why.is_some() {
        p.lost = true;
    }
    why
}

#[derive(Debug, Clone, PartialEq)]
pub struct Store {
    pub site: String,
    /// Minutes since the scenario started.
    pub minute: u32,
    /// The wall-clock time of minute 0, `HH:MM` (for display).
    pub start_clock: String,
    pub units: Vec<Unit>,
    pub products: Vec<Product>,
    /// Why each lost product was lost, by SKU.
    pub losses: Vec<(String, String)>,
}

impl Store {
    /// Store 0412 at 01:50, twenty minutes before its controllers fail: two freezers, two chillers, about €40,000 of stock.
    pub fn scenario_0412() -> Store {
        let unit = |id: &str, name: &str, kind: &str, sp: f64| Unit { id: id.into(), name: name.into(), kind: kind.into(), setpoint_c: sp, temp_c: sp, fault: None };
        let product = |sku: &str, name: &str, unit: &str, rule: &str, pallets: u32, euros: u64| Product {
            sku: sku.into(),
            name: name.into(),
            unit: unit.into(),
            rule_name: rule.into(),
            rule: Rule::by_name(rule).expect("a known rule"),
            pallets,
            value_minor: euros * 100,
            exposure_min: 0,
            lost: false,
        };
        Store {
            site: "store-0412".into(),
            minute: 0,
            start_clock: "01:50".into(),
            units: vec![
                unit("frz-1", "Freezer aisle 1 (ice cream, frozen vegetables)", "freezer", -20.0),
                unit("frz-2", "Freezer aisle 2 (frozen meat and fish)", "freezer", -20.0),
                unit("chl-1", "Dairy wall", "chiller", 3.0),
                unit("chl-2", "Butcher's counter cold room", "chiller", 2.0),
            ],
            products: vec![
                product("FZ-ICE", "Ice cream", "frz-1", "frozen", 2, 6_800),
                product("FZ-VEG", "Frozen vegetables", "frz-1", "frozen", 1, 2_400),
                product("FZ-MEAT", "Frozen meat", "frz-2", "frozen", 2, 11_500),
                product("FZ-FISH", "Frozen fish", "frz-2", "frozen", 1, 6_300),
                product("CH-MILK", "Milk and cream", "chl-1", "dairy", 1, 2_100),
                product("CH-YOG", "Yoghurt and desserts", "chl-1", "dairy", 1, 2_600),
                product("CH-CHEESE", "Cheese", "chl-1", "dairy", 1, 3_900),
                product("CH-MEAT", "Fresh meat", "chl-2", "chilled-meat", 1, 4_700),
            ],
            losses: vec![],
        }
    }

    /// The time of day at the current minute, `HH:MM`.
    pub fn clock(&self) -> String {
        let (h, m) = self.start_clock.split_once(':').and_then(|(h, m)| Some((h.parse::<u32>().ok()?, m.parse::<u32>().ok()?))).unwrap_or((0, 0));
        let t = (h * 60 + m + self.minute) % (24 * 60);
        format!("{:02}:{:02}", t / 60, t % 60)
    }

    pub fn unit(&self, id: &str) -> Option<&Unit> {
        self.units.iter().find(|u| u.id == id)
    }

    /// Put a unit in a fault (or back to normal with `None`).
    pub fn set_fault(&mut self, unit: &str, fault: Option<Fault>) -> Result<(), String> {
        let u = self.units.iter_mut().find(|u| u.id == unit).ok_or_else(|| format!("no unit {unit}"))?;
        u.fault = fault;
        Ok(())
    }

    /// Move the clock on by `minutes`, one minute at a time: units follow their model, products accumulate exposure and are lost
    /// when their rule says so.
    pub fn advance(&mut self, minutes: u32) {
        for _ in 0..minutes {
            self.minute += 1;
            for u in &mut self.units {
                u.step();
            }
            for p in &mut self.products {
                let t = self.units.iter().find(|u| u.id == p.unit).map_or(AMBIENT_C, |u| u.temp_c);
                if let Some(why) = expose(p, t) {
                    self.losses.push((p.sku.clone(), why));
                }
            }
        }
    }

    /// Every product: safe, at risk (and for how long it stays safe if nothing changes), or unsafe. Ordered by what is at stake:
    /// at-risk products first, soonest lost first and, at equal time, most valuable first; then safe ones; then the lost.
    pub fn assess(&self) -> Vec<Assessment> {
        let mut out: Vec<Assessment> = self
            .products
            .iter()
            .map(|p| {
                let unit = self.units.iter().find(|u| u.id == p.unit);
                let temp = unit.map_or(AMBIENT_C, |u| u.temp_c);
                let status = if p.lost {
                    let reason = self.losses.iter().find(|(s, _)| *s == p.sku).map(|(_, r)| r.clone()).unwrap_or_else(|| "lost".into());
                    Status::Unsafe { reason }
                } else {
                    // run this unit and a copy of the product forward to see when the rule would be broken
                    let (mut u, mut q) = (unit.cloned().unwrap_or(Unit { id: p.unit.clone(), name: String::new(), kind: String::new(), setpoint_c: AMBIENT_C, temp_c: AMBIENT_C, fault: None }), p.clone());
                    let mut left = None;
                    for m in 1..=HORIZON_MIN {
                        u.step();
                        if expose(&mut q, u.temp_c).is_some() {
                            left = Some(m - 1);
                            break;
                        }
                    }
                    match left {
                        Some(m) => Status::AtRisk { minutes_left: m },
                        None => Status::Safe,
                    }
                };
                Assessment { sku: p.sku.clone(), name: p.name.clone(), unit: p.unit.clone(), pallets: p.pallets, value_minor: p.value_minor, temp_c: temp, exposure_min: p.exposure_min, status }
            })
            .collect();
        let rank = |a: &Assessment| match a.status {
            Status::AtRisk { minutes_left } => (0, minutes_left),
            Status::Safe => (1, 0),
            Status::Unsafe { .. } => (2, 0),
        };
        out.sort_by(|a, b| rank(a).cmp(&rank(b)).then(b.value_minor.cmp(&a.value_minor)));
        out
    }

    /// The value of the stock still sellable, and of what is lost, in cents.
    pub fn value(&self) -> (u64, u64) {
        let lost: u64 = self.products.iter().filter(|p| p.lost).map(|p| p.value_minor).sum();
        let total: u64 = self.products.iter().map(|p| p.value_minor).sum();
        (total - lost, lost)
    }

    /// The whole state, as a page or an agent reads it.
    pub fn to_json(&self) -> Value {
        let (safe, lost) = self.value();
        json!({
            "site": self.site,
            "minute": self.minute,
            "clock": self.clock(),
            "units": self.units.iter().map(|u| json!({ "id": u.id, "name": u.name, "kind": u.kind, "setpointC": u.setpoint_c, "tempC": round1(u.temp_c), "fault": u.fault.map(Fault::name) })).collect::<Vec<_>>(),
            "assessment": self.assess().iter().map(Assessment::to_json).collect::<Vec<_>>(),
            "valueMinor": { "sellable": safe, "lost": lost },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_hold_their_setpoint_while_the_controller_works() {
        let mut s = Store::scenario_0412();
        s.advance(600);
        for u in &s.units {
            assert!((u.temp_c - u.setpoint_c).abs() < 0.01, "{} drifted to {}", u.id, u.temp_c);
        }
        assert!(s.assess().iter().all(|a| a.status == Status::Safe));
        assert_eq!(s.value(), (4_030_000, 0), "about €40,000 of stock, none lost");
    }

    #[test]
    fn a_freezer_stuck_in_defrost_reaches_about_45_degrees_in_six_hours() {
        let mut s = Store::scenario_0412();
        s.set_fault("frz-1", Some(Fault::DefrostStuck)).unwrap();
        s.advance(360);
        let t = s.unit("frz-1").unwrap().temp_c;
        assert!((43.0..47.0).contains(&t), "{t}");
        assert!(s.unit("frz-2").unwrap().temp_c < -19.9, "the other freezer is fine");
    }

    #[test]
    fn frozen_products_in_a_failing_freezer_go_at_risk_then_unsafe() {
        let mut s = Store::scenario_0412();
        s.set_fault("frz-2", Some(Fault::DefrostStuck)).unwrap();
        s.advance(1);
        let meat = s.assess().into_iter().find(|a| a.sku == "FZ-MEAT").unwrap();
        let Status::AtRisk { minutes_left } = meat.status else { panic!("{meat:?}") };
        // -20 to 0 °C (the hard limit) with tau = 136 min: about 46 minutes
        assert!((40..55).contains(&minutes_left), "{minutes_left}");
        assert_eq!(s.assess()[0].unit, "frz-2", "the failing freezer comes first");
        s.advance(minutes_left + 1);
        let meat = s.assess().into_iter().find(|a| a.sku == "FZ-MEAT").unwrap();
        assert!(matches!(meat.status, Status::Unsafe { .. }), "{meat:?}");
        assert!(s.value().1 >= 1_150_000, "its value is counted as lost");
        assert!(s.assess().iter().filter(|a| a.unit != "frz-2").all(|a| a.status == Status::Safe));
    }

    #[test]
    fn the_allowance_counts_minutes_above_the_limit_not_the_hard_limit() {
        // dairy above 6 °C for 2 hours: a slow warm-up that peaks below 10 °C still loses it once the allowance is used up
        let mut p = Product { sku: "x".into(), name: "x".into(), unit: "u".into(), rule_name: "dairy".into(), rule: Rule::DAIRY, pallets: 1, value_minor: 1, exposure_min: 0, lost: false };
        for _ in 0..120 {
            assert!(expose(&mut p, 7.0).is_none());
        }
        assert!(expose(&mut p, 7.0).unwrap().contains("120 minutes"));
        let mut q = Product { exposure_min: 0, lost: false, ..p.clone() };
        assert!(expose(&mut q, 10.5).unwrap().contains("hard limit"));
        assert!(expose(&mut q, 10.5).is_none(), "lost once");
    }

    #[test]
    fn a_compressor_failure_is_slower_and_a_fixed_unit_recovers() {
        let mut s = Store::scenario_0412();
        s.set_fault("chl-1", Some(Fault::CompressorOff)).unwrap();
        s.advance(30);
        let at_risk: Vec<_> = s.assess().into_iter().filter(|a| a.unit == "chl-1").collect();
        assert!(at_risk.iter().all(|a| matches!(a.status, Status::AtRisk { .. })), "{at_risk:?}");
        s.set_fault("chl-1", None).unwrap();
        s.advance(120);
        assert!(s.assess().iter().all(|a| a.status == Status::Safe), "back to its setpoint before anything was lost");
        assert_eq!(s.value().1, 0);
    }

    #[test]
    fn the_clock_and_the_json() {
        let mut s = Store::scenario_0412();
        assert_eq!(s.clock(), "01:50");
        s.advance(20);
        assert_eq!(s.clock(), "02:10");
        s.advance(24 * 60);
        assert_eq!(s.clock(), "02:10");
        s.set_fault("frz-1", Some(Fault::DefrostStuck)).unwrap();
        let v = s.to_json();
        assert_eq!(v["units"][0]["fault"], "defrost-stuck");
        assert_eq!(v["assessment"].as_array().unwrap().len(), 8);
        assert_eq!(Fault::parse("compressor-off"), Some(Fault::CompressorOff));
        assert!(s.set_fault("nope", None).is_err());
    }
}
