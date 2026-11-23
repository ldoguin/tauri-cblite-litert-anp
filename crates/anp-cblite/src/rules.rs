//! Three deterministic agents for the field-inspection demo. Review and filing are
//! rule-based in real life too, so neither needs a model:
//!
//! * [`WriterExecutor`]: a rule-based stand-in for the tablet's on-device model: turns a rough note into the four labelled lines.
//! * [`ReviewExecutor`]: checks an inspection report has the fields it must have and
//!   a valid risk level, and answers `REVIEW: APPROVED` or `REVIEW: NEEDS INFO`.
//! * [`ClaimsExecutor`]: files a report that review approved and returns a claim number
//!   (the same report always gets the same number); anything else is rejected.
//!
//! A report is plain text with labelled lines, which is what the tablet's LLM agent is
//! asked to write:
//!
//! ```text
//! Asset: Boiler 3, Plant Room B
//! Findings: Corrosion on the feed pipe, a small leak at the valve.
//! Risk: High
//! Action: Isolate the valve and replace the pipe within 7 days.
//! ```

use futures_util::future::BoxFuture;

use crate::executor::{ExecContext, ExecEvent, Executor};
use crate::protocol::{AgentSkill, Artifact, Part, TaskState};

const REQUIRED: [&str; 4] = ["Asset", "Findings", "Risk", "Action"];

/// The value of the line labelled `label` (case-insensitive), ignoring list bullets and
/// markdown emphasis that a model may add (`- **Risk:** High`).
pub fn field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim().trim_start_matches(|c: char| matches!(c, '-' | '*' | '#' | '>' | ' ' | '\t'));
        let l = l.replace("**", "");
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case(label) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// `low`, `medium` or `high`, if the report's risk line says so.
pub fn risk_level(text: &str) -> Option<&'static str> {
    let v = field(text, "Risk")?.to_lowercase();
    ["high", "medium", "low"].into_iter().find(|level| v.contains(level))
}

pub struct Review {
    pub approved: bool,
    pub missing: Vec<&'static str>,
    pub risk: Option<&'static str>,
    pub asset: Option<String>,
}

pub fn review(text: &str) -> Review {
    let mut missing: Vec<&'static str> = REQUIRED.into_iter().filter(|l| field(text, l).is_none()).collect();
    let risk = risk_level(text);
    if risk.is_none() && !missing.contains(&"Risk") {
        missing.push("Risk (must be low, medium or high)");
    }
    Review { approved: missing.is_empty(), missing, risk, asset: field(text, "Asset") }
}

fn review_text(r: &Review) -> String {
    if r.approved {
        let risk = r.risk.unwrap_or("?").to_uppercase();
        format!(
            "REVIEW: APPROVED\nAsset: {}\nRisk: {risk}\nEscalate: {}",
            r.asset.clone().unwrap_or_default(),
            if r.risk == Some("high") { "yes, within 24 hours" } else { "no" }
        )
    } else {
        format!("REVIEW: NEEDS INFO\nMissing: {}", r.missing.join(", "))
    }
}

/// A stable short id for a report (FNV-1a), so filing the same report twice gives the same number.
pub fn claim_number(text: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in text.trim().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("CLM-{:08X}", (h >> 32) as u32 ^ h as u32)
}

fn answer(ctx: &ExecContext, name: &str, text: String) {
    let _ = ctx.events.send(ExecEvent::Artifact {
        artifact: Artifact {
            artifact_id: format!("{name}-{}", ctx.task.id),
            name: Some(name.into()),
            description: None,
            parts: vec![Part::text(text)],
            metadata: None,
        },
        append: false,
    });
    ctx.status(TaskState::Completed, None);
}

// ── a rule-based stand-in for the on-device model ────────────────────────────────────────────────────────

const HIGH: [&str; 11] = ["leak", "corrod", "fail", "wet", "fire", "spark", "smoke", "gas", "flood", "collapse", "exposed wire"];
const MEDIUM: [&str; 8] = ["flicker", "worn", "loose", "crack", "damp", "rust", "noisy", "stiff"];
const ACTION_WORDS: [&str; 9] = ["needs", "need to", "replace", "fix", "order", "should", "must", "isolate", "repair"];

fn sentence_case(s: &str) -> String {
    let s = s.trim().trim_end_matches(|c: char| c == '.' || c == ',').trim();
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Turn a rough note into a report: the first sentence is the asset, a sentence that says what must be done is the action, the rest are the
/// findings, and the risk comes from words in the note (High before Medium before Low). Deterministic; this is what the tablet's model does in
/// the full demo, and it is only here so that the demo runs without a model file.
pub fn write_report(note: &str) -> String {
    let lower = note.to_lowercase();
    let risk = if HIGH.iter().any(|w| lower.contains(w)) {
        "High"
    } else if MEDIUM.iter().any(|w| lower.contains(w)) {
        "Medium"
    } else {
        "Low"
    };
    let mut sentences = note.split(|c| c == '.' || c == '\n').map(str::trim).filter(|s| !s.is_empty());
    let asset = sentences.next().map(sentence_case).unwrap_or_else(|| "Unspecified".into());
    let (mut findings, mut action) = (Vec::new(), None);
    for s in sentences {
        let l = s.to_lowercase();
        if action.is_none() && ACTION_WORDS.iter().any(|w| l.contains(w)) {
            action = Some(sentence_case(s));
        } else {
            findings.push(sentence_case(&s.replace(", nothing to do", "").replace("nothing to do", "")));
        }
    }
    findings.retain(|f| !f.is_empty());
    let findings = match (findings.is_empty(), sentence_case(note)) {
        (false, _) => findings.join(". "),
        (true, n) if !n.is_empty() => n,
        (true, _) => "No details given".to_string(),
    };
    let action = action.unwrap_or_else(|| match risk {
        "High" => "Isolate and repair within 7 days".into(),
        "Medium" => "Schedule a repair".into(),
        _ => "None".into(),
    });
    format!("Asset: {asset}\nFindings: {findings}\nRisk: {risk}\nAction: {action}")
}

pub struct WriterExecutor;

impl Executor for WriterExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            // the demo page shows its report form on a device whose skill id says "inspector"
            id: "field-inspector".into(),
            name: "Field inspector".into(),
            description: "Turns a rough field note into a report with an asset, findings, a risk level and an action (rule-based stand-in for an on-device model).".into(),
            tags: vec!["report".into(), "rules".into()],
            examples: vec!["Plant room B, boiler 3. Feed pipe is corroded and leaking. Needs sorting this week.".into()],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            answer(&ctx, "report", write_report(&text));
        })
    }
}
pub struct ReviewExecutor;

impl Executor for ReviewExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: "review-inspection".into(),
            name: "Review inspection".into(),
            description: "Checks a field inspection report has an asset, findings, a risk level and an action.".into(),
            tags: vec!["review".into(), "rules".into()],
            examples: vec!["Asset: Boiler 3\nFindings: leak\nRisk: High\nAction: replace valve".into()],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            answer(&ctx, "review", review_text(&review(&text)));
        })
    }
}

pub struct ClaimsExecutor;

impl Executor for ClaimsExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: "file-claim".into(),
            name: "File claim".into(),
            description: "Files an approved inspection report and returns a claim number.".into(),
            tags: vec!["claims".into(), "rules".into()],
            examples: vec!["REVIEW: APPROVED\nAsset: Boiler 3\nRisk: HIGH".into()],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            let out = if text.contains("REVIEW: APPROVED") {
                let asset = field(&text, "Asset").unwrap_or_default();
                let risk = field(&text, "Risk").unwrap_or_default();
                format!("CLAIM FILED: {}\nAsset: {asset}\nRisk: {risk}", claim_number(&text))
            } else {
                "NOT FILED: the report was not approved by review.".to_string()
            };
            answer(&ctx, "claim", out);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Asset: Boiler 3, Plant Room B\nFindings: Corrosion on the feed pipe.\nRisk: High\nAction: Replace the pipe in 7 days.";

    #[test]
    fn fields_are_found_through_bullets_and_markdown() {
        let t = "- **Asset:** Pump 7\n* Findings : worn seal\n## Risk: Medium - monitor\n> Action: order a seal";
        assert_eq!(field(t, "asset").as_deref(), Some("Pump 7"));
        assert_eq!(field(t, "FINDINGS").as_deref(), Some("worn seal"));
        assert_eq!(risk_level(t), Some("medium"));
        assert_eq!(field(t, "action").as_deref(), Some("order a seal"));
        assert_eq!(field(t, "owner"), None);
        assert_eq!(field("Risk:   \nAsset: x", "Risk"), None, "an empty value is not a value");
    }

    #[test]
    fn a_complete_report_is_approved_and_high_risk_escalates() {
        let r = review(GOOD);
        assert!(r.approved && r.missing.is_empty());
        let t = review_text(&r);
        assert!(t.starts_with("REVIEW: APPROVED"));
        assert!(t.contains("Risk: HIGH") && t.contains("Escalate: yes"));
        assert!(review_text(&review(&GOOD.replace("High", "Low"))).contains("Escalate: no"));
    }

    #[test]
    fn an_incomplete_report_says_what_is_missing() {
        let r = review("Asset: Boiler 3\nFindings: leak");
        assert!(!r.approved);
        assert_eq!(r.missing, vec!["Risk", "Action"]);
        assert!(review_text(&r).contains("NEEDS INFO") && review_text(&r).contains("Missing: Risk, Action"));
        // a risk line with no recognisable level is not good enough
        let r = review("Asset: a\nFindings: b\nRisk: unclear\nAction: d");
        assert!(!r.approved && r.missing[0].starts_with("Risk"));
    }

    #[test]
    fn claim_numbers_are_stable_and_distinct() {
        assert_eq!(claim_number(GOOD), claim_number(&format!("  {GOOD}\n")));
        assert_ne!(claim_number(GOOD), claim_number(&GOOD.replace("Boiler 3", "Boiler 4")));
        assert!(claim_number(GOOD).starts_with("CLM-") && claim_number(GOOD).len() == 12);
    }
    #[test]
    fn the_writer_turns_rough_notes_into_reports_the_review_accepts() {
        let boiler = write_report("Plant room B, boiler 3. Feed pipe is corroded near the flange and there is a small leak at the isolation valve. Floor is wet. Needs sorting this week, it could fail.");
        assert_eq!(field(&boiler, "Asset").as_deref(), Some("Plant room B, boiler 3"));
        assert_eq!(risk_level(&boiler), Some("high"));
        assert!(field(&boiler, "Action").unwrap().starts_with("Needs sorting this week"), "{boiler}");
        assert!(field(&boiler, "Findings").unwrap().contains("corroded") && field(&boiler, "Findings").unwrap().contains("Floor is wet"));
        let vent = write_report("Warehouse roof vent 12. Seals look good, no water ingress, nothing to do.");
        assert_eq!(risk_level(&vent), Some("low"));
        assert_eq!(field(&vent, "Action").as_deref(), Some("None"));
        assert_eq!(field(&vent, "Findings").as_deref(), Some("Seals look good, no water ingress"));
        let light = write_report("Block C stairwell lights, one is flickering on the second floor. Everything else is fine.");
        assert_eq!(risk_level(&light), Some("medium"), "a flicker outweighs the word fine");
        for r in [&boiler, &vent, &light] {
            assert!(review(r).approved, "the review accepts it: {r}");
            assert_eq!(r.lines().count(), 4, "exactly four labelled lines: {r}");
        }
        // the same note always gives the same report
        assert_eq!(write_report("Pump 7. Worn seal."), write_report("Pump 7. Worn seal."));
        assert!(review(&write_report("")).approved, "even an empty note gets a well-formed report");
    }
}
