//! ANP-06 meta-protocol: before two agents exchange application data they can agree on **which protocol to speak**.
//!
//! Wire format (as in the official SDK): a stream of messages, each starting with one header byte whose top two bits say what
//! follows (`00` meta, `01` application, `10` natural language, `11` verification; the low six bits are reserved), then the
//! payload. A meta payload is a JSON object with an `action`:
//!
//! * `protocolNegotiation`: `sequenceId`, `candidateProtocols` (the protocol text), optional `modificationSummary`, `status`
//!   (`negotiating`, `accepted`, `rejected`). The requester proposes with `sequenceId` 1; each side answers with the next round,
//!   and every evaluation advances the round by two, so requesters use odd rounds and providers even ones.
//! * `codeGeneration` (`generated` or `error`): after agreement each side says whether it can now speak the protocol.
//! * `testCasesNegotiation`, `fixErrorNegotiation`, `naturalLanguageNegotiation`: read and written, not acted on here.
//!
//! The SDK negotiates with a language model that writes and judges protocol text and then generates code for it. This crate has
//! **no model**: an agent offers a *catalog* of the protocols it already implements (a name and a text). The provider accepts a
//! proposal that names one of them (or equals its text), and otherwise counters with its own; the requester proposes one of its
//! own and accepts a counter that names something it has. Rounds are capped (ten, like the SDK) and an agreement means "both
//! sides have it", which is what "code generation" amounts to for protocols that are built in.

use serde_json::{json, Value};
use std::fmt;

pub const MAX_ROUNDS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Meta = 0,
    Application = 1,
    Natural = 2,
    Verification = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaError(pub String);
impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MetaError {}
fn err<T>(s: impl Into<String>) -> Result<T, MetaError> {
    Err(MetaError(s.into()))
}

/// One header byte (channel in the top two bits) and the payload.
pub fn frame(channel: Channel, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 1);
    v.push((channel as u8) << 6);
    v.extend_from_slice(payload);
    v
}

pub fn unframe(bytes: &[u8]) -> Result<(Channel, &[u8]), MetaError> {
    let Some(h) = bytes.first() else { return err("an empty message") };
    let ch = match h >> 6 {
        0 => Channel::Meta,
        1 => Channel::Application,
        2 => Channel::Natural,
        _ => Channel::Verification,
    };
    Ok((ch, &bytes[1..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Negotiating,
    Rejected,
    Accepted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Negotiating => "negotiating",
            Status::Rejected => "rejected",
            Status::Accepted => "accepted",
        }
    }
    fn parse(s: &str) -> Result<Status, MetaError> {
        match s {
            "negotiating" => Ok(Status::Negotiating),
            "rejected" => Ok(Status::Rejected),
            "accepted" => Ok(Status::Accepted),
            o => err(format!("unknown status {o:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Negotiation { sequence_id: u64, candidate: String, summary: Option<String>, status: Status },
    CodeGeneration { generated: bool },
    TestCases { test_cases: String, summary: Option<String>, status: Status },
    FixError { description: String, status: Status },
    NaturalLanguage { request: bool, message_id: String, message: String },
}

impl Message {
    pub fn to_json(&self) -> Value {
        match self {
            Message::Negotiation { sequence_id, candidate, summary, status } => {
                let mut v = json!({ "action": "protocolNegotiation", "sequenceId": sequence_id, "candidateProtocols": candidate, "status": status.as_str() });
                if let Some(s) = summary.as_ref().filter(|s| !s.is_empty()) {
                    v["modificationSummary"] = json!(s);
                }
                v
            }
            Message::CodeGeneration { generated } => json!({ "action": "codeGeneration", "status": if *generated { "generated" } else { "error" } }),
            Message::TestCases { test_cases, summary, status } => {
                let mut v = json!({ "action": "testCasesNegotiation", "testCases": test_cases, "status": status.as_str() });
                if let Some(s) = summary.as_ref().filter(|s| !s.is_empty()) {
                    v["modificationSummary"] = json!(s);
                }
                v
            }
            Message::FixError { description, status } => json!({ "action": "fixErrorNegotiation", "errorDescription": description, "status": status.as_str() }),
            Message::NaturalLanguage { request, message_id, message } => json!({ "action": "naturalLanguageNegotiation", "type": if *request { "REQUEST" } else { "RESPONSE" }, "messageId": message_id, "message": message }),
        }
    }

    pub fn from_json(v: &Value) -> Result<Message, MetaError> {
        let s = |k: &str| v[k].as_str().map(str::to_string);
        let status = || Status::parse(v["status"].as_str().unwrap_or("negotiating"));
        match v["action"].as_str() {
            Some("protocolNegotiation") => {
                let sequence_id = v["sequenceId"].as_u64().ok_or_else(|| MetaError("sequenceId must be a non-negative integer".into()))?;
                Ok(Message::Negotiation { sequence_id, candidate: s("candidateProtocols").unwrap_or_default(), summary: s("modificationSummary"), status: status()? })
            }
            Some("codeGeneration") => Ok(Message::CodeGeneration { generated: v["status"] == "generated" }),
            Some("testCasesNegotiation") => Ok(Message::TestCases { test_cases: s("testCases").unwrap_or_default(), summary: s("modificationSummary"), status: status()? }),
            Some("fixErrorNegotiation") => Ok(Message::FixError { description: s("errorDescription").unwrap_or_default(), status: status()? }),
            Some("naturalLanguageNegotiation") => Ok(Message::NaturalLanguage { request: v["type"] == "REQUEST", message_id: s("messageId").unwrap_or_default(), message: s("message").unwrap_or_default() }),
            Some(o) => err(format!("unknown action {o:?}")),
            None => err("a meta message needs an action"),
        }
    }

    /// The bytes to send: the meta header and the JSON.
    pub fn encode(&self) -> Vec<u8> {
        frame(Channel::Meta, self.to_json().to_string().as_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Message, MetaError> {
        let (ch, payload) = unframe(bytes)?;
        if ch != Channel::Meta {
            return err(format!("not a meta message (channel {})", ch as u8));
        }
        let v: Value = serde_json::from_slice(payload).map_err(|e| MetaError(format!("the payload is not JSON: {e}")))?;
        Message::from_json(&v)
    }
}

// ── the catalog ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Protocol {
    /// A short name that a proposal can mention (`a2a-json-rpc`).
    pub name: String,
    /// The protocol as text, in the form that is sent as a counter-proposal.
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct Catalog(pub Vec<Protocol>);

impl Catalog {
    /// The protocol a proposal means: its text equals one of ours, or it names one (whole word, any case).
    pub fn find(&self, proposal: &str) -> Option<&Protocol> {
        let p = proposal.trim();
        if let Some(x) = self.0.iter().find(|x| x.text.trim() == p) {
            return Some(x);
        }
        let lower = p.to_lowercase();
        self.0.iter().find(|x| {
            let n = x.name.to_lowercase();
            lower.match_indices(&n).any(|(i, _)| {
                let before = lower[..i].chars().next_back().map_or(true, |c| !(c.is_alphanumeric() || c == '-' || c == '_'));
                let after = lower[i + n.len()..].chars().next().map_or(true, |c| !(c.is_alphanumeric() || c == '-' || c == '_'));
                before && after
            })
        })
    }
}

// ── the session ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Requester,
    Provider,
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Negotiating,
    /// The protocol both sides have, by its name here.
    Agreed(String),
    Failed(String),
}

pub struct Session {
    role: Role,
    catalog: Catalog,
    round: u64,
    last_sent: String,
    state: State,
    /// Told by the other side that it can speak the protocol (`codeGeneration generated`).
    pub peer_ready: Option<bool>,
    /// Natural-language messages received.
    pub notes: Vec<String>,
}

impl Session {
    /// The side that is asked: it waits for a proposal.
    pub fn provider(catalog: Catalog) -> Session {
        Session { role: Role::Provider, catalog, round: 0, last_sent: String::new(), state: State::Negotiating, peer_ready: None, notes: vec![] }
    }

    /// The side that asks: it proposes protocol `want` (one of its catalog) in round 1. Returns the session and the first message.
    pub fn requester(catalog: Catalog, want: &str) -> Result<(Session, Vec<u8>), MetaError> {
        let p = catalog.0.iter().find(|p| p.name == want).ok_or_else(|| MetaError(format!("no protocol named {want} in the catalog")))?.clone();
        let msg = Message::Negotiation { sequence_id: 1, candidate: p.text.clone(), summary: None, status: Status::Negotiating };
        Ok((Session { role: Role::Requester, catalog, round: 1, last_sent: p.text, state: State::Negotiating, peer_ready: None, notes: vec![] }, msg.encode()))
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    fn fail(&mut self, why: &str) -> Vec<Vec<u8>> {
        self.state = State::Failed(why.to_string());
        vec![Message::Negotiation { sequence_id: self.round, candidate: String::new(), summary: Some(why.to_string()), status: Status::Rejected }.encode()]
    }

    fn agree(&mut self, proto: &Protocol, candidate: &str) -> Vec<Vec<u8>> {
        self.state = State::Agreed(proto.name.clone());
        // accepted, then: we have it built in, so "code generation" is done
        vec![
            Message::Negotiation { sequence_id: self.round, candidate: candidate.to_string(), summary: None, status: Status::Accepted }.encode(),
            Message::CodeGeneration { generated: true }.encode(),
        ]
    }

    /// Handle one received message; the messages to send back, in order.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, MetaError> {
        let msg = Message::decode(bytes)?;
        match msg {
            Message::CodeGeneration { generated } => {
                self.peer_ready = Some(generated);
                Ok(vec![])
            }
            Message::NaturalLanguage { message, .. } => {
                self.notes.push(message);
                Ok(vec![])
            }
            Message::TestCases { .. } | Message::FixError { .. } => Ok(vec![]),
            Message::Negotiation { sequence_id, candidate, status, .. } => {
                if self.state != State::Negotiating {
                    // a late message (the SDK answers an acceptance with one of its own): nothing more to say
                    return Ok(vec![]);
                }
                match status {
                    Status::Rejected => {
                        self.state = State::Failed("the other side rejected".into());
                        Ok(vec![])
                    }
                    Status::Accepted => {
                        match self.catalog.find(&self.last_sent).cloned() {
                            Some(p) => {
                                self.state = State::Agreed(p.name);
                                // they accepted what we proposed (or countered): tell them we are ready as well
                                Ok(vec![Message::CodeGeneration { generated: true }.encode()])
                            }
                            None => Ok(self.fail("accepted something that is not in this agent's catalog")),
                        }
                    }
                    Status::Negotiating => {
                        if sequence_id != self.round + 1 {
                            return Ok(self.fail(&format!("expected round {}, got {sequence_id}", self.round + 1)));
                        }
                        self.round += 2;
                        if let Some(p) = self.catalog.find(&candidate).cloned() {
                            return Ok(self.agree(&p, &candidate));
                        }
                        if self.round >= MAX_ROUNDS {
                            return Ok(self.fail("no agreement within the round limit"));
                        }
                        let Some(own) = self.catalog.0.first().cloned() else { return Ok(self.fail("this agent implements no protocol")) };
                        // a requester keeps to what it asked for; a provider offers what it has
                        let counter = if self.role == Role::Requester { self.last_sent.clone() } else { own.text.clone() };
                        self.last_sent = counter.clone();
                        Ok(vec![Message::Negotiation { sequence_id: self.round, candidate: counter, summary: Some(format!("this agent implements {}", own.name)), status: Status::Negotiating }.encode()])
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(names: &[&str]) -> Catalog {
        Catalog(names.iter().map(|n| Protocol { name: n.to_string(), text: format!("Protocol {n}: requests and answers as JSON, one object per message.") }).collect())
    }

    #[test]
    fn the_header_byte_carries_the_channel_in_its_top_two_bits() {
        for (c, b) in [(Channel::Meta, 0x00), (Channel::Application, 0x40), (Channel::Natural, 0x80), (Channel::Verification, 0xC0)] {
            let f = frame(c, b"x");
            assert_eq!(f, vec![b, b'x']);
            assert_eq!(unframe(&f).unwrap(), (c, &b"x"[..]));
        }
        assert_eq!(unframe(&[0b0011_1111, 1]).unwrap().0, Channel::Meta, "the low six bits are reserved and ignored");
        assert!(unframe(&[]).is_err());
    }

    #[test]
    fn messages_round_trip_and_match_the_sdks_shapes() {
        let n = Message::Negotiation { sequence_id: 3, candidate: "P".into(), summary: Some("changed X".into()), status: Status::Negotiating };
        assert_eq!(n.to_json(), json!({ "action": "protocolNegotiation", "sequenceId": 3, "candidateProtocols": "P", "status": "negotiating", "modificationSummary": "changed X" }));
        assert_eq!(Message::decode(&n.encode()).unwrap(), n);
        let no_summary = Message::Negotiation { sequence_id: 1, candidate: "P".into(), summary: None, status: Status::Accepted };
        assert!(no_summary.to_json().get("modificationSummary").is_none(), "an empty summary is left out");
        assert_eq!(Message::CodeGeneration { generated: true }.to_json(), json!({ "action": "codeGeneration", "status": "generated" }));
        assert_eq!(Message::CodeGeneration { generated: false }.to_json()["status"], "error");
        let nl = Message::NaturalLanguage { request: true, message_id: "abc".into(), message: "hi".into() };
        assert_eq!(nl.to_json(), json!({ "action": "naturalLanguageNegotiation", "type": "REQUEST", "messageId": "abc", "message": "hi" }));
        assert_eq!(Message::decode(&nl.encode()).unwrap(), nl);
        assert!(Message::decode(&frame(Channel::Application, b"{}")).is_err());
        assert!(Message::decode(&frame(Channel::Meta, b"not json")).is_err());
        assert!(Message::decode(&frame(Channel::Meta, br#"{"action":"nothing"}"#)).is_err());
        assert!(Message::decode(&frame(Channel::Meta, br#"{"action":"protocolNegotiation","sequenceId":"1","status":"negotiating"}"#)).is_err());
        assert!(Message::decode(&frame(Channel::Meta, br#"{"action":"protocolNegotiation","sequenceId":1,"status":"maybe"}"#)).is_err());
    }

    #[test]
    fn a_proposal_is_recognised_by_text_or_by_a_whole_word_name() {
        let c = cat(&["a2a-json-rpc", "chat"]);
        assert_eq!(c.find("use chat please").unwrap().name, "chat");
        assert_eq!(c.find("USE A2A-JSON-RPC").unwrap().name, "a2a-json-rpc");
        assert!(c.find("a chatty protocol").is_none(), "chat inside chatty is not the name");
        assert!(c.find("exchange chat-v2 messages").is_none(), "nor is chat inside chat-v2");
        assert_eq!(c.find(&c.0[1].text).unwrap().name, "chat");
        assert!(c.find("something else").is_none());
    }

    fn run(req: &mut Session, prov: &mut Session, first: Vec<u8>) -> Vec<String> {
        // pass messages back and forth until neither has anything to say
        let mut log = vec![];
        let (mut to_prov, mut to_req) = (vec![first], Vec::<Vec<u8>>::new());
        for _ in 0..40 {
            if to_prov.is_empty() && to_req.is_empty() {
                break;
            }
            for m in std::mem::take(&mut to_prov) {
                log.push(format!("req->prov {}", String::from_utf8_lossy(&m[1..])));
                to_req.extend(prov.receive(&m).unwrap());
            }
            for m in std::mem::take(&mut to_req) {
                log.push(format!("prov->req {}", String::from_utf8_lossy(&m[1..])));
                to_prov.extend(req.receive(&m).unwrap());
            }
        }
        log
    }

    #[test]
    fn a_provider_that_has_the_protocol_accepts_in_round_two_and_both_are_ready() {
        let (mut req, first) = Session::requester(cat(&["chat"]), "chat").unwrap();
        let mut prov = Session::provider(cat(&["chat", "other"]));
        run(&mut req, &mut prov, first);
        assert_eq!(req.state(), &State::Agreed("chat".into()));
        assert_eq!(prov.state(), &State::Agreed("chat".into()));
        assert_eq!((req.peer_ready, prov.peer_ready), (Some(true), Some(true)));
        assert_eq!(prov.round(), 2, "requester odd, provider even");
    }

    #[test]
    fn a_provider_without_it_counters_and_a_requester_that_has_the_counter_agrees() {
        let (mut req, first) = Session::requester(cat(&["chat", "json-rpc"]), "chat").unwrap();
        let mut prov = Session::provider(cat(&["json-rpc"]));
        // the provider counters with json-rpc; the requester also has it, so it accepts the counter
        let log = run(&mut req, &mut prov, first);
        assert!(log.iter().any(|l| l.contains("\"status\":\"negotiating\"") && l.starts_with("prov->req") && l.contains("\"sequenceId\":2")), "{log:?}");
        assert_eq!(req.state(), &State::Agreed("json-rpc".into()), "{log:?}");
        assert_eq!(prov.state(), &State::Agreed("json-rpc".into()), "{log:?}");
    }

    #[test]
    fn with_nothing_in_common_both_give_up_inside_the_round_limit() {
        let (mut req, first) = Session::requester(cat(&["chat"]), "chat").unwrap();
        let mut prov = Session::provider(cat(&["json-rpc"]));
        let log = run(&mut req, &mut prov, first);
        assert!(matches!(req.state(), State::Failed(_)) && matches!(prov.state(), State::Failed(_)), "{log:?} {:?} {:?}", req.state(), prov.state());
        assert!(req.round().max(prov.round()) <= MAX_ROUNDS + 2, "bounded: {log:?}");
    }

    #[test]
    fn a_round_out_of_order_is_rejected_and_late_messages_are_ignored() {
        let mut prov = Session::provider(cat(&["chat"]));
        let skipped = Message::Negotiation { sequence_id: 5, candidate: "chat".into(), summary: None, status: Status::Negotiating }.encode();
        let out = prov.receive(&skipped).unwrap();
        assert!(matches!(prov.state(), State::Failed(_)));
        assert!(String::from_utf8_lossy(&out[0][1..]).contains("rejected"));
        // after agreement, the SDK sends its own `accepted`: nothing to answer
        let (mut req, first) = Session::requester(cat(&["chat"]), "chat").unwrap();
        let mut prov = Session::provider(cat(&["chat"]));
        run(&mut req, &mut prov, first);
        let late = Message::Negotiation { sequence_id: 3, candidate: "chat".into(), summary: None, status: Status::Accepted }.encode();
        assert!(prov.receive(&late).unwrap().is_empty());
        assert_eq!(prov.state(), &State::Agreed("chat".into()));
        assert!(Session::requester(cat(&["chat"]), "nothing").is_err());
    }

    #[test]
    fn natural_language_notes_and_a_rejection_are_kept() {
        let mut prov = Session::provider(cat(&["chat"]));
        prov.receive(&Message::NaturalLanguage { request: true, message_id: "m".into(), message: "can you do chat?".into() }.encode()).unwrap();
        assert_eq!(prov.notes, vec!["can you do chat?".to_string()]);
        prov.receive(&Message::Negotiation { sequence_id: 1, candidate: String::new(), summary: None, status: Status::Rejected }.encode()).unwrap();
        assert!(matches!(prov.state(), State::Failed(_)));
    }
}