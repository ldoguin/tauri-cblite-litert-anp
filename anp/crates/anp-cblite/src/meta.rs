//! ANP-06 for the node: `POST /anp/meta` carries the meta-protocol messages (see `anp_meta`) and `GET /anp/meta/protocols` lists
//! what this node implements.
//!
//! The spec describes a message stream (a WebSocket in the SDK's examples); this is the same messages over HTTP: the caller
//! picks a session id (header `x-anp-session`, 8 to 64 characters of `A-Za-z0-9_-`) and POSTs one framed message as the body
//! (`application/octet-stream`: the header byte, then JSON). The answer holds the messages to send back, each preceded by its
//! length as four bytes, big-endian (nothing at all if there is nothing to say), and the header `x-anp-meta-state` says where
//! the negotiation stands (`negotiating`, `agreed:<protocol>`, `failed`). The node is always the provider: it waits to be asked.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anp_meta::{Catalog, Protocol, Session, State};

/// Sessions kept at most, and how long one may sit idle.
const MAX_SESSIONS: usize = 200;
const IDLE: Duration = Duration::from_secs(600);

pub struct MetaService {
    catalog: Catalog,
    sessions: Mutex<HashMap<String, (Session, Instant)>>,
}

/// The text of the one protocol every node has: its A2A task interface.
pub const A2A_TEXT: &str = "a2a-json-rpc: JSON-RPC 2.0 over HTTP POST to the agent's root URL. Methods, parameters by name: SendMessage {message}, GetTask {id}, ListTasks {pageSize, pageToken}, CancelTask {id}. A message is {messageId, role (ROLE_USER or ROLE_AGENT), parts: [{text}]}; SendMessage answers with {task} once it has settled. The methods are described by the agent's OpenRPC document.";

impl MetaService {
    pub fn new(protocols: Vec<Protocol>) -> MetaService {
        MetaService { catalog: Catalog(protocols), sessions: Mutex::new(HashMap::new()) }
    }

    pub fn protocols(&self) -> Vec<(String, String)> {
        self.catalog.0.iter().map(|p| (p.name.clone(), p.text.clone())).collect()
    }

    pub fn valid_session_id(id: &str) -> bool {
        (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// Handle one message of session `id`: the bytes to answer with, and the state header value.
    pub fn handle(&self, id: &str, body: &[u8]) -> Result<(Vec<u8>, String), String> {
        let mut map = self.sessions.lock().unwrap();
        map.retain(|_, (_, at)| at.elapsed() < IDLE);
        if !map.contains_key(id) && map.len() >= MAX_SESSIONS {
            return Err("too many negotiations in progress".into());
        }
        let (session, at) = map.entry(id.to_string()).or_insert_with(|| (Session::provider(self.catalog.clone()), Instant::now()));
        *at = Instant::now();
        let frames = session.receive(body).map_err(|e| e.0)?;
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(&f);
        }
        let state = match session.state() {
            State::Negotiating => "negotiating".to_string(),
            State::Agreed(p) => format!("agreed:{p}"),
            State::Failed(_) => "failed".to_string(),
        };
        Ok((out, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp_meta::{Message, Status};

    fn svc() -> MetaService {
        MetaService::new(vec![Protocol { name: "a2a-json-rpc".into(), text: A2A_TEXT.into() }])
    }

    fn frames(mut b: &[u8]) -> Vec<Vec<u8>> {
        let mut v = vec![];
        while !b.is_empty() {
            let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
            v.push(b[4..4 + n].to_vec());
            b = &b[4 + n..];
        }
        v
    }

    #[test]
    fn a_proposal_that_names_the_protocol_is_accepted_and_the_node_says_it_is_ready() {
        let s = svc();
        let ask = Message::Negotiation { sequence_id: 1, candidate: "Let us use a2a-json-rpc for tasks".into(), summary: None, status: Status::Negotiating }.encode();
        let (out, state) = s.handle("session-0001", &ask).unwrap();
        assert_eq!(state, "agreed:a2a-json-rpc");
        let msgs: Vec<Message> = frames(&out).iter().map(|f| Message::decode(f).unwrap()).collect();
        assert!(matches!(msgs[0], Message::Negotiation { sequence_id: 2, status: Status::Accepted, .. }));
        assert_eq!(msgs[1], Message::CodeGeneration { generated: true });
    }

    #[test]
    fn something_else_gets_a_counter_proposal_and_sessions_are_separate() {
        let s = svc();
        let ask = Message::Negotiation { sequence_id: 1, candidate: "a protocol for ordering pizza".into(), summary: None, status: Status::Negotiating }.encode();
        let (out, state) = s.handle("session-0002", &ask).unwrap();
        assert_eq!(state, "negotiating");
        let m = Message::decode(&frames(&out)[0]).unwrap();
        assert!(matches!(&m, Message::Negotiation { sequence_id: 2, status: Status::Negotiating, candidate, .. } if candidate.contains("a2a-json-rpc")));
        // another session starts from round 1 again
        let (_, st) = s.handle("session-0003", &ask).unwrap();
        assert_eq!(st, "negotiating");
        // a message that is not a meta message is an error, not a panic
        assert!(s.handle("session-0004", b"\x40{}").is_err());
        assert!(s.handle("session-0004", b"").is_err());
    }

    #[test]
    fn session_ids_are_checked() {
        assert!(MetaService::valid_session_id("abcdefgh"));
        assert!(MetaService::valid_session_id("A-b_1-2345678"));
        for bad in ["short", "has space 1234", "semi;colon1234", &"x".repeat(65), ""] {
            assert!(!MetaService::valid_session_id(bad), "{bad:?}");
        }
    }
}