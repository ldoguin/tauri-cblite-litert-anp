//! # a2a-core
//!
//! The part of an [A2A](https://a2a-protocol.org) 1.0 node that does not depend on how tasks travel: shared by the A2A project (`a2a-cblite`)
//! and the ANP one (`anp-cblite`), which keeps A2A's task model and adds ANP identities, encryption and discovery around it.
//!
//! * [`protocol`] – the A2A 1.0 JSON-RPC types (cards, messages, tasks, events)
//! * [`executor`] – implement [`executor::Executor`] to bring your own agent
//! * `llm` – (feature `litert`, not on Windows) an agent backed by an on-device model through LiteRT-LM
//! * [`DEMO_ALL_HTML`] – the control-room page that shows three devices side by side

pub mod executor;
#[cfg(all(feature = "litert", not(windows)))]
pub mod llm;
pub mod protocol;

/// The control-room page (`/demo/all`): three devices side by side, each pane the node's own `/demo` page.
pub const DEMO_ALL_HTML: &str = include_str!("demo-all.html");