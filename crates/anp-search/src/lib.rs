//! An ANP search agent. The spec (ANP-08) leaves *passive discovery* to each search agent: an agent registers with it, and
//! the agent answers queries; it defines no request or response. This is one such agent, and its API is its own OpenRPC
//! interface (`register`, `crawl`, `refresh`, `search`, `list`), described in its signed agent description.
//!
//! What it indexes is only what verifies:
//! * the description must be fetched over HTTPS (guarded: no internal addresses, no redirects, size limits) from the URL it
//!   names in its own `url` field;
//! * it must name a `did:wba` e1 DID whose document, fetched from that DID's own domain, is self-certifying;
//! * the DID's domain must be the domain the description was fetched from (an agent describes itself on its own domain);
//! * the description's proof must verify against an `assertionMethod` key of that document, and be bound to that domain.
//!
//! So an entry in the index is a claim its owner signed, found where its owner published it. Registering someone else's
//! description, or a changed one, fails. Nothing is trusted because of who registered it.

pub mod auth;
pub mod index;
pub mod openrpc;
pub mod ratelimit;
pub mod service;
pub mod store;

pub use index::{Entry, Index, Match};
pub use service::{Fetcher, Service};