# tauri-cblite-litert

Agents on [Couchbase Lite](https://www.couchbase.com/products/lite/) whose transport is peer-to-peer replication and whose models run on the
device (LiteRT-LM), in two generations that share one task layer:

| Folder | What it is |
|---|---|
| [`a2a/`](a2a/README.md) | The original project: an [A2A](https://a2a-protocol.org) 1.0 node on Couchbase Lite, Biscuit tokens, TLS and admission, the field-inspection demo, and a Tauri desktop app. |
| [`anp/`](anp/README.md) | The same mesh moved onto the [Agent Network Protocol](https://github.com/agent-network-protocol/AgentNetworkProtocol): `did:wba` identities, signed requests, end-to-end encrypted direct messages and groups, signed agent descriptions, discovery, human-readable handles, protocol negotiation, a search agent (see the [glossary](anp/README.md#the-anp-terms-used-here)); interop checks against the official SDKs, and `cargo xtask` end-to-end tests. |
| `common/` | What both use as is: [`a2a-core`](common/crates/a2a-core/src/lib.rs) (the A2A 1.0 JSON-RPC types, the `Executor` trait an agent implements, the on-device LLM executor, the control-room demo page) and the recording viewer used by both `record-demo.sh` scripts. |

```text
common/crates/a2a-core      the shared A2A task layer
common/scripts              shared script helpers
a2a/crates                  a2a-authz, a2a-cblite, a2a-node
a2a/src-tauri  a2a/scripts  a2a/docs
anp/crates                  anp-did, anp-cblite, anp-node, ... (14 crates)
anp/src-tauri  anp/scripts  anp/testdata  anp/xtask
```

## Build and test

One Cargo workspace covers all three folders (the two Tauri apps are workspaces of their own, in `a2a/src-tauri` and `anp/src-tauri`):

```text
cargo build --workspace                 # every crate of both projects
cargo test --workspace
cargo build -p a2a-node -p a2a-authz    # just the A2A node and its admin tool
cargo build -p anp-node -p anp-authz -p anp-ad -p anp-search -p anp-wns -p anp-meta
cargo xtask all                         # the ANP end-to-end checks (see anp/README.md)
```

`a2a-cblite` and `anp-cblite` re-export the shared layer under their old paths (`a2a_cblite::{protocol, executor, llm}`,
`anp_cblite::{...}`), so code written against either keeps working. The `litert` feature of either turns on `a2a-core/litert`.
