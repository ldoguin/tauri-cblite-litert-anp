# tauri-cblite-litert-anp

Agents on Couchbase Lite whose identity is an [ANP](https://github.com/agent-network-protocol/AgentNetworkProtocol)
`did:wba` DID, whose transport is peer-to-peer replication, and whose models run on the device (LiteRT-LM).

This started as a copy of the A2A version of the project (same transport, the same on-device agents, the same
field-inspection demo) and has been moved onto ANP piece by piece. Most of ANP is implemented now, each part checked against the official SDKs; what is missing is said with each part and under
[Next](#next). New to ANP? The [glossary](#the-anp-terms-used-here) right below explains the terms the rest of this page uses.

## The ANP terms used here

ANP (the [Agent Network Protocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)) is an open protocol for agents that find,
identify and talk to each other across organisations. Its parts are numbered documents, ANP-01 to ANP-09; the numbers are given in brackets
below for whoever reads the spec, and nothing here needs them.

| Term | What it means |
|---|---|
| **DID**, `did:wba` | A decentralized identifier: a name for an agent that comes with its public keys. `did:wba` is ANP's kind, tied to a web domain: `did:wba:example.com:agents:alice:e1_…`; its **DID document** (a JSON file listing the keys and where to reach the agent) is served by that domain (ANP-03). |
| `e1` | The variant of `did:wba` used here: the DID ends with a fingerprint of the agent's key, so a document can be checked offline, with no call to the domain. |
| **Signed requests** | Every HTTP request carries a signature made with the caller's DID key, so the receiver knows who sent it and that nothing was changed (HTTP Message Signatures, RFC 9421; ANP-02). |
| **Agent description** | A signed JSON card that says what an agent does and how to call it (ANP-07). |
| **Discovery** | Finding agents: a domain lists its agents' descriptions at `/.well-known/agent-descriptions`, and a **search agent** indexes what verifies (ANP-08). |
| **Handle** | A human-readable name such as `alice.example.com` that resolves to a DID, and is only believed if the DID points back to it (WNS, ANP-04). |
| **Meta-protocol** | Two agents agreeing on which protocol they will speak before they start (ANP-06). |
| **Direct messages** | An end-to-end encrypted one-to-one conversation between two agents, where the keys change with every message (the Double Ratchet). The ANP spec calls this profile **P5** (in ANP-09); here it is `--direct-messaging` and `POST /anp/direct`. |
| **Encrypted groups** | End-to-end encrypted messaging for a group of devices, on **MLS** (Messaging Layer Security, RFC 9420), with a **group host** that orders and relays messages but cannot read them. The ANP spec calls this profile **P6** (in ANP-09); here it is `--group-host` and `/anp/groups`. |
| **Prekey bundle** | Keys an agent publishes in advance (signed by its DID key) so that others can open an encrypted conversation with it while it is offline; a **one-time prekey** is used for a single conversation. |
| **Biscuit token** | Not part of ANP: a signed capability token from an authority that says which agents a device may message. This project's authorization layer. |
| **The SDKs** | ANP's official reference implementations (Python, Rust, Go, TypeScript), which this code is checked against. |

## Where it stands

| Layer | Status |
|---|---|
| **Identity: `did:wba` DIDs** (ANP-03; `crates/anp-did`) | Done for the e1 profile: DID parsing and resolution URLs, the `e1_` Ed25519 key binding (RFC 7638 thumbprint), DID documents with an `eddsa-jcs-2022` Data Integrity proof, offline verification. 9 tests. |
| **DID mode in the mesh** (`Trust::with_did`) | Done: a node *is* `did:wba:<host>:agents:<name>:e1_<fp>`, its signed DID document travels with every signed document, peers are trusted by pinned DID, and connection admission is a DID-signed assertion. 8 unit tests + `scripts/e2e-did.ps1` (17 checks on real nodes over TLS). |
| DID document hosting | `GET /agents/<name>/<e1_fp>/did.json` serves the node's document at the URL `did:wba` resolution derives (put TLS in front for ANP peers). |
| Task layer | Still the A2A 1.0 JSON-RPC task model (inherited). ANP does not define task semantics. || **DID + Biscuit together** | Done: the authority issues a token *bound to a DID* (`anp-admin issue --did`). The key comes from the self-certifying DID document, the token must name that same DID and key, and scoping, expiry, attenuation and replicated revocation all work, with no pinning. 7 unit tests + 4 in `anp-authz` + `scripts/e2e-did-biscuit.ps1` (20 checks on real nodes). ANP-05 (authorization) is only a draft upstream, so Biscuit stays the authorization layer. |
| **Agent descriptions** (ANP-07; `crates/anp-ad`) | Done: build, validate (the spec's field rules), sign and verify. Every DID-mode node serves a signed description at `/agents/<name>/ad.json`, generated from its A2A agent card, and its DID document advertises it as an `AgentDescription` service. 8 + 1 unit tests, 6 checks in `scripts/e2e-did.ps1`, and an `anp-ad verify` CLI. |
| **Discovery** (ANP-08) | Active discovery done: `GET /.well-known/agent-descriptions` is a paged JSON-LD `CollectionPage` of the verified descriptions under the node's domain; `GET /discover` is the mesh view (every agent, its DID, whether its replicated description verifies); `anp-ad discover` crawls a listing. 7 + 2 unit tests, 8 checks in `scripts/e2e-did.ps1`. Passive discovery (registering with a search agent) is not implemented, see below. |
| **End-to-end encryption** (`crates/anp-e2ee`, `--e2ee`) | Done: payloads of tasks and commands are sealed to the node they are for (and to the author), so a relay that only replicates them cannot read them. Signed prekey bundles with a device manifest, X3DH-style sealed messages with P5's suite, key schedule and associated data. 15 unit tests, `scripts/e2e-e2ee.ps1` (21 checks on real nodes with a control run). |
| **Signed requests** (ANP-02; `crates/anp-httpauth`, `--require-auth`) | Done for RFC 9421 HTTP Message Signatures with Ed25519: signer, verifier (policy, body digest, authority spellings), replay cache, node middleware, 27 SDK vectors, both directions live with the SDK. 6 tests. The older `DIDWba` header and Bearer tokens are not implemented. |
| **Encrypted direct messages** (ANP-09 "P5"; `anp_e2ee::session`, `anp_e2ee::wire`, `--direct-messaging`, `POST /anp/direct`) | Done: the Double Ratchet (follow-up messages, DH ratchet turns, out-of-order delivery, skipped keys, replay refusal, persistence), one-time prekeys, the `direct.send` and key-service wire objects with the error table, and a node endpoint that accepts an init, continues the session, runs each message through the agent and sends the answer back sealed and ANP-02-signed. 9 session tests, 7 wire tests, 4 conversation scenarios and a live node chat with the **official Rust SDK**. See Interoperability for what is not covered. Replies go through a persistent **outbox with retries**, and the node is a **key service** for peers that publish their bundles here (`publish_prekey_bundle`). The node also **starts conversations** (cold-stock rescue milestone 3): it fetches the peer's bundle from the peer's own endpoint, checks it against the peer's DID document and sends the init; either side can then ask in the session. An answer to the node's own question goes to a conversation log and to subscribers, not to its agent, so two nodes never answer each other's answers. The operator sends with `POST /anp/direct/conversations` (`{"to": DID, "text": ...}` or `"payload"`) and reads with `GET` (`?peer=DID`): this machine only, never through a proxy. `cargo xtask e2e-direct` runs two nodes on two domains both ways (27 checks). |
| **HTTPS DID resolver** (`crates/anp-resolve`, `--trust-domain`) | Done: `did:wba` and `did:web` documents are fetched over HTTPS, verified (e1 binding and proof; for `did:web` the domain vouches), cached, and guarded against being used to reach internal hosts. A node told to trust a domain accepts callers (ANP-02) and P5 peers from it without being handed their documents; a P5 peer's reply endpoint comes from its `ANPMessageService`. 13 resolver tests against a real TLS server, plus the **official SDK's client** accepted on its domain alone. |
| **The older way of signing requests** (ANP-02 `DIDWba`; `--allow-legacy-auth`) | Done, off by default: `Authorization: DIDWba` headers (version 1.0 and 1.1, `aud`/`service`) and the Bearer token the node answers with (HS256 JWT, 1 h). The SDK's own vector verifies; the SDK's clients (Python and Go) sign in, get the token and use it. |
| **OpenRPC interface** (`/agents/<name>/openrpc.json`) | Done: the node's JSON-RPC methods (`SendMessage`, `GetTask`, `ListTasks`, `CancelTask`) described as OpenRPC and linked from the signed agent description as a `StructuredInterface`. The SDK's parsers and its header generator accept it, and a call built from it works. |
| **Search agent** (ANP-08 passive discovery; `crates/anp-search`, `anp-search`) | Done as a separate service: register a description by URL or crawl a domain's `.well-known` listing, index only what verifies, search by words and protocol. Its own API is its signed OpenRPC interface. Tested with the SDK reading and verifying what it serves. |
| **Field-inspection demo on DIDs** | Done: `scripts/demo-field-inspection.sh` runs tablet, branch and head office as DIDs with tokens bound to them and encrypted task text; the demo page shows each device's DID and whether its description verified. `scripts/e2e-field-did.ps1` runs the scenario (signal loss included) on Windows with the built-in agents. |
| **Official Go SDK 1.0.7** | DID documents, the direct-messaging (P5 v2) prekey bundle, associated data, plaintext and wire objects and RFC 9421 signatures both ways, and its client against a running node (signatures, then the older scheme). The Go SDK has no direct-messaging session (P5 v2), so the session cryptography is checked against the Rust SDK only. |
| **Handles: human-readable names** (ANP-04 WNS; `crates/anp-wns`, `anp-wns`, `--handle`) | Done: handle syntax and `wba://` URIs, the resolution document (`/.well-known/handle/<local>`, generations as decimal strings of any size, display-only profile), forward **and** reverse binding checks, a guarded HTTPS client, and a node that provides handles and carries the matching `ANPHandleService` in its DID document. Compared with the SDK on a table of 33 handles, and read by the Python and TypeScript SDKs. |
| **Negotiating a protocol** (ANP-06 meta-protocol; `crates/anp-meta`, `anp-meta`, `--meta-protocol`) | Done without a language model: the one-byte framing, every message type, the round rules, and a negotiation that works from a catalog of the protocols an agent already implements. Both roles run against the SDK's own `MetaProtocol` (with a stand-in where it would call a model). |
| **A Windows node and a Linux node in one mesh** (`scripts/linux-node-build.sh`, `scripts/e2e-cross-os.ps1`) | Done: the node builds and runs on Linux (WSL2, x86_64, Couchbase Lite for Linux); both directions of tasks, signed descriptions verified across, token scoping, an unauthorised Linux node refused, a restart. One physical machine, two operating systems. |
| **Encrypted groups** (ANP-09 "P6"; `crates/anp-group`, `crates/anp-group-mls`, `crates/anp-group-host`) | Done, **including a group host the node serves** (`--group-host`: key service, group DIDs, ordering, origin-proof checks, receipts by the group's key, mailboxes; three devices over signed HTTP, and the SDK as a member and as a controller through it): the `anp.group.e2ee.v2` wire objects, AAD and bindings, the DID-WBA device binding and the RFC 9421 origin proof (`anp-group`), and the MLS session under them (`anp-group-mls`, openmls 0.8): key packages whose leaf carries the binding, create, add (commit, welcome, tree), join, process a commit, remove, send and read. Byte-for-byte equal to the SDK's shared vectors; and **this project and the official Rust SDK (with its MLS feature) are members of each other's groups, both ways**: the SDK adds this project and this project adds the SDK, each validates the other's key package, every leaf and the messages. Also **roster and policy hashes** (`anp_group::state`), a **member cap** the host enforces, a **signed group state** (`group.e2ee.state`) and a **WebSocket push channel** for mailboxes (`GET /anp/groups/ws`). The host and a two-node mesh were run against a second node on the **WSL2 VM of the same PC** (another OS, another Couchbase Lite build, its own IP), not a physically separate machine. |
| **Spending authority and signed quotes** (cold-stock rescue milestones 1 and 2; `anp-authz`, `crates/anp-quote`) | Done as libraries: a token can carry a spending limit (a cap per commitment, categories, the site), which a holder can narrow but never raise (`anp-admin issue --spend-cap ...`). `anp-quote` is a four-message protocol (request, quote, acceptance, confirmation or rejection), each signed with the sender's DID key and naming the previous one by digest. The seller checks the buyer's token itself, bound to the DID and key that signed the acceptance; a whole deal audits offline afterwards, judged at the time of the acceptance. A `Ledger` keeps the buyer's running total. 11 + 13 unit tests. Not yet wired into the node: that is milestone 7. |
| **The node as a group member** (cold-stock rescue milestone 4; `anp_cblite::group_member`, `--group-member HOST_URL`) | Done: besides hosting groups, a node can be one of their MLS devices. Its DID document then lists the group profiles for its device; it publishes key packages to the host (again after each welcome), creates groups and adds and removes members as their controller, and collects its mailbox with the host's long poll: it joins from a welcome, processes others' commits against the binding the notice names, learns it was removed, and checks every message (origin proof against the sender's DID document, the host's receipt by the group's key, MLS sender = signer) before decrypting it. The MLS state, the groups and a log are kept on disk. The operator acts through `POST /anp/groups/member/{create,add,remove,send}` and reads `GET /anp/groups/member[?group=DID]` (this machine only). `cargo xtask e2e-group`: three companies' nodes in a group hosted by a fourth, 33 checks, including a restart, a removal, and the host holding no message in clear. |
| **The simulated store** (cold-stock rescue milestone 5; `crates/anp-coldstore`, `anp_cblite::coldstore`, `--store-sim MIN_PER_SEC`) | Done: store 0412's cold room (two freezers, two chillers, eight products worth about €40,000) with a cooling model per unit, two controller faults (stuck in defrost, as in the October 2026 attacks; compressor off), and food-safety rules per product (a limit with an allowance in minutes, and a hard limit). `assess` says what is safe, what is at risk and for how many minutes (the model run forward), and what is lost, ranked by urgency and value. A node running it logs each unit's temperature every five simulated minutes into a new replicated collection, `telemetry`: signed like every document, and only the node a log names may write it (tokens now carry `right("telemetry", "own")`). `GET /store/sim`, `POST /store/sim/{fault,advance}` and `GET /telemetry` answer this machine only. 6 + 1 unit tests; `cargo xtask e2e-coldstore`, 27 checks, with a head office that catches up after a cut link. The demo's rules are plausible, not regulatory advice. |
| **Counterparties and the store's buying desk** (cold-stock rescue milestone 6; `crates/anp-counterparty`, `anp_cblite::quotes`) | Done: eight rule-based companies (`--counterparty frostline\|polar\|coldchain\|rungis-cold\|orly-freeze\|foodbank\|insurer\|supplier --buyer-root ROOT`): three carriers (too expensive, unavailable, right), two warehouses (one with room for 2 pallets), a food bank, an insurer, a supplier. A quote-protocol message in a direct conversation goes to the node's desk, not its agent: a request gets a signed quote or refusal by the company's rules; an acceptance is checked by the company itself against the buyer's token and confirmed or refused with the reason. The store's node buys (`--spend-token FILE --spend-root ROOT --budget EUROS --site NAME`): signed requests and acceptances, quotes verified on arrival, a ledger (reserved, committed, freed), and every confirmed deal kept as an offline-auditable record; over its token's cap or its budget it does not sign and says a person is needed, who can raise the budget or hand it a new token from the authority (`POST /anp/quotes/authority`). `GET /anp/quotes`, `POST /anp/quotes/{request,accept,authority,audit}`, this machine only. 4 unit tests; `cargo xtask e2e-quotes`, 35 checks on nine nodes. |
| **The store's agent** (cold-stock rescue milestone 7; `anp_cblite::rescue`, `--rescue DIRECTORY.json`) | Done, rule-based: from the cold room's assessment it works out the needs, asks every company of each role at once, and chooses through a rule layer that sits between the plan and the signing desk and logs every decision with its rule (nothing past its safety limit is moved or given away; a carrier must arrive before the first loss, the cheapest that can wins; storage is filled cheapest per pallet and re-planned when an offer falls short; only what is worth more than moving it is moved; chilled stock goes to the food bank; lost stock is restocked). Over its budget or token it signs nothing and writes the duty manager a decision (the plan, what it saves, what doing nothing loses), resuming on `POST /rescue/approve`. Then it commits one acceptance per need, opens an encrypted group with every company that confirmed, posts the plan, and audits every deal. `GET /rescue`, `POST /rescue/{start,approve,decline}`, this machine only. `cargo xtask e2e-rescue`: the whole night on ten nodes, 30 checks. Not done: finding companies through the search agent (the directory is given), and a planner driven by an on-device model. |
| **Official TypeScript SDK 0.9.5** | DID documents, RFC 9421 signatures both ways, handle resolution and verification, and its client against a running node (signatures, then the older scheme). Found that it reads only the legacy proof form, so DID documents and descriptions are now written in it (see Interoperability). |

## DID mode: agents identified by DIDs

```text
anp-node --name alice --data ./alice --did-host alice.example.com --print-did
alice did:wba:alice.example.com:agents:alice:e1_Wc4f...        # derived from the node's key

anp-node --name bob --data ./bob --did-host bob.example.com --trust-did <alice's DID> --tls --admit --connect wss://...
```

* The DID is **self-certifying**: its last segment is the thumbprint of the node's Ed25519 key, so a DID document can be
  checked offline. That matters on a mesh whose devices are often offline: nothing is fetched to verify a peer.
* Trust is an explicit **pin of the peer's DID**. A forged document that names a trusted domain is refused, because
  anyone can mint a document saying it lives on any host. Only a document actually fetched over HTTPS from the domain
  proves the domain vouches for it. That resolver is not built, so `trust a whole domain` is not offered yet.
* The node's *name* is part of its DID (`.../agents/<name>/e1_...`), so a valid DID cannot be used to sign as someone
  else.
* Admission: the connection password is a base64 assertion `{did, doc, ts, sig}`; the listener checks the DID is pinned,
  the document verifies, the name matches and the signature covers `name, did, ts` (10-minute window, so clocks matter).

## End-to-end encryption

```text
anp-node --name bob --data ./bob --did-host bob.example.com --e2ee ...      # needs DID mode
```

* **What is encrypted:** the `message` of an inbox command and the `task` of a task document (status text, artifacts,
  history). Each is sealed to the node it is for **and** to its author, so a node can always read what it wrote
  (the executor reads its own task back; a task kept on one node is sealed to that node alone).
* **What is not:** routing metadata (document ids, `to`/`from`, `owner`/`origin`, timestamps, which task ids exist, their
  sizes and timing), agent cards, DID documents and agent descriptions. A relay learns *who talks to whom and when*, not
  *what*. The node that runs the task, and its on-device model, of course see the plaintext.
* **Relays:** a node that only replicates a document holds the ciphertext; its own API answers `task not found` and its
  task list omits it. The e2e searches the relay's database files for the secret: absent with `--e2ee`, present in a
  control run without it.
* **Keys:** a node's X25519 key-agreement key is derived from its signing seed (domain-separated) and published in the DID
  document's `keyAgreement` (`X25519KeyAgreementKey2019`). Its **signed prekey** (rotated every 7 days, kept 90, bundle
  valid 30) is published in a bundle signed by the DID key and replicated with the agent card. Senders learn a peer's
  keys only from a card that passed the trust checks.
* **Construction (from ANP-09 P5 §5-6):** `DH1 = DH(KA_sender, SPK_recipient)`, `DH2 = DH(EK, KA_recipient)`,
  `DH3 = DH(EK, SPK_recipient)`, HKDF-SHA256 with P5's info strings, ChaCha20-Poly1305 under the first message key and
  nonce (`kdf_ck(CK0)`), associated data = the JCS of an object binding the sender, recipient, document id, field,
  suite, prekey and session ids. A ciphertext cannot be moved to another document, field, sender or recipient.
* **Fails closed:** with no verified keys for the recipient (their card has not replicated) the write is refused with
  an error; nothing is ever sent in the clear. A peer's expired bundle counts as no keys.
* **No downgrade:** with `--e2ee`, a document from a peer that carries the payload in plaintext is refused and logged.
  (It has still replicated to everyone in between: the refusal protects the receiver, not the sender's secrets.)
* **Two ways to use it.** Documents in the replicated store are each their own init (`seal`/`open`: no state, any order, offline
  recipients are no problem). A conversation with an agent on **another ANP stack** is a direct-messaging *session* (P5) (`anp_e2ee::session`): an init
  followed by follow-up messages that ratchet, which is what `POST /anp/direct` speaks (below). Both use the same bundles, suite,
  key schedule and associated data. The key schedule (X3DH with and without a one-time prekey, `kdf_ck`, `kdf_rk`) and the JCS form
  of the associated data **match the vectors published by the ANP SDK**, and the official Rust SDK opens our messages and we open its.
* **Forward secrecy is limited:** a message is protected by the recipient's signed prekey until that prekey is deleted
  (after 90 days). Stealing a device inside that window opens everything sealed to its keys, and the key-agreement key
  comes from the same seed as the signing key. Deleting old prekeys also makes old messages unreadable for everyone,
  including the recipient (the e2e unit tests cover this).
* **Offline:** sending needs the recipient's last-seen bundle (kept from their replicated card, re-read from the local
  database after a restart, so it works with no network). A peer offline for more than the bundle's remaining validity
  (23-30 days) cannot be written to until it is back.
* **Not tested:** EE2E together with Biscuit tokens (it only depends on DID mode, but the e2e does not run the hybrid),
  large payloads, streaming-heavy tasks (every state change is a new sealed document).

## Encrypted direct messages with agents on other ANP stacks (ANP-09 "P5")

```text
anp-node --name live --data ./live --did-host live.example.com --e2ee --direct-messaging \
         --allow-caller client.did.json --direct-peer did:wba:client.example.com:agents:client:e1_...=https://client.example.com/anp/inbox
```

* **What it is:** an agent on another stack (the official SDK, for one) can fetch this node's prekey bundle, open a direct-messaging session,
  and chat with the node's agent. The node's DID document advertises an `ANPMessageService` at `/anp/direct`.
* **The endpoint** (`POST /anp/direct`, JSON-RPC): `direct.e2ee.get_prekey_bundle` returns the node's signed bundle and, to a *known* peer,
  one one-time prekey (each handed out once, used once, kept on disk); `direct.send` takes an init (X3DH, session created) or a
  follow-up (ratchet). Failures carry the spec's error codes: 4000 no such bundle, 4003 no one-time prekey, 4005 no session, 4007 bad init,
  4008 replay, 4009 decryption failed, 4010 too many skipped, 4012 wrong addressee, unknown sender or binding.
* **Who may talk to the node:** only peers whose DID document it was given (`--allow-caller`, shared with the ANP-02 caller list). The
  sender is authenticated by the key exchange itself: an init only opens if it was made with the static key-agreement key the
  peer's DID document publishes, for the device that document's manifest lists with it.
* **What happens to a message:** the plaintext (`text/plain`, or a JSON payload with a `text` member) goes to the node's agent as an
  ordinary A2A message; the answer is sealed into the session and POSTed to the peer's endpoint, signed with ANP-02. The reply is a
  follow-up, so the first one has `pn = 0, n = 0` and turns the ratchet. Sessions are kept in `direct-sessions.json`, one-time prekeys
  in `e2ee-opks.json`, next to the node's key.
* **Where replies go:** `--direct-peer DID=URL`, or the `ANPMessageService` in the peer's DID document. With neither, the reply is not sent.
  A reply is sealed into the session first and then put in an **outbox** (`direct-outbox.json`, kept on disk); a loop delivers it,
  signing each attempt afresh (new nonce). If the peer is unreachable or answers 5xx, 429, 408, 401, 403 or 404 it is retried after
  2 s, 4 s, 8 s ... up to 5 min, and given up after 40 attempts or 24 h; any other 4xx, or a JSON-RPC error from the peer, drops it at
  once. The ciphertext is never re-made, so the peer sees one message id however often it arrives, and a restart loses nothing.
* **The node as a key service for other devices:** `direct.e2ee.publish_prekey_bundle` stores a peer's bundle and one-time prekeys
  (`direct-published.json`, at most 1000 prekeys per device); `get_prekey_bundle` for that device then serves them, handing one prekey
  to a known peer each time. Only the peer itself can publish: the node must run with `--require-auth` and the request must be signed
  by the publisher's own DID, and the bundle must verify against that DID's document (4001 if not, 4002 if expired).
* **Not hardened yet:** the endpoint is open unless the node runs with `--require-auth` (then ANP-02 applies to it like to the rest);
  there is no rate limiting; a new init from a known peer device replaces its older session.
## Interoperability with other ANP implementations

Checked against the official SDK, AgentConnect (`agent-network-protocol/anp`): **Python `anp` 1.0.7** and **Rust `anp` 1.0.7**, run locally in WSL by
`scripts/interop/run.ps1` (install the Python one with `scripts/interop/setup.sh`; the Rust driver in `scripts/interop/rust-sdk` builds on its own in an isolated folder), and against the vectors it publishes (copied unmodified
into `testdata/anp-sdk/`, Apache-2.0, see `NOTICE.md`). Every row below was a real test that could have failed: five of them did
before the fixes listed after the table.

| What | Result |
|---|---|
| e1 DID documents | The SDK's `validate_did_document_binding(..., verify_proof=True)` **accepts a document this project generates**; this project **verifies documents the SDK generates** (`create_did_wba_document(did_profile="e1")`) and the SDK's signed golden document. |
| `eddsa-jcs-2022` proofs | Both forms the SDK uses are read (legacy raw-base64url without `@context`, multibase `z…` with it); this project writes the multibase form, which the SDK accepts. |
| Direct messages (P5), the key schedule: X3DH with and without a one-time prekey, `kdf_ck`, `kdf_rk`, session id | **Match the SDK's published vectors** (`p5_shared_vectors.json`). |
| Direct messages (P5 v2), the associated data | Byte-for-byte the SDK's `expected_ad_init`; the SDK's own `build_init_aad_v2` produces the same bytes for our messages. |
| Prekey bundles | The SDK's `verify_prekey_bundle_v2` **accepts our bundle** against our DID document and device manifest; we accept **the SDK's signed golden bundle** (signed by a separate device key, checked against its manifest, with every MUST enforced). |
| Application plaintext | RFC 8785 canonical form, including numbers (`1e+30`, `-0`, shortest digits), equals the SDK's. |
| **Direct messages: the first, encrypted message, both directions** | The **official Rust SDK opens a message this project sealed** (payload, floats and ids intact; a flipped ciphertext byte is refused), and **this project opens a message the Rust SDK sealed** to our bundle (a changed device id is refused). The SDK's `accept_incoming_init` and `initiate_session` are the ones used. |
| ANP-02 HTTP signatures (RFC 9421) | All **13 security vectors and 14 authority-spelling vectors** pass. A request we sign is verified by the SDK's `verify_http_message_signature` (and refused with a changed body); a request the SDK signs is verified by us. |
| The SDK's client against a node | `--require-auth` node, requests signed by the SDK: signed calls work; unsigned calls, replays, changed bodies, other paths and unknown signers get 401; the public documents stay open. 10 checks. |
| **Direct messages: whole conversations, both directions** | A full conversation with the Rust SDK **started by either side**: init, two replies, a ratchet turn, three more replies, one more answer, with the second and third batches **read out of order** by the other side. Also with a **one-time prekey** (used by both sides, refused by both when the recipient does not supply it). 4 scenarios, 6 legs each. |
| Direct messages (P5), the wire objects | `direct.send` (init and follow-up), `publish_prekey_bundle`, `get_prekey_bundle` and their results: every object in the SDK's vectors parses here, our builders reproduce them exactly, the error table (4000-4012) is the same, the vectors' negative encodings are refused; the SDK's parsers accept what we build and ours accept what its builders produce. |
| **A running node and the SDK's client** | The SDK's Rust client calls `POST /anp/direct` on a running node: fetches the bundle (and a one-time prekey) through the key service, verifies it against the node's DID document, opens a session, sends three messages and gets the agent's answers back **sealed in the session and signed with ANP-02**, with the ratchet turning. A replay, an unknown sender, a wrong device, a missing session and an unknown method are refused with the right codes. After the node **restarts** the session carries on. |
| **Resolving over HTTPS** | A CA-signed HTTPS server publishes the SDK's DID documents. A node with **no** `--allow-caller` and **no** `--direct-peer`, only `--trust-domain`, accepts the SDK's signed calls (and refuses an unpublished DID, a DID on another domain, a replay and a changed body) and chats with the Rust SDK client over direct messages, replying to the endpoint in its document. |
| **The older scheme** | The SDK's own legacy vector verifies. The Python and Go SDK clients sign in with `Authorization: DIDWba`, store the `Authentication-Info` token and use it as Bearer; a replayed header, another domain, an old timestamp, a changed nonce, a damaged token and an unknown DID are refused. Off unless `--allow-legacy-auth`. |
| **Agent description and OpenRPC** | The SDK's `fastanp` header generator's fields are all in our description (and the fixed ones identical); the SDK crawler's parser finds the A2A and OpenRPC interfaces, its converter turns every method into a model tool, `parse_openrpc` accepts the document, and a call built from it is answered. The SDK's `verify_w3c_proof` verifies our signed descriptions against our DID documents. |
| **Search agent** | A second instance with `--rate-limit 3` answers the fourth registration 429 with a `Retry-After`, shares the ration with `crawl`, and leaves `search` and `list` alone. A node behind a TLS proxy (test CA) is crawled over HTTPS; the SDK verifies the indexed description itself and reads the search agent's own description and OpenRPC document. Missing, plain-http, copied-to-another-address and changed descriptions are refused. |
| **Go SDK** | DID documents validate both ways; the SDK accepts our prekey bundle, init AAD and canonical plaintext, parses every wire object we build, and we parse every one it builds; RFC 9421 requests verify both ways; its client works against a node with ANP-02 signatures and with the older scheme. |
| **Encrypted groups: the message formats** | The SDK's shared vectors: every request, notification and result is read and rebuilt as it was, and the MLS authenticated data, the add and remove bindings, the plaintext and the member binding are byte-for-byte the SDK's. The Go SDK parses requests this project built (including a delivery with its origin context), computes the same authenticated data, and builds every request of the vectors for this project to parse. The Python SDK verifies the device binding this project signed and its origin proofs (also the one preserved on a delivery); this project verifies an origin proof the Python SDK made. |
| **Encrypted groups with MLS, through the node's group host** | `scripts/e2e-group-host.ps1`, and in the interop run: the SDK is the third device of a hosted group (it processes the welcome and a commit made by this project, sends with its own origin proof, reads this project's messages) and the controller of another. Before that, the SDK in file-based groups: the official Rust SDK (anp 1.0.7, its MLS feature, driven through its typed operations: key package, create, add, welcome, encrypt, decrypt) and this project are devices of the same groups, both ways: each validates the other's key package, binding and every leaf, joins from the other's welcome and reads its messages, with the authenticated data the spec defines for groups. |

**What broke and was fixed because of it:** (1) we rejected the SDK's own DID documents (its default proof is the legacy form);
(2) our key-agreement key was an embedded entry the SDK does not read (it is now a verification method referenced from
`keyAgreement`, like the SDK's); (3) our bundle was signed by the binding key and lacked `owner_device_id` and a
`deviceManifest`; (4) our associated data was our own subset (it is now P5 v2's `AD_init`); (5) our JCS refused floating
point numbers (it now writes numbers as ECMAScript does).

**Not verified, and why:**
* **The Python SDK and direct messages:** Python 1.0.7 does not implement P5's v2 key schedule (its `direct_e2ee/session.py` is a v1
  construction with other HKDF labels, and no `kdf_ck`), so it cannot take part in a direct-messaging conversation; the Rust SDK, which does, was used for all of it.
* **ANP-02:** a caller's DID
  document must be given to the node (`--allow-caller FILE`) or its domain trusted (`--trust-domain`, see below). The direct-messaging endpoint's
  own requests in the live test were not signed (the node was run without `--require-auth`); the node's replies were.
* **Direct messages beyond what is above:** multiple devices per DID (a node is one device), a mailbox for messages *to* an offline peer other than our own
  replies (the outbox only holds the node's answers; a published bundle is stored but the node does not relay other parties' messages),
  retiring a published bundle or its prekeys on request, attachments and other content types than `text/plain` (a JSON payload is read only for a `text` member), and encrypted groups (which need MLS).
* **Agent descriptions:** ours validate against our reading of ANP-07 and are accepted by the SDK's parsers and its verifier; the SDK's
  `openanp` generator needs FastAPI (not installed), so only the `fastanp` header generator and the crawler/client parsers were run.
* The `replay_key` values in the SDK's authority vectors (their recipe is not published) are not compared: our replay keys are
  our own.
* **The proof form, and what the TypeScript SDK found:** an `eddsa-jcs-2022` proof comes in two forms: the W3C **multibase** one (`z` + base58btc, signed
  over proof options that include the document's `@context`) and the **legacy** one (plain base64url, signed without it), which is what the Python, Go and
  TypeScript SDKs write by default. Python, Go and Rust read both; **TypeScript reads only the legacy form**, so it rejected our DID documents. DID
  documents and agent descriptions are now written in the legacy form, which every SDK reads; prekey bundles still use the multibase one (their readers read both), and both are read on input.
* Only the Python, Rust and Go SDKs at 1.0.7 and the TypeScript SDK at 0.9.5 (not Dart or Java), on one machine (the Windows host, and WSL as a second host
  for the Python and Rust ones), against fixtures or one running node at a time. The two-node deployment (a Windows node and a Linux node, `e2e-cross-os.ps1`) is
  two operating systems on **one physical machine** (WSL2), not two hosts on a network of their own. The Go SDK has no direct-messaging session (P5 v2), and the TypeScript SDK has no
  direct E2EE at all, so the session cryptography has only the Rust SDK to be checked against.

## Handles: human-readable names (ANP-04 WNS)

```text
anp-node ... --did-host agents.example.com --handle alice --handle desk      # alice.agents.example.com, desk.agents.example.com
anp-wns validate wba://Alice.Agents.Example.com
anp-wns resolve alice.agents.example.com [--base URL] [--roots ca.pem] [--allow-private]
anp-wns verify  alice.agents.example.com [--did-doc FILE]
```

* A **handle** is `<local>.<domain>`: the local part is 1 to 63 characters of `a-z0-9-` (starts and ends with a letter or digit, no
  `--`), the domain a name with at least two labels; input is case-folded and the local part ends at the first dot. `wba://<handle>`
  is its URI form. Handles carry no port.
* **The provider's side:** a node started with `--handle LOCAL` (the DID host must be a domain name; a port in it is not part of the
  handle) serves `GET /.well-known/handle/<local>`: `handle`, `did`, `status` (`active`), `binding_generation` (`"1"`: the DID is the node's
  key, so the binding never changes), `updated`, `ttl` (300) and a `profile` (`DIDSubjectProfile`: agent, display name, description) for showing only. Its DID
  document carries one `ANPHandleService` entry per handle, whose endpoint is that URL. Like the other documents it is served over plain HTTP:
  put TLS in front, on the handle's domain.
* **The client's side** resolves through the same guarded HTTPS fetcher as the DID resolver (no internal addresses, no redirects: a 301 is
  reported as *moved*, 404 *not found*, 410 *gone*), checks that the document is for the handle asked and that `binding_generation` is a
  canonical positive decimal string, and drops a `profile` that does not describe the same DID and handle.
* **A handle is believed only if the binding holds both ways:** the provider says the handle is that DID and it is `active`
  (suspended and revoked ones never verify), **and** the DID's own document has an `ANPHandleService` with an `https` endpoint on the
  provider's domain (a host that merely contains the domain, or has the domain as user info, does not count). A `did:wba` must live on the handle's
  domain (a port on the same host is fine); a `did:web` may live elsewhere but must still declare the provider.
* **A caching client** (`CachingClient`, `Cache`): an answer is kept for the provider's `ttl` (300 s when it gives none, never more than a day, 0 means do not keep), and the **highest `binding_generation` seen** for a handle is remembered for as long as the process lives: an older generation after a newer one is refused as a rollback, the same generation naming another DID is refused, and a **rotation** (the handle moving to another DID) is accepted only with a higher generation. A handle the provider says is gone or revoked is forgotten.
* **Not there:** registering handles (there is no API for it in the spec: an operator lists them with `--handle`), changing a binding (so
  `binding_generation` never rises), caching by `ttl`, handles in the search agent, and a handle resolver for domains on a non-default port (`--base` is for that).

## Agent description: what an agent offers (ANP-07)

```text
GET /agents/alice/ad.json         # signed, generated from alice's A2A agent card
anp-ad verify --ad ad.json --did-doc did.json --domain alice.example.com
```

* Fields follow the ANP-07 v1.2 page: `protocolType: "ANP"`, `protocolVersion`, `type: "AgentDescription"`, `name`, `did`,
  `url`, `created`, `securityDefinitions` + `security` (`didwba`, in the `Authorization` header), `Infomations` (spelled
  like that in the spec) and `interfaces`. The A2A endpoint is advertised as a `StructuredInterface` with
  `protocol: "A2A"`; the card's skills become `Infomations`.
* `anp-ad verify` checks the DID document first (key bound to the DID), then the description: field rules, that it names
  that DID, that the proof was made by one of its `assertionMethod` keys, the signature, and, if the proof carries a
  `domain`, that it matches where the description was fetched from. The proof is bound to the DID's host with a fresh
  `challenge` each time (the spec requires a challenge whenever a domain is given).
* No credentials in a description: a security definition that carries `password`, `token`, `key` and the like is
  rejected.
* **Divergence from the spec text, deliberately:** the only proof ANP-07 shows is ECDSA P-256 (`EcdsaSecp256r1Signature2019`)
  and it says nothing about EdDSA. These agents hold Ed25519 keys, so the proof is the standard `DataIntegrityProof` /
  `eddsa-jcs-2022` suite, the same as the DID documents. A verifier that only knows the example suite will not accept
  it. There is no JSON-LD `@context`, because the spec defines none.
* The URLs are `https://<did host>/...` as the DID rules dictate, but the node itself serves plain HTTP: put TLS in front
  of it (or test through the node's own port, as `e2e-did.ps1` does). Only the node's own description is served; a
  peer's would need to be signed by that peer.
* **OpenRPC:** the description also links an OpenRPC document (`/agents/<name>/openrpc.json`, public) for the node's A2A methods; streaming
  is left out because OpenRPC cannot describe it. The SDK's own header generator (`fastanp` `ADGenerator`) produces the same fixed
  fields as ours (`protocolType`, `protocolVersion`, `type`, `securityDefinitions`, `security`); the SDK's other generator (`openanp`)
  writes a `Product`-shaped document with a different `security` form, which is not what this project emits.
* Not covered: the spec's other interface protocols (MCP, WebRTC) and `humanAuthorization` beyond the field being accepted.

## Discovery: finding agents (ANP-08)

```text
GET /.well-known/agent-descriptions[?page=N]    # what an ANP client crawls: the descriptions under this domain
GET /discover                                    # what this node knows of its mesh, verified
anp-ad discover --url http://host:port/.well-known/agent-descriptions
```

* **Active discovery, as in the spec:** the listing is a JSON-LD `CollectionPage` (`@context` with `ad`, `did`, `@vocab`
  schema.org) whose `items` are `ad:AgentDescription` entries with `name` and `@id` (the description's URL), 20 per page,
  linked by `next` until the last page. A client follows `next` until there is none.
* **Only verified, only this domain:** an entry appears if its description verifies against its own DID document and it is
  published under this node's domain. Agents on other domains are listed by *their* domain, not by this one.
* **Offline discovery, which the spec has no notion of:** each node publishes its signed description and DID document
  together with its replicated agent card, so any node can read and verify its peers' descriptions with no network to
  their domains (`/discover`). The e2e shows bob's description verifying on alice, and carol's on bob, through the mesh.
  A replica is never served as if it were the original (the proof is bound to the original's domain), so replicated
  descriptions appear only in `/discover`, not in the well-known listing of another domain.
* **The crawler is cautious:** at most N pages (default 20), a page is never fetched twice, `next` must stay on the origin the
  crawl started from (a listing cannot send the client to an internal address), and each description is listed once.
  Items that are not `http(s)` URLs are errors.
* **Passive discovery** is the search agent below. The spec leaves registration to each search agent's own description (it defines
  no request or response), so the API is this agent's own: its OpenRPC interface.
* The spec says nothing on caching, status codes or content type; the listing is served as `application/ld+json`.
* `anp-ad discover` speaks plain http unless built with `--features tls`, and it checks the shape of each description, not
  signatures (use `anp-ad verify` with the DID document for that). The listing's URLs are the https ones the DID rules
  give, so against a node on a test port the descriptions show as unreachable: put TLS and the DID's host in front.

## Search agent (ANP-08 passive discovery)

```text
anp-search --data ./search --http-port 8800 --did-host search.example.com [--allow-domain agents.partner.com]...
           [--resolver-roots ca.pem] [--resolver-allow-private]
           [--rate-limit 10] [--rate-seconds 6] [--trust-forwarded-for] [--refresh-hours 24]
           [--store cbl|json] [--require-signed-registration [--public-origin https://search.example.com] [--allow-caller did.json]...]
```

* It is an agent of its own: a `did:wba` e1 identity, a DID document, a **signed agent description** and an OpenRPC interface at the
  usual URLs, and JSON-RPC at `POST /` with `register`, `crawl`, `refresh`, `search`, `search_handle` and `list` (parameters by name).
* **Typo tolerance:** a query word may differ from an indexed word by one edit (an insertion, a deletion, a replacement or a swap of two neighbours) from five letters, by two from nine, at 0.3 of the weight of a whole-word match: `concirege` finds `concierge`, `hotl` finds nothing.
* **Handles** (`search_handle {handle}`, `--handle-base URL` for tests): the handle is resolved through the WNS caching client (verified both ways), and the registered agents of the DID it names are returned; a handle that does not verify finds nothing and says why.
* **`register {url}`** fetches the description at `url` and indexes it only if: it was fetched over HTTPS (guarded like the DID
  resolver: no internal addresses, no redirects, size and time limits); it names the URL it came from in its own `url`; it names a
  `did:wba` e1 DID on **that same domain** (an agent describes itself on its own domain); that DID's document, fetched from the
  domain, is self-certifying; and the description's proof verifies against one of its `assertionMethod` keys and is bound to the
  domain. A changed, copied or forged description fails; nothing is believed because of who registered it.
* **`crawl {domain}`** is active discovery of a domain (its `/.well-known/agent-descriptions`, at most 10 pages, 50 descriptions,
  same origin only) and registers what verifies; the reply says what was refused and why.
* **`refresh {url}`** checks a registration again: updated if it still verifies, removed if its server says 404 or 410, kept
  (with the reason) if it cannot be fetched or no longer verifies. That is also how an agent withdraws: take the description
  down, then refresh.
* **`search {query, protocol?, limit?}`** ranks by weighted word matches: name counts most, then description, then what the agent
  offers; words are lightly stemmed (`claims`, `claim`, `claiming` meet), a query word of three letters or more also matches words that
  start with it at half weight, and a word few agents use counts more than a common one (inverse document frequency, as in BM25 without
  length normalisation). `protocol` keeps agents that speak `A2A`, `openrpc` and so on. An empty query matches nothing; `list` pages
  through everything. No synonyms or typo tolerance.
* **Rate limit:** `register`, `crawl` and `refresh` (the methods that make it fetch) are rationed per client address with a token bucket
  (`--rate-limit` requests at once, then one every `--rate-seconds`; over the limit the answer is HTTP 429 with `Retry-After` and
  JSON-RPC error -32029). `search` and `list` are not. Behind a proxy every client has the proxy's address unless it is started with
  `--trust-forwarded-for`, which believes `X-Forwarded-For` and so is only for a proxy that sets it.
* **Scheduled refresh:** every ten minutes the agent re-checks up to 50 registrations not verified for `--refresh-hours` (oldest first).
  One that still verifies is updated; one whose server says 404/410, or that no longer verifies, is **dropped** (the index holds only what
  verifies); one that could not be reached (network, resolver) is kept until it has gone seven intervals unseen.
* **Signed registration** (`--require-signed-registration`): `register`, `crawl` and `refresh` must come in a request signed with ANP-02 (RFC 9421) by a DID whose document the agent fetches and verifies (over the guarded resolver; `--allow-caller FILE` gives it documents it cannot fetch). The signature covers the method, the exact public URL (`--public-origin`, default `https://<did-host>`) and the body, is fresh for a few minutes and is accepted once. **What the signer may do:** a description is registered, refreshed or withdrawn only by the DID it names (-32031 for another), and a domain is crawled only on the word of a DID that lives on it. An unsigned request is a 401 with -32030 and nothing is fetched. `search`, `list` and `search_handle` stay open. Off by default, which is the old open registration (`--allow-domain` narrows that).
* **Where the index lives:** a **Couchbase Lite database** (`DIR/index.cblite2`, one document per entry, a change writes one document atomically; the handles live on a thread of their own, as in `anp-cblite`), or with `--store json` the single file `DIR/index.json` as before. An `index.json` left by an earlier version is moved into the database once at start (and set aside as `index.json.migrated`). Ranking still works on an in-memory copy loaded at start, so the cap of 10 000 entries and the memory use are unchanged; the database makes the writes incremental and crash-safe, not the search bigger. The agent now needs the Couchbase Lite library next to it, like the node.
* **Limits:** registration is open unless `--require-signed-registration` is set (anyone can ask it to look at a description; `--allow-domain` narrows that); the index is loaded into memory, at most 10 000 entries; a URL belongs to the DID that first registered it until it is removed.

## Negotiating a protocol: the meta-protocol (ANP-06)

```text
anp-node ... --meta-protocol a2a-json-rpc [--meta-protocol NAME=FILE]...
anp-meta ask http://host:port/anp/meta --want chat --protocol chat --protocol json-rpc-lite
```

* **Wire format**, as in the SDK: a stream of messages, each one a header byte (the top two bits are the channel: `00` meta, `01` application,
  `10` natural language, `11` verification; the low six are reserved) and a payload. A meta payload is JSON with an `action`:
  `protocolNegotiation` (`sequenceId`, `candidateProtocols`, `modificationSummary`, `status` of `negotiating`, `accepted` or `rejected`), `codeGeneration`
  (`generated` or `error`), `testCasesNegotiation`, `fixErrorNegotiation` and `naturalLanguageNegotiation` (the last three are read and written, not acted on).
  The requester proposes in round 1; every evaluation advances the round by two (requesters odd, providers even).
* **No language model.** The SDK writes and judges protocol text with an LLM and then generates code for it. Here an agent has a **catalog** of
  protocols it already implements (a name and a text). A provider accepts a proposal that equals one of them or names one (a whole word, any case),
  otherwise counters with its own; a requester proposes one of its own and accepts a counter that names something it has. At most ten rounds, an
  out-of-order round is rejected, and a late `accepted` (the SDK answers an acceptance with one of its own) is ignored. After agreement each side sends
  `codeGeneration: generated`, which here means "it is built in". A protocol that is not in the catalog cannot be agreed, however it is worded.
* **On the node** `--meta-protocol a2a-json-rpc` (built in: the node's task interface) or `NAME=FILE` offers a protocol. The messages travel over
  **HTTP** here, which the spec does not define a binding for: `POST /anp/meta` with `x-anp-session: <8-64 characters of A-Za-z0-9_->` and one framed message as
  the body; the answer holds the messages to send back, each preceded by its length in four bytes, and `x-anp-meta-state` says where it stands.
  `GET /anp/meta/protocols` lists the catalog. Sessions are kept in memory (200 at most, ten idle minutes). The node is always the provider; `anp-meta ask` is the requester.
* **WebSocket binding:** `GET /anp/meta/ws` upgrades to a WebSocket; each binary message is one framed meta message (header byte, then payload), the answers come back one binary message per frame, and one connection is one session. `anp-meta ask ws://host:port/anp/meta/ws ...` is the client (plain `ws://`; `wss://` needs a TLS terminator in front). It adds `axum`'s `ws` feature on the node and `tungstenite` in `anp-meta`.
* **Not there:** negotiation by a model (so no free-text protocols), code generation, and the test-case and error-fixing exchanges.

## Encrypted groups (ANP-09 "P6")

Three crates. **`crates/anp-group`** is the wire layer: the objects and rules of the `anp.group.e2ee.v2` profile that need no MLS implementation (below).
**`crates/anp-group-mls`** is the MLS session of one device on top of it, and **`crates/anp-group-host`** is the group host (the service that orders
membership, assigns `group_event_seq`, issues receipts and delivers), which the node serves (the last subsection).

* **Requests, results and notifications** for `group.e2ee.publish_key_package`, `get_key_package`, `create`, `add`, `remove`, `send` and the host's
  `group.e2ee.notice` and `group.incoming`, built and parsed as the SDK does: no unknown member, no `null` for an optional member, counters
  (`epoch`, `group_event_seq`) as canonical decimal strings, base64url unpadded and canonical, RFC 3339 timestamps, the group target equal to
  the state reference's group, a published key package owned by the sending device, a welcome notice addressed to the added device, a delivery whose
  ordering fields agree with its cipher object. The 14 error codes (5000 to 5013) are in `ERRORS`.
* **The canonical bytes** (RFC 8785): the MLS `authenticated_data` of a send, the submission bindings of add and remove, and the group application
  plaintext (exactly one of `text`, `payload`, `payload_b64u`; `text/plain` uses `text`, JSON types use `payload`).
* **The device binding** ties an MLS leaf to a DID: a signed object naming the DID, the device, the signing key, the leaf's signature key and a validity
  window. `binding::verify` checks it end to end given what an MLS parser found in the LeafNode (`LeafEvidence`): the DID document is the issuer's and
  valid; the device is allowed in encrypted groups in its `deviceManifest` (the group profile and its dependencies, `P6_PROFILES`) and its signing key is the binding's;
  the object proof verifies against an `assertionMethod` key; the window holds; the MLS credential identity is the DID and the leaf key is the binding's;
  the leaf carries exactly one binding extension whose data is the binding's canonical bytes, and the leaf's capabilities and the group's required
  capabilities list the extension once. Leaves of one DID must differ in device and key (`check_leaf_identity_set`).
* **The origin proof** (`origin`): a sender signs `{method, meta, body}` (RFC 8785) as an RFC 9421 proof over the covered components `@method`,
  `@target-uri` (the logical `anp://group/<did>`) and `content-digest`, with its `authentication` key; a recipient of a `group.incoming` rebuilds the
  original submission from the delivery and the preserved `origin_context` and verifies the same proof, so a host that alters the ciphertext, or
  claims another sender, is caught.
* **A draft:** the binding extension (`0xF0A1`) has no registered MLS code point, and the SDK blocks public release for that reason; so does
  `ensure_public_release_ready()` here. The node's own device manifest lists the direct-messaging profiles only (the host is not a group member).
* **Not there in this crate:** policy and roster hashes beyond carrying them, and multi-device recovery (the host is `anp-group-host`, below).

### The MLS session (`anp-group-mls`)

One `Member` is one device (a DID, a device id, its own MLS signature key), on `openmls` 0.8.0 with the suite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the SDK's configuration: basic credentials whose identity is the DID; the binding embedded in the
LeafNode as the draft extension `0xF0A1` (the leaf's capabilities list it, the group requires it); handshake messages are public messages, application
messages private; the ratchet tree travels next to the welcome; a group id is 32 random bytes.

* **Operations:** `key_package` (refuses a binding that names another leaf key), `create_group`, `add_member` (the commit's authenticated data is the group's add
  submission binding; the commit stays pending until `finalize_commit`, or `abort_commit` if the host refused it), `join` from a welcome, `process_commit`
  (the commit's authenticated data must be the binding of the submission it came with), `remove_member`, `encrypt` and `decrypt` (authenticated data = the send
  binding), `leaves` (every leaf as `LeafEvidence`, to feed `binding::verify`), and `export_state`/`import_state` to keep a device across restarts.
* **A decrypt looks at the authenticated data first.** openmls deletes a message key as it decrypts (forward secrecy), so a message refused afterwards for
  the wrong context could never be read again; checking before costs nothing. A *damaged ciphertext* does reach the decryption and uses up that message's key:
  an MLS property, and a way for whoever relays messages to make single messages unreadable (not later ones).
* **openmls panics in a debug build** when an AEAD check fails (a `debug_assert!`; in release it returns an error). Bytes from outside go through `guarded`, which turns
  that panic into an error, so a damaged message cannot take the process down.
* **Tests** (`tests/group.rs`): a group of three is created, grown by two adds (the second made by the first added member, processed by the creator), written to,
  and shrunk by a remove; every leaf is checked against its DID document after every change; wrong context, a changed message id, group state or sender, a damaged
  ciphertext, a commit with the wrong authenticated data, a replay and a removed device reading later messages are all refused; a restart in between loses nothing.
* **With the official SDK** (`tests/sdk_interop.rs`, driven by `scripts/interop/run.ps1` against `scripts/interop/rust-sdk-group`, built in WSL): *the SDK creates
  a group and adds this project*: it validates this project's key package and binding and builds the commit and welcome; this project joins, validates every leaf
  against both DID documents, reads the SDK's message and answers; the SDK decrypts the answer and validates this project's leaf. *This project creates the
  group and adds the SDK*: this project validates the SDK's binding against its DID document and its MLS leaf, adds it; the SDK's `process_welcome_v2`
  validates every leaf, it reads this project's message and answers.
* **Not there:** several devices of one DID, DID transitions and recovery after a crash; policy
  and roster hashes; and the binding extension is a draft with no registered code point, so none of this should be released as a standard.

## Signed requests (ANP-02)

```text
anp-node ... --did-host node.example.com --require-auth --public-origin https://node.example.com --allow-caller client.did.json
```

* With `--require-auth` every request must carry an RFC 9421 HTTP Message Signature (`Signature-Input`, `Signature`,
  `Content-Digest` for a body) from a DID whose document the node was given with `--allow-caller` (verified at startup:
  self-certifying). The key must be listed under `authentication`.
* The signature covers the method, the **exact public URL** and the body; `created` may be at most 60 s ahead and 300 s old; a
  signature is accepted once (nonce, or the signature itself, remembered for the window); other parameters are covered too.
  `--public-origin` is how callers address the node (behind a TLS proxy, the proxy's URL): it is configured, not read from `Host`.
* Always public: the DID document, the agent description, the agent card, the discovery listing and the demo pages (which do
  not sign, so the dashboard's data calls fail with `--require-auth`). Everything else (JSON-RPC, the mesh directory, the
  security status, link control, revocations) needs a signature. A refusal is a 401 with `WWW-Authenticate: DIDWba` and
  `Accept-Signature`.
* **The older scheme, on request** (`--allow-legacy-auth`): `Authorization: DIDWba v="1.1", did=..., nonce=..., timestamp=...,
  verification_method=..., signature=...` (an Ed25519 signature over the SHA-256 of the RFC 8785 form of
  `{nonce, timestamp, aud, did}`, `aud` being the host of `--public-origin`; version 1.0 uses `service`). A header is accepted once
  (per DID and nonce), at most 300 s old and 60 s ahead. The node answers with `Authentication-Info: access_token="...",
  token_type="Bearer", expires_in=3600` and the same token as `Authorization: Bearer`; later requests may carry just the token.
  The token is an HS256 JWT (`sub` the DID) with a secret that only this node holds and that a restart forgets. **It is weaker:**
  the header covers neither the method, the path nor the body, and a token can be replayed by whoever holds it until it
  expires, which is why it is off by default. Only HS256 is accepted (never the algorithm a token names for itself).
* Mesh peers are authenticated separately (signed documents and the connection admission above), not by this.

## DID + Biscuit
```text
anp-admin issue --root root.key --node alice --node-dir ./alice --did did:wba:alice.example.com:agents:alice:e1_... --inbox-to bob,hq --out alice.token
anp-node --name alice --data ./alice --did-host alice.example.com --root-key <ROOT_PUB> --token alice.token --tls --admit
```

* The token's authority block says `did("...")` and `check if claimed_did($d), did($d)`: it only works for a holder who proves
  that DID. The receiver reads the key from the DID document, so a stolen token on a node with another key cannot even
  start (and is refused if replayed: the signature fails and the token names someone else's DID).
* The DID comes from the node's key, so create it first: `anp-node --did-host H --print-did`, issue the token, then start
  the node. `--did-host` is applied before `--root-key` for that reason.
* Plain Biscuit tokens (no `--did`) still work for nodes without DIDs, unchanged. In DID+Biscuit mode only DID-bound tokens
  are accepted.
* Mode string in `/security`: `did+biscuit`. `--trust-did` pins are ignored when a token is used: the authority decides.

## Known limits (DID mode)

* Pure DID mode (no tokens) has no capability scoping and no revocation other than un-pinning a DID. Use it together with
  Biscuit for either. Rotating a key changes the DID (the spec has no migration protocol either): issue a new token.
* Replay: an admission assertion captured within its window could be replayed. TLS with certificate pinning is what
  protects it in transit; there is no server challenge yet.
* Canonical JSON (RFC 8785) is implemented for strings, integers, booleans, arrays and objects. Floating point numbers
  are refused rather than risk a wrong canonical form.
* The `e1` profile only; `k1_` and legacy path DIDs without a fingerprint are rejected.
* Checked against the written spec **and** against the official SDKs (Python, Rust and Go at 1.0.7, TypeScript at 0.9.5): see Interoperability above for what was run and what was not (one machine, one running node at a time, no Dart or Java).

## Build and test

Names: the flags `--direct-messaging`, `--direct-peer`, `--group-host`, `--group-open-mailboxes`, the paths `/anp/direct` and `/anp/groups`, and the
state files `direct-*.json` and `group-host.json` were called `--p5`, `--p5-peer`, `--p6-host`, `--p6-open-mailboxes`, `/anp/p5`, `/anp/p6`, `p5-*.json`
and `p6-host.json` before; the old flags and paths still work, and old state files are renamed on the first start.

Paths below are relative to this folder (`anp/`); `cargo` commands work from anywhere in the repository, which is one workspace with `a2a/` and `common/` (see the [top-level README](../README.md)). The A2A task layer (`protocol`, `executor`, `llm`, the control-room page) is the shared [`a2a-core`](../common/crates/a2a-core) crate; `anp_cblite` re-exports it under the same paths.

```text
cargo test --workspace
cargo xtask e2e-e2ee                                                       # the end-to-end encryption check, in Rust (no shell; Windows, Linux, macOS), 21 checks
cargo xtask e2e-direct                                                     # two nodes on two domains start encrypted direct conversations both ways: 27 checks
cargo xtask e2e-group                                                      # three nodes as members of an encrypted group hosted by a fourth: 33 checks
cargo xtask e2e-coldstore                                                  # the simulated store, its signed temperature log at a head office, a cut link: 27 checks
cargo xtask e2e-quotes                                                     # the store buys from eight counterparty nodes with signed quotes, limits and an approval: 35 checks
cargo xtask e2e-rescue                                                     # the store's agent runs the whole rescue on ten nodes, the duty manager approves: 30 checks
cargo xtask e2e-did                                                        # DID mode, descriptions, discovery, attackers: 33 checks
cargo xtask e2e-did-biscuit                                                # DID + Biscuit: scoping, stolen tokens, revocation: 20 checks
cargo xtask e2e | e2e-secure | e2e-biscuit                                 # two nodes: routing, streaming, cancel, outsiders, scoped tokens, revocation: 22 / 37 / 52 checks
cargo xtask e2e-field-did | e2e-hardened                                   # the field scenario on DIDs (14), the hardened setup with an attacker per layer (23)
cargo xtask all                                                            # every task above that needs no other machine
cargo xtask e2e-cross-os                                                   # a node here and one in WSL, 17 checks
cargo xtask e2e-second-host --remote-host me@box --remote-addr box         # the group host and a mesh against another host over ssh, 21 checks
cargo xtask group-host                                                        # the group host over signed HTTP against a node started by the task (the SDK part is still scripts/e2e-group-host.ps1)
cargo build -p anp-node -p anp-ad -p anp-search -p anp-wns -p anp-meta   # (anp-group, anp-group-mls and anp-group-host are libraries; the node serves the host: scripts/e2e-group-host.ps1)
pwsh scripts/e2e-did.ps1 -Exe <target>\debug\anp-node.exe              # DID mode, descriptions and discovery, 31 checks (needs anp-ad.exe)
pwsh scripts/e2e-did-biscuit.ps1 -Exe <target>\debug\anp-node.exe -Admin <target>\debug\anp-admin.exe   # DID + Biscuit, 20 checks
pwsh scripts/e2e-e2ee.ps1 -Exe <target>\debug\anp-node.exe                  # end-to-end encryption through a relay, 21 checks
pwsh scripts/e2e-field-did.ps1 -Exe <target>\debug\anp-node.exe -Admin <target>\debug\anp-admin.exe   # the field-inspection scenario on DIDs, 14 checks
pwsh scripts/interop/run.ps1 -Target <target>                                 # the official ANP SDKs against this code (WSL, scripts/interop/setup.sh first)
pwsh scripts/interop/go-sdk-build.ps1                                         # once: builds the Go SDK driver in an isolated folder (downloads the SDK); run.ps1 then includes it
pwsh scripts/interop/ts-sdk-build.ps1                                         # once: installs the TypeScript SDK in an isolated folder (npm, no install scripts); run.ps1 then includes it
bash scripts/linux-node-build.sh                                              # in WSL or on Linux: builds the node there (needs rustc, gcc and libclang)
bash scripts/interop/rust-sdk-group-build.sh                                  # in WSL: builds the program that drives the Rust SDK's MLS operations; run.ps1 then includes the encrypted-group interop and the SDK through the host
pwsh scripts/e2e-cross-os.ps1                                                 # a Windows node and a Linux node in one mesh, 18 checks
pwsh scripts/e2e-second-host.ps1 -RemoteHost me@box -RemoteAddr box            # the group host (6 live tests) and a two-node mesh against a node on another host over ssh
# the Couchbase Lite DLL (cblite.dll) must sit next to the exe; `cargo xtask` puts it there itself (the PowerShell scripts do not)
# The scripts run unchanged under PowerShell 7 (`pwsh`, 7.7 tested) and Windows PowerShell 5.1; all eight e2e scripts, the second-host run and the SDK interop run pass under 7.
# Paths come from `scripts/common.ps1`: binaries and scratch folders are under `$env:CARGO_TARGET_DIR` (or `<repo>\target`, cargo's default), so no script names a drive or a user; `-Exe`, `-Admin`, `-Work`, `-Target` still override. The scripts are still Windows-host oriented (`wsl` for the Linux side, `.exe` in a few places of the interop run), and the interop run's Linux half needs WSL.
```

Everything else (LiteRT agents, the Tauri app in `src-tauri`, the Biscuit scripts) is carried over from the A2A project ([`../a2a`](../a2a/README.md)) and works as
it did there, except the field-inspection demo, which now runs on DIDs (`scripts/demo-field-inspection.sh`, needs Linux and a model file).
The Tauri app has not been rebuilt or re-run in this phase. Crates were renamed `a2a-*` to `anp-*`.

## Trusting a domain (HTTPS DID resolver)

```text
anp-node ... --require-auth --public-origin https://node.example.com --trust-domain agents.partner.com
             [--resolver-roots private-ca.pem] [--resolver-allow-private]
```

* A DID on a trusted domain (`did:wba:agents.partner.com:...` or `did:web:agents.partner.com:...`) is accepted as an ANP-02 caller
  or a direct-messaging peer once its document has been **fetched from that domain over HTTPS and verified**. No `--allow-caller` file, no
  `--direct-peer`: what vouches for the DID is the domain. For direct messages the reply endpoint is the document's `ANPMessageService`.
* **Trusting a domain means trusting everyone who can publish a document there.** Use it for a domain you would let act for you.
* Checks: HTTPS only, web PKI roots (plus `--resolver-roots`, a private CA); no redirects; size and time limits; the document
  must verify (a `did:wba` e1 document must match the DID's key thumbprint) and its `id` must equal the DID; results are cached
  (positive, short negative, bounded). A body that ends without a length and without a TLS `close_notify` is treated as
  truncated and refused.
* **SSRF guard:** every address the name resolves to is checked at connect time, and loopback, private, link-local, CGNAT,
  multicast and similar ranges are refused, so DNS rebinding cannot reach them. `--resolver-allow-private` lifts that for a
  closed network or tests.
* Not there: DNS-over-HTTPS or DNSSEC, certificate revocation checks. `did:web` is **not self-certifying** (the domain alone
  vouches for the key), which is why it is only accepted from trusted domains.

### The group host (`anp-group-host`, served by the node with `--group-host`)

`anp-node --group-host --did-host groups.example --require-auth` serves a host at `POST /anp/groups` (JSON-RPC). The host is **not a member** of any group and holds
no group secret: it cannot read a message and does not process a commit. What it does:

* **A key service** (`publish_key_package`, `get_key_package`): a package is checked when published (binding against the device's DID document and against the
  MLS leaf inside it) and handed out once.
* **Groups.** `POST /anp/groups/provision` (this project''s own method) makes a **group DID** on the host''s domain and keeps its key; the document is public at
  `/groups/<name>/<fingerprint>/did.json`. `create`, then `add` and `remove` (only the group''s controller, its creator), `send` (only members, in the current
  epoch). Every submission carries the sender''s **origin proof**, verified against the sender''s DID document; a commit must be framed in the current epoch for the
  crypto group and carry the **submission binding as its authenticated data**; a membership change **names the state version it creates** (create makes version 1,
  each add or remove the next one; the SDK''s notice check requires the same reference in the binding and the notice), a send names the current one.
  The epoch advances by one per change and `group_event_seq` per message.
* **Delivery.** Each accepted change or message becomes a notification in the mailbox of every device that must see it: a `group.e2ee.notice` (welcome for the added
  device, commit for the others, removal for the removed one) or a `group.incoming` (the ciphertext with the sender''s preserved proof, so a recipient re-verifies it).
  A device collects its mailbox with `group.e2ee.pull` (this project''s own method: the spec leaves the transport open), acknowledging by id. With `--require-auth` the
  caller (ANP-02 signature) must be the device it pulls for; `--group-open-mailboxes` waives that (tests, and a node on a trusted network).
* **Receipts.** `group_receipt` is an object proof by the **group DID''s key** over what was accepted; its `payload_digest` is the origin proof''s `contentDigest`.
* **State** (groups, members, mailboxes, group keys) is kept in `<data>/group-host.json`.
* **Checked** by `scripts/e2e-group-host.ps1` (a node with signed HTTP): three devices of this project create a group, add two more (a device that is not the controller is refused,
  5003), write, read each other''s messages with receipts verified against the group''s document, cannot read each other''s mailboxes, and a device is removed and told so.
  Then, in `scripts/interop/run.ps1`, **the official Rust SDK as the third device** (it processes its welcome and *the commit this project made* through
  `process_notice_v2`, sends a message whose origin proof it made, reads a message of this project''s through `verify_group_incoming_origin_proof_v2` and `decrypt_v2`),
  and **as the controller of another group** (its create, add and send go through the host and this project joins and reads).
* **Removal of the SDK:** this project removes the SDK device through the host; the SDK processes its own removal (`process_notice_v2` reports `self_removed`), will not encrypt for that group any more, and the host refuses a send signed by it.
* **Two devices of one DID** (each with its own signing and key-agreement key in the document, which the SDK requires) are both members of a hosted group; the second is not the controller (5003), and its message is read by the others. Mailboxes are per DID and device, and with signed requests a DID may pull any of its devices' mailboxes.
* **Two SDK devices of one DID** (the driver's `kpextra` adds a second device with its own signing and key-agreement key to the SDK's document) are both members of a group controlled by this project: each processes its welcome, the first processes the commit that added its sibling, the second sends with an origin proof by its own key, and this project and the first device read it.
* **Push, two ways:** `group.e2ee.pull` takes `wait_ms` (at most 30000): the request is held until something is delivered (a pull that finds mail answers at once); `anp-cblite`'s group host wakes waiters after every accepted change. And a **WebSocket channel** per device, `GET /anp/groups/ws?did=DID&device=ID`: what waits for the device is sent at once and what arrives later as it arrives, one text frame `{"id", "notification"}` each (the objects `pull` returns); the device answers `{"ack": [ids]}` and those are dropped. With `--require-auth` the upgrade request must be signed (ANP-02) by that DID, exactly as for a pull: another DID, or no signature, gets 401. A device that is offline simply finds its mail on the next connect or pull.
* **Roster and policy hashes** (`anp_group::state`). `group_state_ref` has two optional members, `policy_hash` and `roster_hash`, and the spec does not say what they hash (the SDK's vectors use a placeholder). This project defines them: `roster_hash` = `sha-256:` + hex of SHA-256 over the RFC 8785 form of the members (`{did, device_id, leaf_key}`, sorted), **for the state the reference points at** (so a membership change that creates version N+1 carries the roster after it); `policy_hash` the same over `{max_members, membership_change: "controller-only", profile}`. **Nothing is required of a peer that does not use them**: a reference without the hashes is accepted as before (the SDK as a controller and a member, which knows nothing of them, still works), one that carries them must carry the right ones (`add`, `remove` and `send` answer 5005 otherwise), and the host puts the reference in its notices and results exactly as the controller bound it.
* **A policy the host enforces:** `POST /anp/groups/provision {"name", "max_members"}` (at least 1) gives a group a cap; an add past it is refused (JSON-RPC -32010, this project's own code: the spec's error table has none for it). Only the controller changes membership, as before. The cap is kept with the group's key and survives a restart.
* **The group state, signed:** `group.e2ee.state` (`params: {meta: {sender_did, sender_device_id}, group_did}`; this project's own method, members only, 5013 for anyone else, and with `--require-auth` the HTTP caller must be that DID) returns version, epoch, last event number, controller, `max_members`, both hashes and the member list, **signed by the group DID's key**; a client recomputes the roster hash from what it knows and compares.
* **Not there:** a policy beyond the member cap (no per-member roles, no invitations), the hashes inside the receipts (the SDK's receipt check is strict, so they travel in `group.e2ee.state` instead), a host that is a member itself, and any
  authentication of `provision` beyond the node''s `--require-auth` (anyone with a signature the node accepts can ask for a group DID).
* **Another machine:** `scripts/e2e-second-host.ps1` runs the host's live tests (HTTP, the push channel, hashes, the cap, two devices of one DID, a held pull) against a node on a separate host over ssh, **and a two-node mesh** (the `e2e-cross-os.ps1` scenario: DIDs and tokens bound to them, TLS with a pinned certificate, admission, encryption, tasks both ways, signed descriptions verified, scoping, an unauthorised node refused, a restart). It has been **run, with the second host being the WSL2 VM on the same PC**, reached over its own IP: 21 checks (the host's 6 live tests count as one). **Not run on a physically separate machine.** What the mesh run showed: the listener's TLS certificate used to be made again at every start, so a dialler that had pinned it could not reconnect after a restart. The node now keeps its TLS identity in its data folder (`tls.key.pem`, an RSA key made once and readable by the owner only, and `tls.cert.pem`, the self-signed certificate, valid ten years and renewed from the same key within a month of its end or when the node's name changes): the certificate is the same after a restart and the dialler reconnects by itself, which the script checks. The replicated agent list keeps showing a peer whose link is down, so only a task over the link proves it is up.
## Next

1. **Encrypted groups, next:** a push channel that also works over `wss://` (the node serves plain HTTP; put TLS in front), richer policy (roles, invitations), and the hashes in a form the SDK's strict receipt check would take. The Go and Python SDKs have P5 v2 *objects* (bundle, associated data, plaintext, wire: checked against this project in `run.ps1`) but no v2 session, so only the Rust SDK has one to compare against.
2. **A physically separate second host:** `scripts/e2e-second-host.ps1` (the group host and the mesh) has passed against the WSL2 VM, but nothing has run across two machines, with a real network between them and two clocks. Also not done: the official SDK agents running on the other host (the SDK driver is still driven from this machine's WSL).
3. **The remaining SDKs:** Dart and Java, and the `openanp` description generator (needs FastAPI), to compare against. None of them has been downloaded.
4. **WNS:** handle registration (the spec has no API for it) and a cache that survives restarts.
5. **Meta-protocol:** `wss://` in the client, negotiation by a language model for free-text protocols, and the test-case and error-fixing exchanges.
6. **Search agent:** synonyms, and ranking inside the database (the index is still loaded into memory to rank, so it is bounded at 10 000 entries).
7. **The Rust runner:** every end-to-end script has a `cargo xtask` twin with the same checks and the same counts (`e2e` 22, `e2e-secure` 37, `e2e-biscuit` 52, `e2e-did` 33, `e2e-did-biscuit` 20, `e2e-e2ee` 21, `e2e-field-did` 14, `e2e-hardened` 23, `e2e-cross-os` 17, `e2e-second-host` 21, and `group-host`); the PowerShell scripts stay beside them. Not ported: the SDK interop run (`scripts/interop/run.ps1`) and the official-SDK part of `e2e-group-host.ps1`: they are orchestration around about twenty Python and shell drivers that run in WSL, and the drivers hold the checks, so a Rust wrapper would change nothing. The harness is `xtask/src/harness.rs` (nodes, JSON-RPC, SSE, tally) and `xtask/src/remote.rs` (WSL or ssh).