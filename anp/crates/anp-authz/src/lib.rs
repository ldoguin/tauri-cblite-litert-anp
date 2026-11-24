//! Scoped, expiring, delegable credentials for mesh nodes, as
//! [Biscuit](https://www.biscuitsec.org) tokens.
//!
//! One **authority** (a root key pair, kept offline by an administrator) issues
//! each node a token that says *who it is* and *what it may do*:
//!
//! ```text
//! node("tablet-7");                    // the node id
//! node_key("<base64 public key>");     // binds the token to the node's own signing key
//! right("agents", "own");              // may publish its own agent card
//! right("tasks",  "own");              // may write the state of tasks it runs
//! right("telemetry", "own");           // may publish its own sensor readings
//! right("rescue", "own");              // may publish its own rescue records
//! right("approvals", "own");           // may sign an approval (whether it counts is the store's call)
//! right("inbox",  "branch-1");         // may send commands addressed to branch-1 ("*" = anyone)
//! check if time($t), $t < 2026-12-01T00:00:00Z;   // expiry
//! ```
//!
//! Every node verifies tokens with only the authority's *public* key, so
//! verification works offline. A token can be narrowed by anyone who holds it,
//! without contacting the authority ([`attenuate`]); it can never be widened.
//!
//! A token is a bearer credential, so it is always paired with a signature by
//! the key it names: stealing the token alone is useless. Revocation is not part
//! of Biscuit; [`Authorized::revocation_ids`] exposes the ids so the caller can
//! keep a deny-list.

use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use biscuit_auth::{
    builder::{Algorithm, AuthorizerBuilder, BlockBuilder},
    AuthorizerLimits, Biscuit, KeyPair,
};

/// The authority's public key type, for callers that hold one.
pub use biscuit_auth::PublicKey;

/// A name that is safe to splice into Datalog: no quotes, no whitespace.
/// A `did:wba` identifier, safe to put inside a Datalog string (no quotes, no whitespace).
fn did_ok(s: &str) -> bool {
    s.starts_with("did:wba:") && s.len() <= 256 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '%'))
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

fn key_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

fn target_ok(s: &str) -> bool {
    s == "*" || ident_ok(s)
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a base64 Ed25519 public key (the authority's, for verifying tokens).
pub fn parse_public_key(b64: &str) -> Result<PublicKey, String> {
    let raw = B64.decode(b64.trim()).map_err(|e| format!("public key: {e}"))?;
    PublicKey::from_bytes(&raw, Algorithm::Ed25519.into()).map_err(|e| format!("public key: {e}"))
}

/// What a node is allowed to do.
#[derive(Debug, Clone)]
pub struct Grant {
    pub node: String,
    /// The node's own signing key (base64), e.g. the contents of its `node.pub`.
    pub node_key_b64: String,
    /// Nodes it may send commands to; `"*"` means any.
    pub inbox_targets: Vec<String>,
    pub expires: Option<SystemTime>,
    /// Bind the token to this `did:wba` identity: it then only works for a node that proves that DID (the DID's
    /// own key must equal `node_key`, so the token, the DID and the key all name the same holder).
    pub did: Option<String>,
    /// What the holder may commit its principal to (an agent that buys on its owner's behalf); `None`: nothing.
    pub spend: Option<Spend>,
}

/// Delegated spending authority, carried in the authority block of a token, so a counterparty can check any
/// commitment the holder signs against it ([`authorize_commitment`]).
///
/// ```text
/// spend_cap("EUR", 600000);          // at most 6,000.00 EUR per commitment, in minor units (cents)
/// spend_category("transport");       // what it may buy (repeatable)
/// spend_for("store-0412");           // the site it acts for ("*" = any)
/// ```
///
/// The cap is per commitment: a counterparty sees one commitment, not the holder's other ones. A total over
/// several commitments is the holder's own ledger to keep; the counterparty check bounds the damage of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spend {
    /// ISO 4217 code, e.g. `EUR`.
    pub currency: String,
    /// The largest single commitment, in the currency's minor units (cents for EUR).
    pub cap_minor: u64,
    /// The categories of purchase allowed, e.g. `transport`, `storage`. At least one.
    pub categories: Vec<String>,
    /// The site or account the holder acts for; `None` = any.
    pub on_behalf_of: Option<String>,
}

fn currency_ok(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

fn spend_facts(s: &Spend) -> Result<String, String> {
    if !currency_ok(&s.currency) {
        return Err(format!("currency '{}' must be a three-letter ISO 4217 code such as EUR", s.currency));
    }
    if s.cap_minor > i64::MAX as u64 {
        return Err("spending cap too large".into());
    }
    if s.categories.is_empty() {
        return Err("a spending grant names at least one category".into());
    }
    if let Some(bad) = s.categories.iter().find(|c| !ident_ok(c)) {
        return Err(format!("category '{bad}' must be 1-64 characters of [A-Za-z0-9._:-]"));
    }
    if let Some(bad) = s.on_behalf_of.as_ref().filter(|w| !ident_ok(w)) {
        return Err(format!("'{bad}' must be 1-64 characters of [A-Za-z0-9._:-]"));
    }
    let mut src = format!("spend_cap(\"{}\", {});\n", s.currency, s.cap_minor);
    for c in &s.categories {
        src.push_str(&format!("spend_category(\"{c}\");\n"));
    }
    src.push_str(&format!("spend_for(\"{}\");\n", s.on_behalf_of.as_deref().unwrap_or("*")));
    Ok(src)
}

/// The administrator's root key pair. Keep the private half offline.
pub struct Authority {
    root: KeyPair,
}

impl Authority {
    pub fn generate() -> Authority {
        Authority { root: KeyPair::new() }
    }

    pub fn from_private_b64(b64: &str) -> Result<Authority, String> {
        let raw = B64.decode(b64.trim()).map_err(|e| format!("root key: {e}"))?;
        let root = KeyPair::from_bytes(&raw, Algorithm::Ed25519.into()).map_err(|e| format!("root key: {e}"))?;
        Ok(Authority { root })
    }

    pub fn private_b64(&self) -> String {
        B64.encode(&self.root.private().to_bytes()[..])
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.root.public().to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        self.root.public()
    }

    /// Issue a token (base64) for `grant`.
    pub fn issue(&self, grant: &Grant) -> Result<String, String> {
        if !ident_ok(&grant.node) {
            return Err(format!("node id '{}' must be 1-64 characters of [A-Za-z0-9._:-]", grant.node));
        }
        if !key_ok(&grant.node_key_b64) {
            return Err("node key is not valid base64".into());
        }
        if let Some(bad) = grant.inbox_targets.iter().find(|t| !target_ok(t)) {
            return Err(format!("inbox target '{bad}' must be '*' or a node id"));
        }
        if let Some(d) = &grant.did {
            if !did_ok(d) {
                return Err(format!("'{d}' is not a did:wba identifier"));
            }
        }
        let mut src = format!(
            "node(\"{}\");\nnode_key(\"{}\");\nright(\"agents\", \"own\");\nright(\"tasks\", \"own\");\nright(\"telemetry\", \"own\");\nright(\"rescue\", \"own\");\nright(\"approvals\", \"own\");\nright(\"tokens\", \"own\");\n",
            grant.node, grant.node_key_b64
        );
        for t in &grant.inbox_targets {
            src.push_str(&format!("right(\"inbox\", \"{t}\");\n"));
        }
        if let Some(d) = &grant.did {
            // A DID-bound token is useless to anyone who cannot prove the DID.
            src.push_str(&format!("did(\"{d}\");\ncheck if claimed_did($d), did($d);\n"));
        }
        if let Some(s) = &grant.spend {
            src.push_str(&spend_facts(s)?);
        }
        if let Some(e) = grant.expires {
            src.push_str(&format!("check if time($t), $t < {};\n", rfc3339(e)));
        }
        let token = Biscuit::builder()
            .code(&src)
            .map_err(|e| format!("building token: {e}"))?
            .build(&self.root)
            .map_err(|e| format!("signing token: {e}"))?;
        token.to_base64().map_err(|e| e.to_string())
    }
}

/// Further limits to put on a token. Applying them can only reduce what the
/// token allows.
#[derive(Debug, Clone, Default)]
pub struct Attenuation {
    pub expires: Option<SystemTime>,
    /// Only these inbox targets stay allowed.
    pub inbox_targets: Option<Vec<String>>,
    /// Commitments may be at most this much (minor units), whatever the token's own cap says.
    pub spend_cap_minor: Option<u64>,
    /// Only these categories of purchase stay allowed.
    pub spend_categories: Option<Vec<String>>,
    /// Only commitments for this site stay allowed.
    pub spend_for: Option<String>,
}

/// Narrow `token_b64` by appending a block. Needs only the authority's *public*
/// key, so any holder can delegate a reduced token offline.
pub fn attenuate(token_b64: &str, root: &PublicKey, a: &Attenuation) -> Result<String, String> {
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;
    let mut src = String::new();
    if let Some(e) = a.expires {
        src.push_str(&format!("check if time($t), $t < {};\n", rfc3339(e)));
    }
    if let Some(ts) = &a.inbox_targets {
        if let Some(bad) = ts.iter().find(|t| !target_ok(t)) {
            return Err(format!("inbox target '{bad}' must be '*' or a node id"));
        }
        let set = ts.iter().map(|t| format!("\"{t}\"")).collect::<Vec<_>>().join(", ");
        src.push_str(&format!(
            "check if collection($c), $c != \"inbox\" or collection(\"inbox\"), target($t), {{{set}}}.contains($t);\n"
        ));
    }
    // spending limits only constrain commitments ("commit"): documents and admission pass them by
    if let Some(cap) = a.spend_cap_minor {
        if cap > i64::MAX as u64 {
            return Err("spending cap too large".into());
        }
        src.push_str(&format!("check if collection($c), $c != \"commit\" or commit_amount($a), $a <= {cap};\n"));
    }
    if let Some(cs) = &a.spend_categories {
        if cs.is_empty() {
            return Err("give at least one category to keep".into());
        }
        if let Some(bad) = cs.iter().find(|c| !ident_ok(c)) {
            return Err(format!("category '{bad}' must be 1-64 characters of [A-Za-z0-9._:-]"));
        }
        let set = cs.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        src.push_str(&format!("check if collection($c), $c != \"commit\" or commit_category($k), {{{set}}}.contains($k);\n"));
    }
    if let Some(w) = &a.spend_for {
        if !ident_ok(w) {
            return Err(format!("'{w}' must be 1-64 characters of [A-Za-z0-9._:-]"));
        }
        src.push_str(&format!("check if collection($c), $c != \"commit\" or commit_for(\"{w}\");\n"));
    }
    if src.is_empty() {
        return Ok(token_b64.to_string());
    }
    let block = BlockBuilder::new().code(&src).map_err(|e| format!("building block: {e}"))?;
    token.append(block).map_err(|e| e.to_string())?.to_base64().map_err(|e| e.to_string())
}

/// What a document claims, to be checked against the author's token.
#[derive(Debug, Clone, Copy)]
pub struct Claim<'a> {
    /// The document's author.
    pub node: &'a str,
    /// The public key (base64) the document's signature will be checked with.
    pub key_b64: &'a str,
    /// `agents`, `tasks` or `inbox`.
    pub collection: &'a str,
    /// For `inbox`: the node the command is addressed to.
    pub target: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct Authorized {
    /// Hex revocation ids of every block of the token, for a deny-list.
    pub revocation_ids: Vec<String>,
}

/// Check that `token_b64` was issued by `root`, has not expired, and lets the
/// claimed node write the claimed kind of document with the claimed key.
pub fn authorize(token_b64: &str, root: &PublicKey, c: &Claim) -> Result<Authorized, String> {
    authorize_with(token_b64, root, c, None)
}

/// [`authorize`], for a node that proves a DID. With `Some(did)` the token must be bound to exactly that DID
/// (see [`Grant::did`]); with `None` a DID-bound token is refused, because the holder has not shown the DID.
pub fn authorize_with(token_b64: &str, root: &PublicKey, c: &Claim, did: Option<&str>) -> Result<Authorized, String> {
    if did.map_or(false, |d| !did_ok(d)) {
        return Err("malformed DID".into());
    }
    if !ident_ok(c.node) || !key_ok(c.key_b64) || !ident_ok(c.collection) || c.target.map_or(false, |t| !ident_ok(t)) {
        return Err("malformed claim".into());
    }
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;

    let mut src = format!(
        "claimed_node(\"{}\");\nclaimed_key(\"{}\");\ncollection(\"{}\");\n",
        c.node, c.key_b64, c.collection
    );
    if let Some(t) = c.target {
        src.push_str(&format!("target(\"{t}\");\n"));
    }
    if let Some(d) = did {
        // the token must carry this very DID (an unbound token does not satisfy this)
        src.push_str(&format!("claimed_did(\"{d}\");\ncheck if did($d), claimed_did($d);\n"));
    }
    src.push_str(
        r#"
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 collection("inbox"), target($t), node($t);
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 collection("inbox"), target($t), right("inbox", $t);
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 collection("inbox"), right("inbox", "*");
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 collection($c), $c != "inbox", right($c, "own");
        deny if true;
        "#,
    );
    // Biscuit's default time budget is 1 ms, which a slow or busy device exceeds, rejecting
    // perfectly valid tokens at random. 100 ms still bounds the work a hostile token can cause.
    let limits = AuthorizerLimits { max_time: Duration::from_millis(100), ..Default::default() };
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(limits)
        .time()
        .code(&src)
        .map_err(|e| format!("authorizer: {e}"))?
        .build(&token)
        .map_err(|e| format!("authorizer: {e}"))?;
    authorizer.authorize().map_err(|e| format!("token does not allow this: {e}"))?;

    Ok(Authorized { revocation_ids: token.revocation_identifiers().iter().map(|id| hex(id)).collect() })
}

// ── Commitments ─────────────────────────────────────────────────────────────

/// A commitment the holder of a token signs on its principal's behalf (an order, an acceptance of a quote).
#[derive(Debug, Clone, Copy)]
pub struct Commitment<'a> {
    /// Who signs it: the token's node name and the key its signature is checked with.
    pub node: &'a str,
    pub key_b64: &'a str,
    /// The amount, in the currency's minor units (cents for EUR).
    pub amount_minor: u64,
    pub currency: &'a str,
    /// What it buys, e.g. `transport`.
    pub category: &'a str,
    /// The site or account it is for.
    pub on_behalf_of: &'a str,
}

/// May the holder of `token_b64` sign commitment `c`? The token must come from `root`, be unexpired, name the
/// signer and its key (and, with `Some(did)`, be bound to that DID), carry a spending grant in the same currency
/// whose cap is at least the amount, allow the category and the site, and pass every narrowing block added since.
///
/// This is what a counterparty runs before it accepts an order: the holder cannot talk it past the limit.
/// Revocation is the caller's deny-list, as for documents ([`Authorized::revocation_ids`]).
pub fn authorize_commitment(token_b64: &str, root: &PublicKey, c: &Commitment, did: Option<&str>) -> Result<Authorized, String> {
    authorize_commitment_at(token_b64, root, c, did, SystemTime::now())
}

/// [`authorize_commitment`] as of time `at` instead of now: was the commitment within the holder's authority when it
/// was made? This is how a record is audited later, after the token has expired.
pub fn authorize_commitment_at(token_b64: &str, root: &PublicKey, c: &Commitment, did: Option<&str>, at: SystemTime) -> Result<Authorized, String> {
    if did.map_or(false, |d| !did_ok(d)) {
        return Err("malformed DID".into());
    }
    if !ident_ok(c.node) || !key_ok(c.key_b64) || !currency_ok(c.currency) || !ident_ok(c.category) || !ident_ok(c.on_behalf_of) {
        return Err("malformed commitment".into());
    }
    if c.amount_minor > i64::MAX as u64 {
        return Err("amount too large".into());
    }
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;
    let mut src = format!(
        "time({});\nclaimed_node(\"{}\");\nclaimed_key(\"{}\");\ncollection(\"commit\");\ncommit_amount({});\ncommit_currency(\"{}\");\ncommit_category(\"{}\");\ncommit_for(\"{}\");\n",
        rfc3339(at), c.node, c.key_b64, c.amount_minor, c.currency, c.category, c.on_behalf_of
    );
    if let Some(d) = did {
        src.push_str(&format!("claimed_did(\"{d}\");\ncheck if did($d), claimed_did($d);\n"));
    }
    src.push_str(
        r#"
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 commit_currency($cur), spend_cap($cur, $cap), commit_amount($a), $a <= $cap,
                 commit_category($cat), spend_category($cat),
                 commit_for($s), spend_for($s);
        allow if node($n), claimed_node($n), node_key($k), claimed_key($k),
                 commit_currency($cur), spend_cap($cur, $cap), commit_amount($a), $a <= $cap,
                 commit_category($cat), spend_category($cat),
                 spend_for("*");
        deny if true;
        "#,
    );
    let limits = AuthorizerLimits { max_time: Duration::from_millis(100), ..Default::default() };
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(limits)
        .code(&src)
        .map_err(|e| format!("authorizer: {e}"))?
        .build(&token)
        .map_err(|e| format!("authorizer: {e}"))?;
    authorizer.authorize().map_err(|e| format!("token does not allow this commitment: {e}"))?;
    Ok(Authorized { revocation_ids: token.revocation_identifiers().iter().map(|id| hex(id)).collect() })
}

/// Parse an amount such as `7200`, `7200.5` or `7200.50` into minor units (two decimals).
pub fn parse_amount_minor(v: &str) -> Result<u64, String> {
    let v = v.trim();
    let (whole, frac) = v.split_once('.').unwrap_or((v, ""));
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) || frac.len() > 2 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("'{v}' is not an amount like 7200 or 7200.50"));
    }
    let w: u64 = whole.parse().map_err(|_| format!("'{v}' is too large"))?;
    let f: u64 = format!("{frac:0<2}").parse().unwrap_or(0);
    w.checked_mul(100).and_then(|x| x.checked_add(f)).filter(|x| *x <= i64::MAX as u64).ok_or_else(|| format!("'{v}' is too large"))
}

// ── Revocation ──────────────────────────────────────────────────────────────

/// A signed instruction from the authority: "stop accepting the token with this id".
///
/// It is an ordinary replicated document, but its proof is the authority's own
/// signature, not any node's: every node that syncs it can check it with only the
/// authority's public key, and no node can forge one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// Hex revocation id (see [`Authorized::revocation_ids`]).
    pub revoked: String,
    pub reason: String,
    /// Milliseconds since the epoch, when it was issued.
    pub issued_at: i64,
    /// Base64 Ed25519 signature by the authority.
    pub sig: String,
}

fn revocation_message(revoked: &str, issued_at: i64) -> String {
    format!("a2a-revocation/v1\n{revoked}\n{issued_at}")
}

fn hex_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Revocation {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "revoked": self.revoked, "reason": self.reason, "issuedAt": self.issued_at, "sig": self.sig })
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Revocation, String> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
        Ok(Revocation {
            revoked: s("revoked").ok_or("revocation: missing 'revoked'")?,
            reason: s("reason").unwrap_or_default(),
            issued_at: v.get("issuedAt").and_then(|x| x.as_i64()).ok_or("revocation: missing 'issuedAt'")?,
            sig: s("sig").ok_or("revocation: missing 'sig'")?,
        })
    }
}

impl Authority {
    fn signing_key(&self) -> Result<SigningKey, String> {
        let seed = self.root.private().to_bytes();
        let bytes: [u8; 32] = seed[..].try_into().map_err(|_| "root key is not a 32-byte Ed25519 seed".to_string())?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Revoke the token `token_b64` (and so every token derived from it by attenuation).
    pub fn revoke(&self, token_b64: &str, reason: &str) -> Result<Revocation, String> {
        let token = Biscuit::from_base64(token_b64, self.root.public()).map_err(|e| format!("not one of this authority's tokens: {e}"))?;
        let ids = token.revocation_identifiers();
        let first = ids.first().ok_or("token has no revocation id")?;
        self.revoke_id(&hex(first), reason)
    }

    /// Revoke by hex id (the authority block's id kills every attenuated copy too).
    pub fn revoke_id(&self, id: &str, reason: &str) -> Result<Revocation, String> {
        if !hex_ok(id) {
            return Err("a revocation id is hex".into());
        }
        let id = id.to_lowercase();
        let issued_at = chrono::Utc::now().timestamp_millis();
        let sig = self.signing_key()?.sign(revocation_message(&id, issued_at).as_bytes());
        Ok(Revocation { revoked: id, reason: reason.chars().take(200).collect(), issued_at, sig: B64.encode(sig.to_bytes()) })
    }
}

/// Is `rev` signed by the authority whose public key is `root`?
pub fn verify_revocation(rev: &Revocation, root: &PublicKey) -> Result<(), String> {
    if !hex_ok(&rev.revoked) {
        return Err("a revocation id is hex".into());
    }
    let key_bytes: [u8; 32] = root.to_bytes().as_slice().try_into().map_err(|_| "authority key is not Ed25519".to_string())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| e.to_string())?;
    let raw = B64.decode(&rev.sig).map_err(|_| "signature encoding".to_string())?;
    let arr: [u8; 64] = raw.try_into().map_err(|_| "signature length".to_string())?;
    key.verify(revocation_message(&rev.revoked.to_lowercase(), rev.issued_at).as_bytes(), &Signature::from_bytes(&arr))
        .map_err(|_| "not signed by the authority".to_string())
}
/// Connection-level admission: is `token_b64` issued by `root`, unexpired, and for `node`?
///
/// It cannot check the key binding (there is no signature at connection time), so it is
/// admission control, not authentication; every document is still signed and checked.
pub fn admit(token_b64: &str, root: &PublicKey, node: &str) -> Result<Authorized, String> {
    admit_with(token_b64, root, node, None)
}

/// [`admit`] for a node that proves a DID (see [`authorize_with`]).
pub fn admit_with(token_b64: &str, root: &PublicKey, node: &str, did: Option<&str>) -> Result<Authorized, String> {
    if !ident_ok(node) {
        return Err("malformed node name".into());
    }
    if did.map_or(false, |d| !did_ok(d)) {
        return Err("malformed DID".into());
    }
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;
    // `collection("admission")`: the checks a narrowing block adds for one kind of document (inbox targets,
    // spending limits) are written "collection is not X, or ...", so they let an admission through
    let mut src = format!("claimed_node(\"{node}\");\ncollection(\"admission\");\n");
    if let Some(d) = did {
        src.push_str(&format!("claimed_did(\"{d}\");\ncheck if did($d), claimed_did($d);\n"));
    }
    src.push_str("allow if node($n), claimed_node($n);\ndeny if true;\n");
    let limits = AuthorizerLimits { max_time: Duration::from_millis(100), ..Default::default() };
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(limits)
        .time()
        .code(&src)
        .map_err(|e| format!("authorizer: {e}"))?
        .build(&token)
        .map_err(|e| format!("authorizer: {e}"))?;
    authorizer.authorize().map_err(|e| format!("token does not admit this node: {e}"))?;
    Ok(Authorized { revocation_ids: token.revocation_identifiers().iter().map(|id| hex(id)).collect() })
}
/// The revocation ids of a token issued by `root` (hex, one per block), for a caller that keeps a deny-list. Errors when the token is not
/// from that authority; says nothing about expiry or what the token allows.
pub fn token_revocation_ids(token_b64: &str, root: &PublicKey) -> Result<Vec<String>, String> {
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;
    Ok(token.revocation_identifiers().iter().map(|id| hex(id)).collect())
}

/// A human-readable dump of a token (blocks, facts, checks) and its revocation ids.
pub fn inspect(token_b64: &str, root: &PublicKey) -> Result<String, String> {
    let token = Biscuit::from_base64(token_b64, *root).map_err(|e| format!("invalid token: {e}"))?;
    let ids: Vec<String> = token.revocation_identifiers().iter().map(|id| hex(id)).collect();
    Ok(format!("{token}\nrevocation ids:\n  {}", ids.join("\n  ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "UIB1fyVV0tiX2wAIkAT/TIf0iyql4df7DlQVRNo7vjE=";

    fn grant(node: &str, targets: &[&str]) -> Grant {
        Grant {
            node: node.into(),
            node_key_b64: KEY.into(),
            inbox_targets: targets.iter().map(|s| s.to_string()).collect(),
            expires: None,
            did: None,
            spend: None,
        }
    }

    fn claim<'a>(node: &'a str, coll: &'a str, target: Option<&'a str>) -> Claim<'a> {
        Claim { node, key_b64: KEY, collection: coll, target }
    }

    #[test]
    fn issued_token_authorizes_what_it_grants() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("alice", &["bob"])).unwrap();
        let root = auth.public_key();
        authorize(&t, &root, &claim("alice", "agents", None)).unwrap();
        authorize(&t, &root, &claim("alice", "tasks", None)).unwrap();
        authorize(&t, &root, &claim("alice", "inbox", Some("bob"))).unwrap();
    }

    #[test]
    fn inbox_is_limited_to_the_granted_targets() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("carol", &["bob"])).unwrap();
        let root = auth.public_key();
        assert!(authorize(&t, &root, &claim("carol", "inbox", Some("bob"))).is_ok());
        assert!(authorize(&t, &root, &claim("carol", "inbox", Some("alice"))).is_err());
        assert!(authorize(&t, &root, &claim("carol", "inbox", None)).is_err(), "no target, no wildcard");
    }

    #[test]
    fn a_node_may_always_address_itself() {
        // Commands to oneself (a local task) replicate like any other document; other nodes must not
        // refuse them just because the token lists no inbox targets for the node's own name.
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = auth.issue(&grant("tablet", &["branch"])).unwrap();
        assert!(authorize(&t, &root, &claim("tablet", "inbox", Some("tablet"))).is_ok());
        assert!(authorize(&t, &root, &claim("tablet", "inbox", Some("branch"))).is_ok());
        assert!(authorize(&t, &root, &claim("tablet", "inbox", Some("hq"))).is_err(), "other nodes still need a right");
        // and it is the *token's* node name that counts, not the claimed one
        assert!(authorize(&t, &root, &claim("mallory", "inbox", Some("mallory"))).is_err());
        let none = auth.issue(&grant("solo", &[])).unwrap();
        assert!(authorize(&none, &root, &claim("solo", "inbox", Some("solo"))).is_ok());
        assert!(authorize(&none, &root, &claim("solo", "inbox", Some("branch"))).is_err());
    }

    #[test]
    fn wildcard_allows_any_target() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("alice", &["*"])).unwrap();
        assert!(authorize(&t, &auth.public_key(), &claim("alice", "inbox", Some("anyone"))).is_ok());
    }

    #[test]
    fn a_token_names_one_node_and_one_key() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("alice", &["*"])).unwrap();
        let root = auth.public_key();
        assert!(authorize(&t, &root, &claim("mallory", "tasks", None)).is_err(), "someone else's token");
        let other_key = Claim { node: "alice", key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", collection: "tasks", target: None };
        assert!(authorize(&t, &root, &other_key).is_err(), "stolen token with a different key");
    }

    #[test]
    fn a_token_from_another_authority_is_refused() {
        let real = Authority::generate();
        let fake = Authority::generate();
        let t = fake.issue(&grant("alice", &["*"])).unwrap();
        assert!(authorize(&t, &real.public_key(), &claim("alice", "tasks", None)).is_err());
    }

    #[test]
    fn admission_checks_the_token_and_the_node_name_only() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = auth.issue(&grant("alice", &["bob"])).unwrap();
        assert!(admit(&t, &root, "alice").is_ok());
        assert!(admit(&t, &root, "mallory").is_err(), "someone else's token");
        assert!(admit(&t, &Authority::generate().public_key(), "alice").is_err(), "wrong authority");
        assert!(admit("junk", &root, "alice").is_err());
        assert!(admit(&t, &root, "alice\"); allow if true; //").is_err());
        let mut g = grant("alice", &["*"]);
        g.expires = Some(SystemTime::now() - Duration::from_secs(60));
        assert!(admit(&auth.issue(&g).unwrap(), &root, "alice").is_err(), "expired");
    }

    #[test]
    fn expired_tokens_are_refused() {
        let auth = Authority::generate();
        let mut g = grant("alice", &["*"]);
        g.expires = Some(SystemTime::now() - Duration::from_secs(3600));
        let expired = auth.issue(&g).unwrap();
        g.expires = Some(SystemTime::now() + Duration::from_secs(3600));
        let valid = auth.issue(&g).unwrap();
        let root = auth.public_key();
        assert!(authorize(&expired, &root, &claim("alice", "tasks", None)).is_err());
        assert!(authorize(&valid, &root, &claim("alice", "tasks", None)).is_ok());
    }

    #[test]
    fn a_holder_can_narrow_a_token_offline_but_not_widen_it() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = auth.issue(&grant("alice", &["*"])).unwrap();

        // only bob from now on
        let narrowed = attenuate(&t, &root, &Attenuation { inbox_targets: Some(vec!["bob".into()]), ..Default::default() }).unwrap();
        assert!(authorize(&narrowed, &root, &claim("alice", "inbox", Some("bob"))).is_ok());
        assert!(authorize(&narrowed, &root, &claim("alice", "inbox", Some("hq"))).is_err());
        assert!(authorize(&narrowed, &root, &claim("alice", "tasks", None)).is_ok(), "other rights stay");

        // already expired
        let dead = attenuate(&t, &root, &Attenuation { expires: Some(SystemTime::now() - Duration::from_secs(5)), ..Default::default() }).unwrap();
        assert!(authorize(&dead, &root, &claim("alice", "tasks", None)).is_err());

        // attenuating a narrowed token with a wider list does not widen it
        let attempt = attenuate(&narrowed, &root, &Attenuation { inbox_targets: Some(vec!["bob".into(), "hq".into()]), ..Default::default() }).unwrap();
        assert!(authorize(&attempt, &root, &claim("alice", "inbox", Some("hq"))).is_err());
    }

    #[test]
    fn tampering_with_a_token_breaks_it() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("alice", &["bob"])).unwrap();
        // flip one character in the middle (the token is URL-safe base64 text)
        let mut chars: Vec<char> = t.chars().collect();
        let n = chars.len() / 2;
        chars[n] = if chars[n] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_ne!(tampered, t);
        assert!(authorize(&tampered, &auth.public_key(), &claim("alice", "tasks", None)).is_err());
        assert!(authorize("not a token", &auth.public_key(), &claim("alice", "tasks", None)).is_err());
    }

    #[test]
    fn names_that_could_inject_datalog_are_refused() {
        let auth = Authority::generate();
        assert!(auth.issue(&grant("a\"); right(\"inbox\", \"*\"); node(\"x", &["bob"])).is_err());
        assert!(auth.issue(&grant("alice", &["bob\"); //"])).is_err());
        let t = auth.issue(&grant("alice", &["bob"])).unwrap();
        let evil = Claim { node: "alice\"); allow if true; //", key_b64: KEY, collection: "tasks", target: None };
        assert!(authorize(&t, &auth.public_key(), &evil).is_err());
    }

    #[test]
    fn the_authority_can_revoke_a_token_and_everyone_can_check_it() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("alice", &["*"])).unwrap();
        let narrowed = attenuate(&t, &auth.public_key(), &Attenuation { inbox_targets: Some(vec!["bob".into()]), ..Default::default() }).unwrap();
        let rev = auth.revoke(&t, "tablet lost").unwrap();
        assert!(verify_revocation(&rev, &auth.public_key()).is_ok());
        // it targets the authority block, so attenuated copies share the id and die with it
        let ids = authorize(&narrowed, &auth.public_key(), &claim("alice", "tasks", None)).unwrap().revocation_ids;
        assert_eq!(ids[0], rev.revoked);
        // survives a trip through JSON (how it is stored and replicated)
        assert_eq!(Revocation::from_json(&rev.to_json()).unwrap(), rev);
    }

    #[test]
    fn a_forged_or_altered_revocation_is_refused() {
        let auth = Authority::generate();
        let impostor = Authority::generate();
        let t = auth.issue(&grant("alice", &["*"])).unwrap();
        let fake = impostor.revoke_id(&authorize(&t, &auth.public_key(), &claim("alice", "tasks", None)).unwrap().revocation_ids[0], "mallory says so").unwrap();
        assert!(verify_revocation(&fake, &auth.public_key()).is_err(), "signed by someone else");
        let mut real = auth.revoke(&t, "x").unwrap();
        real.issued_at += 1;
        assert!(verify_revocation(&real, &auth.public_key()).is_err(), "altered after signing");
        assert!(auth.revoke("garbage", "x").is_err());
        assert!(auth.revoke_id("not hex!", "x").is_err());
    }

    #[test]
    fn root_keys_round_trip_and_revocation_ids_are_stable() {
        let auth = Authority::generate();
        let again = Authority::from_private_b64(&auth.private_b64()).unwrap();
        assert_eq!(auth.public_b64(), again.public_b64());
        assert!(parse_public_key(&auth.public_b64()).is_ok());
        let t = auth.issue(&grant("alice", &["bob"])).unwrap();
        let a = authorize(&t, &auth.public_key(), &claim("alice", "tasks", None)).unwrap();
        let b = authorize(&t, &auth.public_key(), &claim("alice", "agents", None)).unwrap();
        assert_eq!(a.revocation_ids, b.revocation_ids);
        assert_eq!(a.revocation_ids.len(), 1);
    }

    // ── tokens bound to a DID ───────────────────────────────────────────────────────────────────────────

    const DID_A: &str = "did:wba:a.example.com%3A8800:agents:alice:e1_Wc4fXq2L9s0kT3nB7yH1dR5vJ8mZ6pA4uE0gQ2xN3oI";
    const DID_B: &str = "did:wba:b.example.com:agents:alice:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn did_token(auth: &Authority, did: Option<&str>) -> String {
        let mut g = grant("alice", &["bob"]);
        g.did = did.map(str::to_string);
        auth.issue(&g).unwrap()
    }

    #[test]
    fn a_did_bound_token_works_only_for_the_node_that_proves_that_did() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = did_token(&auth, Some(DID_A));
        let c = claim("alice", "inbox", Some("bob"));
        authorize_with(&t, &root, &c, Some(DID_A)).unwrap();
        assert!(authorize_with(&t, &root, &c, Some(DID_B)).is_err(), "another DID");
        assert!(authorize(&t, &root, &c).is_err(), "no DID shown at all");
        assert!(authorize_with(&t, &root, &claim("alice", "inbox", Some("hq")), Some(DID_A)).is_err(), "scoping still applies");
        assert!(admit_with(&t, &root, "alice", Some(DID_A)).is_ok());
        assert!(admit_with(&t, &root, "alice", Some(DID_B)).is_err());
        assert!(admit(&t, &root, "alice").is_err());
    }

    #[test]
    fn a_node_that_proves_a_did_needs_a_token_bound_to_it() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let plain = did_token(&auth, None);
        assert!(authorize_with(&plain, &root, &claim("alice", "tasks", None), Some(DID_A)).is_err(), "a token naming no DID is not enough");
        assert!(admit_with(&plain, &root, "alice", Some(DID_A)).is_err());
        authorize(&plain, &root, &claim("alice", "tasks", None)).unwrap(); // unchanged without DIDs
    }

    #[test]
    fn did_binding_survives_attenuation_and_shows_in_inspect() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = did_token(&auth, Some(DID_A));
        let narrowed = attenuate(&t, &root, &Attenuation { inbox_targets: Some(vec!["bob".into()]), ..Default::default() }).unwrap();
        authorize_with(&narrowed, &root, &claim("alice", "inbox", Some("bob")), Some(DID_A)).unwrap();
        assert!(authorize_with(&narrowed, &root, &claim("alice", "inbox", Some("bob")), Some(DID_B)).is_err());
        assert!(inspect(&t, &root).unwrap().contains(DID_A));
    }

    #[test]
    fn malformed_dids_are_refused_not_interpolated() {
        let auth = Authority::generate();
        let mut g = grant("alice", &[]);
        g.did = Some("did:wba:x\"); allow if true; //".into());
        assert!(auth.issue(&g).is_err());
        g.did = Some("did:web:example.com".into());
        assert!(auth.issue(&g).is_err(), "only did:wba");
        let t = did_token(&auth, Some(DID_A));
        assert!(authorize_with(&t, &auth.public_key(), &claim("alice", "tasks", None), Some("did:wba:x\"); allow if true; //")).is_err());
        assert!(admit_with(&t, &auth.public_key(), "alice", Some("not a did")).is_err());
    }

    // ── spending caps ───────────────────────────────────────────────────────────────────────────────────

    fn spender(auth: &Authority, cap_minor: u64, site: Option<&str>) -> String {
        let mut g = grant("store-0412", &["*"]);
        g.spend = Some(Spend {
            currency: "EUR".into(),
            cap_minor,
            categories: vec!["transport".into(), "storage".into()],
            on_behalf_of: site.map(str::to_string),
        });
        auth.issue(&g).unwrap()
    }

    fn order<'a>(amount_minor: u64, category: &'a str, site: &'a str) -> Commitment<'a> {
        Commitment { node: "store-0412", key_b64: KEY, amount_minor, currency: "EUR", category, on_behalf_of: site }
    }

    #[test]
    fn a_commitment_up_to_the_cap_is_allowed_and_one_cent_more_is_not() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = spender(&auth, 600_000, Some("store-0412"));
        authorize_commitment(&t, &root, &order(600_000, "transport", "store-0412"), None).unwrap();
        authorize_commitment(&t, &root, &order(1, "storage", "store-0412"), None).unwrap();
        assert!(authorize_commitment(&t, &root, &order(600_001, "transport", "store-0412"), None).is_err());
    }

    #[test]
    fn category_site_and_currency_must_match_the_grant() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = spender(&auth, 600_000, Some("store-0412"));
        assert!(authorize_commitment(&t, &root, &order(100, "catering", "store-0412"), None).is_err(), "category");
        assert!(authorize_commitment(&t, &root, &order(100, "transport", "store-0999"), None).is_err(), "another site");
        let usd = Commitment { currency: "USD", ..order(100, "transport", "store-0412") };
        assert!(authorize_commitment(&t, &root, &usd, None).is_err(), "currency");
        // a grant for any site
        let any = spender(&auth, 600_000, None);
        authorize_commitment(&any, &root, &order(100, "transport", "store-0999"), None).unwrap();
    }

    #[test]
    fn a_token_without_a_spending_grant_commits_to_nothing() {
        let auth = Authority::generate();
        let t = auth.issue(&grant("store-0412", &["*"])).unwrap();
        assert!(authorize_commitment(&t, &auth.public_key(), &order(1, "transport", "store-0412"), None).is_err());
        assert!(authorize_commitment(&t, &auth.public_key(), &order(0, "transport", "store-0412"), None).is_err());
    }

    #[test]
    fn the_signer_must_be_the_tokens_node_and_key() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = spender(&auth, 600_000, None);
        let stolen = Commitment { key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ..order(100, "transport", "s") };
        assert!(authorize_commitment(&t, &root, &stolen, None).is_err(), "a stolen token with another key");
        let other = Commitment { node: "mallory", ..order(100, "transport", "s") };
        assert!(authorize_commitment(&t, &root, &other, None).is_err());
        assert!(authorize_commitment(&t, &Authority::generate().public_key(), &order(100, "transport", "s"), None).is_err(), "another authority");
    }

    #[test]
    fn expired_spending_tokens_are_refused() {
        let auth = Authority::generate();
        let mut g = grant("store-0412", &[]);
        g.spend = Some(Spend { currency: "EUR".into(), cap_minor: 100, categories: vec!["transport".into()], on_behalf_of: None });
        g.expires = Some(SystemTime::now() - Duration::from_secs(60));
        let t = auth.issue(&g).unwrap();
        assert!(authorize_commitment(&t, &auth.public_key(), &order(1, "transport", "s"), None).is_err());
        // but it was valid when the commitment was made: an audit after the fact still passes
        let then = SystemTime::now() - Duration::from_secs(3600);
        authorize_commitment_at(&t, &auth.public_key(), &order(1, "transport", "s"), None, then).unwrap();
    }

    #[test]
    fn a_did_bound_spending_token_needs_that_did() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let mut g = grant("store-0412", &[]);
        g.did = Some(DID_A.into());
        g.spend = Some(Spend { currency: "EUR".into(), cap_minor: 100, categories: vec!["transport".into()], on_behalf_of: None });
        let t = auth.issue(&g).unwrap();
        authorize_commitment(&t, &root, &order(100, "transport", "s"), Some(DID_A)).unwrap();
        assert!(authorize_commitment(&t, &root, &order(100, "transport", "s"), Some(DID_B)).is_err());
        assert!(authorize_commitment(&t, &root, &order(100, "transport", "s"), None).is_err());
    }

    #[test]
    fn spending_can_be_narrowed_offline_but_never_raised() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = spender(&auth, 600_000, None);
        let low = attenuate(&t, &root, &Attenuation { spend_cap_minor: Some(150_000), ..Default::default() }).unwrap();
        authorize_commitment(&low, &root, &order(150_000, "transport", "s"), None).unwrap();
        assert!(authorize_commitment(&low, &root, &order(150_001, "transport", "s"), None).is_err());
        // a later block with a higher number does not lift the lower one
        let raised = attenuate(&low, &root, &Attenuation { spend_cap_minor: Some(900_000), ..Default::default() }).unwrap();
        assert!(authorize_commitment(&raised, &root, &order(200_000, "transport", "s"), None).is_err());
        // nor does narrowing past the authority's own cap raise it
        let over = attenuate(&t, &root, &Attenuation { spend_cap_minor: Some(900_000), ..Default::default() }).unwrap();
        assert!(authorize_commitment(&over, &root, &order(700_000, "transport", "s"), None).is_err());
        // category and site
        let only = attenuate(&t, &root, &Attenuation { spend_categories: Some(vec!["transport".into()]), spend_for: Some("store-0412".into()), ..Default::default() }).unwrap();
        authorize_commitment(&only, &root, &order(100, "transport", "store-0412"), None).unwrap();
        assert!(authorize_commitment(&only, &root, &order(100, "storage", "store-0412"), None).is_err());
        assert!(authorize_commitment(&only, &root, &order(100, "transport", "store-0999"), None).is_err());
        // a category the grant never had stays out even if a narrowing block names it
        let sneaky = attenuate(&t, &root, &Attenuation { spend_categories: Some(vec!["catering".into()]), ..Default::default() }).unwrap();
        assert!(authorize_commitment(&sneaky, &root, &order(100, "catering", "s"), None).is_err());
    }

    #[test]
    fn spending_limits_leave_documents_and_admission_alone() {
        let auth = Authority::generate();
        let root = auth.public_key();
        let t = spender(&auth, 600_000, Some("store-0412"));
        let narrowed = attenuate(
            &t,
            &root,
            &Attenuation { spend_cap_minor: Some(100), spend_categories: Some(vec!["transport".into()]), spend_for: Some("store-0412".into()), ..Default::default() },
        )
        .unwrap();
        for tok in [&t, &narrowed] {
            authorize(tok, &root, &claim("store-0412", "tasks", None)).unwrap();
            authorize(tok, &root, &claim("store-0412", "inbox", Some("carrier-1"))).unwrap();
            admit(tok, &root, "store-0412").unwrap();
        }
        // and a narrowed inbox no longer locks the holder out of admission
        let inbox = attenuate(&t, &root, &Attenuation { inbox_targets: Some(vec!["hq".into()]), ..Default::default() }).unwrap();
        admit(&inbox, &root, "store-0412").unwrap();
        // the same revocation id covers the narrowed copy
        let a = authorize_commitment(&narrowed, &root, &order(100, "transport", "store-0412"), None).unwrap();
        assert_eq!(a.revocation_ids[0], auth.revoke(&t, "x").unwrap().revoked);
        assert!(inspect(&t, &root).unwrap().contains("spend_cap"));
    }

    #[test]
    fn bad_spending_input_is_refused_not_interpolated() {
        let auth = Authority::generate();
        let mut g = grant("s", &[]);
        let ok = Spend { currency: "EUR".into(), cap_minor: 1, categories: vec!["transport".into()], on_behalf_of: None };
        for bad in [
            Spend { currency: "eur".into(), ..ok.clone() },
            Spend { currency: "EU\"); allow if true; //".into(), ..ok.clone() },
            Spend { categories: vec![], ..ok.clone() },
            Spend { categories: vec!["x\"); allow if true; //".into()], ..ok.clone() },
            Spend { on_behalf_of: Some("a b".into()), ..ok.clone() },
            Spend { cap_minor: u64::MAX, ..ok.clone() },
        ] {
            g.spend = Some(bad);
            assert!(auth.issue(&g).is_err());
        }
        g.spend = Some(ok);
        let t = auth.issue(&g).unwrap();
        let root = auth.public_key();
        assert!(authorize_commitment(&t, &root, &Commitment { category: "t\"); allow if true; //", ..order(1, "transport", "s") }, None).is_err());
        assert!(authorize_commitment(&t, &root, &Commitment { amount_minor: u64::MAX, ..order(1, "transport", "s") }, None).is_err());
        assert!(attenuate(&t, &root, &Attenuation { spend_categories: Some(vec![]), ..Default::default() }).is_err());
        assert!(attenuate(&t, &root, &Attenuation { spend_for: Some("x\")".into()), ..Default::default() }).is_err());
    }

    #[test]
    fn amounts_parse_to_minor_units() {
        assert_eq!(parse_amount_minor("7200").unwrap(), 720_000);
        assert_eq!(parse_amount_minor("7200.5").unwrap(), 720_050);
        assert_eq!(parse_amount_minor("0.07").unwrap(), 7);
        for bad in ["", "-1", "1.234", "1,5", "abc", ".5", "99999999999999999999"] {
            assert!(parse_amount_minor(bad).is_err(), "{bad}");
        }
    }
}