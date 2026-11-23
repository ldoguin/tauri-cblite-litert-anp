//! ANP-02 request authentication: HTTP Message Signatures (RFC 9421) made with an Ed25519 key that a DID document lists
//! under `authentication`.
//!
//! A signed request carries `Signature-Input` (what is covered and when it was made) and `Signature`, and, when it has
//! a body, `Content-Digest` (RFC 9530). The verifier here follows the ANP SDK's rules, which its published vectors
//! pin down:
//! * `@method` and `@target-uri` must always be covered; a body requires a covered, matching `Content-Digest`;
//! * `created` is required, may be at most `future_skew` seconds ahead and `max_age` seconds old; a present `expires`
//!   must be after `created` and not yet passed;
//! * an optional `alg` must be `ed25519`; other signed parameters are accepted and covered by the signature;
//! * a signature without a `nonce` is valid for *stateless* verification only: a full authenticator must still refuse
//!   replays, which [`ReplayCache`] does (by nonce, or by the signature itself when there is none);
//! * a covered `@authority` may be written in any of the equivalent spellings of the request's authority (default port
//!   explicit or not, IPv6 bracketed or not, expanded or compressed); IPv4-mapped IPv6 aliases are refused. The signed
//!   *target URI* is always the exact one of the request.
//!
//! Resolving the DID is the caller's job (`key_for`): over HTTPS, from a replicated document, or from a file.

use anp_did::{SigningKey, VerifyingKey};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Mutex;

pub use anp_did;
pub mod legacy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError(pub String);
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request authentication: {}", self.0)
    }
}
impl std::error::Error for AuthError {}
fn err<T>(s: impl Into<String>) -> Result<T, AuthError> {
    Err(AuthError(s.into()))
}

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// How old `created` may be, in seconds.
    pub max_age: i64,
    /// How far ahead of our clock `created` may be, in seconds.
    pub future_skew: i64,
    /// Refuse signatures without a nonce (a stateless check cannot tell a replay from a retry).
    pub require_nonce: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Policy { max_age: 300, future_skew: 60, require_nonce: false }
    }
}

/// The request as the verifier saw it. `url` is the full URL the client addressed (scheme, authority, path, query):
/// behind a TLS-terminating proxy that is the *public* URL, not the one the node itself received.
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

/// A request that passed every check.
#[derive(Debug, Clone)]
pub struct Verified {
    pub key_id: String,
    /// The DID: the key id up to `#`.
    pub did: String,
    pub nonce: Option<String>,
    pub created: i64,
    pub expires: Option<i64>,
    /// Identifies this signature for replay protection.
    pub replay_key: String,
}

// ── structured fields ───────────────────────────────────────────────────────────────────────────────────

/// Split `s` on `sep` outside quoted strings and parentheses.
fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let (mut out, mut start, mut depth, mut quoted, mut esc) = (Vec::new(), 0, 0i32, false, false);
    for (i, c) in s.char_indices() {
        if quoted {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// A quoted string starting at `s[0]`: the unescaped value and the rest after the closing quote.
fn quoted(s: &str) -> Result<(String, &str), AuthError> {
    let mut chars = s.char_indices();
    if chars.next().map(|(_, c)| c) != Some('"') {
        return err("expected a quoted string");
    }
    let (mut out, mut esc) = (String::new(), false);
    for (i, c) in chars {
        if esc {
            if c != '"' && c != '\\' {
                return err("bad escape in a quoted string");
            }
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            return Ok((out, &s[i + 1..]));
        } else {
            out.push(c);
        }
    }
    err("unterminated quoted string")
}

/// The parsed `Signature-Input` member.
#[derive(Debug, Clone)]
pub struct SignatureInput {
    pub label: String,
    pub components: Vec<String>,
    /// Everything after `label=`: the covered components and their parameters, exactly as signed.
    pub params_raw: String,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub key_id: Option<String>,
    pub alg: Option<String>,
}

/// Parse one `label=("c1" "c2");created=…;keyid="…"` member.
pub fn parse_signature_input(member: &str) -> Result<SignatureInput, AuthError> {
    let member = member.trim();
    let (label, rest) = member.split_once('=').ok_or_else(|| AuthError("no label".into()))?;
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return err("bad label");
    }
    let params_raw = rest.trim().to_string();
    let body = params_raw.strip_prefix('(').ok_or_else(|| AuthError("covered components must be an inner list".into()))?;
    // the inner list
    let mut components = Vec::new();
    let mut cur = body.trim_start();
    loop {
        if let Some(after) = cur.strip_prefix(')') {
            cur = after;
            break;
        }
        let (c, after) = quoted(cur)?;
        if after.starts_with(';') {
            return err("covered components with parameters are not supported");
        }
        components.push(c);
        cur = after.trim_start();
        if cur.is_empty() {
            return err("unterminated component list");
        }
    }
    if components.is_empty() {
        return err("no covered components");
    }
    let mut out = SignatureInput { label: label.to_string(), components, params_raw: params_raw.clone(), created: None, expires: None, nonce: None, key_id: None, alg: None };
    // parameters
    for raw in split_top_level(cur, ';').into_iter().skip(1) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (name, value) = match raw.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (raw, None),
        };
        match (name, value) {
            ("created", Some(v)) => out.created = Some(v.parse().map_err(|_| AuthError("created is not an integer".into()))?),
            ("expires", Some(v)) => out.expires = Some(v.parse().map_err(|_| AuthError("expires is not an integer".into()))?),
            ("nonce", Some(v)) => out.nonce = Some(quoted(v)?.0),
            ("keyid", Some(v)) => out.key_id = Some(quoted(v)?.0),
            ("alg", Some(v)) => out.alg = Some(quoted(v)?.0),
            _ => {} // tag, fresh, counter, … : covered by the signature as part of `params_raw`
        }
    }
    Ok(out)
}

/// The `keyid` a request claims to be signed with, read from its `Signature-Input` header value without verifying anything:
/// enough to know *whose* DID document to look up. `None` if the header does not hold exactly one parseable signature.
pub fn key_id_of(signature_input: &str) -> Option<String> {
    let members = split_top_level(signature_input, ',');
    if members.len() != 1 {
        return None;
    }
    parse_signature_input(members[0]).ok()?.key_id
}

/// The bytes of the `Signature` member with the given label (`label=:base64:`).
pub fn parse_signature(header: &str, label: &str) -> Result<Vec<u8>, AuthError> {
    for member in split_top_level(header, ',') {
        let Some((l, v)) = member.trim().split_once('=') else { continue };
        if l == label {
            let b = v.trim().strip_prefix(':').and_then(|x| x.strip_suffix(':')).ok_or_else(|| AuthError("the signature is not a byte sequence".into()))?;
            return B64.decode(b).map_err(|_| AuthError("the signature is not base64".into()));
        }
    }
    err(format!("no signature labelled {label}"))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<String> {
    let vals: Vec<&str> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()).collect();
    (!vals.is_empty()).then(|| vals.join(", "))
}

/// RFC 9530 `Content-Digest` for `body`.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", B64.encode(Sha256::digest(body)))
}

// ── authority spellings ─────────────────────────────────────────────────────────────────────────────────

fn scheme_and_authority(url: &str) -> Result<(&str, &str), AuthError> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| AuthError("the URL has no scheme".into()))?;
    if scheme != "https" && scheme != "http" {
        return err("only http(s) URLs");
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return err("the URL needs an authority without userinfo");
    }
    Ok((scheme, authority))
}

/// Every accepted spelling of the authority of `url`.
fn authority_candidates(url: &str) -> Result<Vec<String>, AuthError> {
    let (scheme, authority) = scheme_and_authority(url)?;
    let default = if scheme == "https" { 443u16 } else { 80 };
    let (host, port): (&str, Option<u16>) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| AuthError("unterminated IPv6 literal".into()))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().map_err(|_| AuthError("bad port".into()))?),
            None if after.is_empty() => None,
            None => return err("bad authority"),
        };
        (h, port)
    } else if authority.matches(':').count() == 1 {
        let (h, p) = authority.split_once(':').unwrap();
        (h, Some(p.parse::<u16>().map_err(|_| AuthError("bad port".into()))?))
    } else {
        (authority, None)
    };
    if port == Some(0) {
        return err("port 0");
    }
    let port = port.unwrap_or(default);
    let mut spellings: Vec<(String, bool)> = Vec::new(); // (host, is_ipv6)
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        if v6.to_ipv4_mapped().is_some() {
            return err("IPv4-mapped IPv6 aliases are refused");
        }
        spellings.push((host.to_string(), true));
        spellings.push((v6.to_string(), true));
    } else {
        spellings.push((host.to_ascii_lowercase(), false));
        spellings.push((host.to_string(), false));
    }
    let mut out: Vec<String> = Vec::new();
    for (h, v6) in spellings {
        let forms: Vec<String> = if v6 { vec![format!("[{h}]"), h.clone()] } else { vec![h.clone()] };
        for f in forms {
            for c in [f.clone(), format!("{f}:{port}")] {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
    }
    Ok(out)
}

// ── signature base ──────────────────────────────────────────────────────────────────────────────────────

fn signature_base(si: &SignatureInput, req: &Request, authority: Option<&str>) -> Result<Vec<u8>, AuthError> {
    let mut lines: Vec<String> = Vec::new();
    for c in &si.components {
        let v = match c.as_str() {
            "@method" => req.method.to_ascii_uppercase(),
            "@target-uri" => req.url.to_string(),
            "@authority" => authority.ok_or_else(|| AuthError("no authority".into()))?.to_string(),
            d if d.starts_with('@') => return err(format!("unsupported derived component {d}")),
            h => {
                if h != h.to_ascii_lowercase() {
                    return err("header component names must be lowercase");
                }
                header(req.headers, h).ok_or_else(|| AuthError(format!("covered header {h} is missing")))?
            }
        };
        lines.push(format!("\"{c}\": {v}"));
    }
    lines.push(format!("\"@signature-params\": {}", si.params_raw));
    Ok(lines.join("\n").into_bytes())
}

/// Verify the signature on `req`. `key_for` maps the signed `keyid` (a DID URL) to the Ed25519 key it must be checked
/// with (for example [`anp_did::authentication_key`] on the resolved DID document), or `None` if it is not acceptable.
/// `now` is Unix seconds.
pub fn verify(req: &Request, key_for: &dyn Fn(&str) -> Option<VerifyingKey>, policy: &Policy, now: i64) -> Result<Verified, AuthError> {
    let input = header(req.headers, "signature-input").ok_or_else(|| AuthError("no Signature-Input header".into()))?;
    let sigs = header(req.headers, "signature").ok_or_else(|| AuthError("no Signature header".into()))?;
    let members = split_top_level(&input, ',');
    if members.len() != 1 {
        return err("exactly one signature is accepted");
    }
    let si = parse_signature_input(members[0])?;
    let sig_bytes = parse_signature(&sigs, &si.label)?;
    let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| AuthError("the signature is not 64 bytes".into()))?;

    for need in ["@method", "@target-uri"] {
        if !si.components.iter().any(|c| c == need) {
            return err(format!("{need} must be covered"));
        }
    }
    let created = si.created.ok_or_else(|| AuthError("created is required".into()))?;
    if created > now + policy.future_skew {
        return err("created is in the future");
    }
    if now - created > policy.max_age {
        return err("the signature is too old");
    }
    if let Some(e) = si.expires {
        if e <= created {
            return err("expires is not after created");
        }
        if now > e {
            return err("the signature has expired");
        }
    }
    if let Some(a) = &si.alg {
        if !a.eq_ignore_ascii_case("ed25519") {
            return err("alg must be ed25519");
        }
    }
    if policy.require_nonce && si.nonce.is_none() {
        return err("a nonce is required");
    }
    let key_id = si.key_id.clone().filter(|k| k.contains('#')).ok_or_else(|| AuthError("keyid must be a DID URL".into()))?;

    // the body and its digest
    let covered_digest = si.components.iter().any(|c| c == "content-digest");
    let digest_header = header(req.headers, "content-digest");
    if !req.body.is_empty() || covered_digest {
        match &digest_header {
            Some(d) if *d == content_digest(req.body) => {}
            Some(_) => return err("Content-Digest does not match the body"),
            None => return err("a Content-Digest is required"),
        }
        if !covered_digest {
            return err("the body's Content-Digest is not covered by the signature");
        }
    }

    let key = key_for(&key_id).ok_or_else(|| AuthError(format!("no acceptable key for {key_id}")))?;
    let candidates: Vec<Option<String>> = if si.components.iter().any(|c| c == "@authority") {
        authority_candidates(req.url)?.into_iter().map(Some).collect()
    } else {
        vec![None]
    };
    let mut verified = false;
    for a in &candidates {
        let base = signature_base(&si, req, a.as_deref())?;
        if key.verify_strict(&base, &anp_did_signature(&sig)).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return err("the signature does not verify");
    }
    let did = key_id.split('#').next().unwrap_or("").to_string();
    let replay_key = match &si.nonce {
        Some(n) => hex(&Sha256::digest(format!("nonce\n{key_id}\n{n}").as_bytes())),
        None => hex(&Sha256::digest(format!("sig\n{key_id}\n{}", B64.encode(sig)).as_bytes())),
    };
    Ok(Verified { key_id, did, nonce: si.nonce, created, expires: si.expires, replay_key })
}

fn anp_did_signature(b: &[u8; 64]) -> ed25519_dalek::Signature {
    ed25519_dalek::Signature::from_bytes(b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── replay ──────────────────────────────────────────────────────────────────────────────────────────────

/// Remembers the signatures it has accepted for a while, so a captured request cannot be sent again. Entries live as
/// long as a signature could still pass the time checks.
pub struct ReplayCache {
    seen: Mutex<HashMap<String, i64>>,
    ttl: i64,
}

impl ReplayCache {
    pub fn new(policy: &Policy) -> ReplayCache {
        ReplayCache { seen: Mutex::new(HashMap::new()), ttl: policy.max_age + policy.future_skew + 1 }
    }
    /// `true` the first time a verified request is presented, `false` for a replay.
    pub fn accept(&self, v: &Verified, now: i64) -> bool {
        let mut m = self.seen.lock().unwrap();
        m.retain(|_, at| now - *at <= self.ttl);
        if m.contains_key(&v.replay_key) {
            return false;
        }
        m.insert(v.replay_key.clone(), now);
        true
    }
}

// ── signing ─────────────────────────────────────────────────────────────────────────────────────────────

/// The headers that authenticate a request: `Signature-Input`, `Signature` and, for a request with a body,
/// `Content-Digest`. Covers `@method`, `@target-uri`, `@authority` and (with a body) `content-digest`; valid for 300
/// seconds from `created`. `nonce` should be unique per request.
pub fn sign(sk: &SigningKey, key_id: &str, method: &str, url: &str, body: &[u8], created: i64, nonce: &str) -> Result<Vec<(String, String)>, AuthError> {
    let (_, authority) = scheme_and_authority(url)?;
    let mut components = vec!["@method", "@target-uri", "@authority"];
    let mut headers = Vec::new();
    if !body.is_empty() {
        components.push("content-digest");
        headers.push(("Content-Digest".to_string(), content_digest(body)));
    }
    let comps = components.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" ");
    let params_raw = format!("({comps});created={created};expires={};nonce=\"{nonce}\";keyid=\"{key_id}\"", created + 300);
    let si = SignatureInput { label: "sig1".into(), components: components.iter().map(|c| c.to_string()).collect(), params_raw: params_raw.clone(), created: Some(created), expires: None, nonce: None, key_id: None, alg: None };
    let req_headers = headers.clone();
    let req = Request { method, url, headers: &req_headers, body };
    let base = signature_base(&si, &req, Some(authority))?;
    use ed25519_dalek::Signer;
    let sig = sk.sign(&base);
    headers.push(("Signature-Input".into(), format!("sig1={params_raw}")));
    headers.push(("Signature".into(), format!("sig1=:{}:", B64.encode(sig.to_bytes()))));
    Ok(headers)
}
