//! `did:wba` identities for the Agent Network Protocol (ANP-03, e1 profile).
//!
//! A `did:wba` path DID ends in `e1_<fingerprint>`, where the fingerprint is the RFC 7638 thumbprint of the
//! agent's Ed25519 key. That makes the DID *self-certifying*: given a DID document, anyone can check offline that
//! the key in it is the key the DID names, and that the document was signed by that key (`eddsa-jcs-2022`).
//!
//! The ANP spec resolves a DID by fetching `https://<host>/<path>/did.json`. This crate only does the
//! cryptography and the URL rules, so a caller can feed it documents from anywhere: an HTTPS fetch, or, on a
//! mesh of devices that are often offline, a replicated database. Verification does not care how the document
//! arrived.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use ed25519_dalek::{Signature, Signer, Verifier};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const DI_CONTEXT: &str = "https://w3id.org/security/data-integrity/v2";
pub const MULTIKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const X25519_CONTEXT: &str = "https://w3id.org/security/suites/x25519-2019/v1";
const CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    Syntax(String),
    Binding(String),
    Document(String),
    Proof(String),
}
impl fmt::Display for DidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidError::Syntax(s) => write!(f, "bad did:wba syntax: {s}"),
            DidError::Binding(s) => write!(f, "key does not match the DID: {s}"),
            DidError::Document(s) => write!(f, "bad DID document: {s}"),
            DidError::Proof(s) => write!(f, "DID document proof rejected: {s}"),
        }
    }
}
impl std::error::Error for DidError {}

// ── identifiers ─────────────────────────────────────────────────────────────────────────────────────────

/// The RFC 7638 thumbprint of an Ed25519 key, base64url without padding: the `e1_` fingerprint minus its prefix.
pub fn thumbprint(pk: &[u8; 32]) -> String {
    // Required members only, lexicographic order, no whitespace.
    let jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, B64.encode(pk));
    B64.encode(Sha256::digest(jwk.as_bytes()))
}

/// The last path segment of a path DID: `e1_` + thumbprint.
pub fn e1_segment(pk: &[u8; 32]) -> String {
    format!("e1_{}", thumbprint(pk))
}

/// `publicKeyMultibase` for an Ed25519 key: `z` + base58btc(0xed01 || key).
pub fn multibase(pk: &[u8; 32]) -> String {
    let mut b = vec![0xed, 0x01];
    b.extend_from_slice(pk);
    format!("z{}", bs58::encode(b).into_string())
}

pub fn decode_multibase(s: &str) -> Result<[u8; 32], DidError> {
    let rest = s.strip_prefix('z').ok_or_else(|| DidError::Document("publicKeyMultibase must start with z".into()))?;
    let raw = bs58::decode(rest).into_vec().map_err(|e| DidError::Document(format!("multibase: {e}")))?;
    if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
        return Err(DidError::Document("not an Ed25519 multikey".into()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw[2..]);
    Ok(k)
}

/// A parsed `did:wba` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbaDid {
    pub host: String,
    pub port: Option<u16>,
    /// Path segments, including the trailing `e1_…` fingerprint when there is one.
    pub path: Vec<String>,
}

fn is_b64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

impl WbaDid {
    pub fn parse(s: &str) -> Result<Self, DidError> {
        let rest = s.strip_prefix("did:wba:").ok_or_else(|| DidError::Syntax("must start with did:wba:".into()))?;
        let mut parts = rest.split(':');
        let authority = parts.next().unwrap_or("");
        let (host, port) = match authority.split_once("%3A").or_else(|| authority.split_once("%3a")) {
            Some((h, p)) => (h, Some(p.parse::<u16>().map_err(|_| DidError::Syntax("bad port".into()))?)),
            None => (authority, None),
        };
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() || host.contains('/') {
            return Err(DidError::Syntax("host must be a domain name (IP addresses are not allowed)".into()));
        }
        let path: Vec<String> = parts.map(str::to_string).collect();
        for seg in &path {
            let ok = !seg.is_empty() && seg.chars().all(|c| is_b64url(c) || c == '.');
            if !ok {
                return Err(DidError::Syntax(format!("bad path segment {seg:?}")));
            }
        }
        Ok(WbaDid { host: host.to_lowercase(), port, path })
    }

    /// The `e1_` fingerprint (without the prefix) if this DID carries one.
    pub fn e1(&self) -> Option<&str> {
        let last = self.path.last()?;
        let fp = last.strip_prefix("e1_")?;
        (fp.len() == 43 && fp.chars().all(is_b64url)).then_some(fp)
    }

    /// Where the spec says the document lives: `https://host[:port]/path/did.json`, or `/.well-known/did.json`.
    pub fn resolution_url(&self) -> String {
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        if self.path.is_empty() {
            format!("https://{}{}/.well-known/did.json", self.host, port)
        } else {
            format!("https://{}{}/{}/did.json", self.host, port, self.path.join("/"))
        }
    }

    /// The URL path part only (what a server mounts the document at).
    pub fn document_path(&self) -> String {
        if self.path.is_empty() { "/.well-known/did.json".into() } else { format!("/{}/did.json", self.path.join("/")) }
    }
}

impl fmt::Display for WbaDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:wba:{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, "%3A{p}")?;
        }
        for s in &self.path {
            write!(f, ":{s}")?;
        }
        Ok(())
    }
}

/// Build the DID for a key: `did:wba:<host>[%3A<port>]:<segments…>:e1_<fingerprint>`.
pub fn did_for_key(host: &str, port: Option<u16>, segments: &[&str], pk: &[u8; 32]) -> String {
    let mut path: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
    path.push(e1_segment(pk));
    WbaDid { host: host.to_lowercase(), port, path }.to_string()
}

// ── canonical JSON (RFC 8785) ───────────────────────────────────────────────────────────────────────────

/// A double as ECMAScript's `Number::toString` writes it (RFC 8785 §3.2.2.3): the shortest digits that round-trip,
/// plain notation for exponents from -6 to 20, scientific (`1e+30`, `1e-27`) beyond, and `-0` as `0`.
pub fn es6_number(x: f64) -> Result<String, DidError> {
    if !x.is_finite() {
        return Err(DidError::Document("NaN and infinity cannot be canonicalised".into()));
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "d.ddde<exp>".
    let sci = format!("{:e}", x.abs());
    let (mant, exp) = sci.split_once('e').ok_or_else(|| DidError::Document("bad number".into()))?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().map_err(|_| DidError::Document("bad exponent".into()))? + 1; // value = 0.digits * 10^n
    let sign = if x < 0.0 { "-" } else { "" };
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let es = if e < 0 { format!("-{}", -e) } else { format!("+{e}") };
        if k == 1 { format!("{digits}e{es}") } else { format!("{}.{}e{es}", &digits[..1], &digits[1..]) }
    };
    Ok(format!("{sign}{body}"))
}

/// JSON Canonicalization Scheme (RFC 8785).
pub fn jcs(v: &Value) -> Result<String, DidError> {
    let mut out = String::new();
    jcs_into(v, &mut out)?;
    Ok(out)
}

fn jcs_into(v: &Value, out: &mut String) -> Result<(), DidError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Integers that a double holds exactly are written as integers; everything else as ECMAScript would.
            match (n.as_i64(), n.as_u64()) {
                (Some(i), _) if i.unsigned_abs() <= (1u64 << 53) => out.push_str(&i.to_string()),
                (_, Some(u)) if u <= (1u64 << 53) => out.push_str(&u.to_string()),
                _ => out.push_str(&es6_number(n.as_f64().ok_or_else(|| DidError::Document("number out of range".into()))?)?),
            }
        }
        // serde_json escapes exactly what JCS requires: quote, backslash, and control characters.
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string")),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_into(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16())); // UTF-16 code unit order
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key"));
                out.push(':');
                jcs_into(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

// ── documents ───────────────────────────────────────────────────────────────────────────────────────────

/// The Ed25519 key of a verification method, in the forms the ANP SDK and DID practice use: a `Multikey` or
/// `Ed25519VerificationKey2020` (`publicKeyMultibase`, `z6Mk…`), a `JsonWebKey2020` OKP/Ed25519 JWK, or an
/// `Ed25519VerificationKey2018` (`publicKeyBase58`).
pub fn ed25519_key_from_method(vm: &Value) -> Option<VerifyingKey> {
    let raw: [u8; 32] = match vm["type"].as_str()? {
        "Multikey" | "Ed25519VerificationKey2020" => decode_multibase(vm["publicKeyMultibase"].as_str()?).ok()?,
        "Ed25519VerificationKey2018" => bs58::decode(vm["publicKeyBase58"].as_str()?).into_vec().ok()?.try_into().ok()?,
        "JsonWebKey2020" => {
            let jwk = &vm["publicKeyJwk"];
            if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
                return None;
            }
            B64.decode(jwk["x"].as_str()?.trim_end_matches('=')).ok()?.try_into().ok()?
        }
        _ => return None,
    };
    VerifyingKey::from_bytes(&raw).ok()
}

/// The key a request signature made with `key_id` (a DID URL) must be verified with: the Ed25519 verification method of
/// `doc` with that id, and only if the document lists it under `authentication` (an embedded entry or an id).
pub fn authentication_key(doc: &Value, key_id: &str) -> Option<VerifyingKey> {
    let auth = doc.get("authentication")?.as_array()?;
    let authorised = auth.iter().any(|a| a.as_str() == Some(key_id) || a["id"].as_str() == Some(key_id));
    if !authorised {
        return None;
    }
    let from_methods = doc.get("verificationMethod").and_then(Value::as_array).and_then(|m| m.iter().find(|v| v["id"].as_str() == Some(key_id)));
    let embedded = auth.iter().find(|a| a["id"].as_str() == Some(key_id));
    ed25519_key_from_method(from_methods.or(embedded)?)
}
/// What `eddsa-jcs-2022` signs: SHA-256(JCS(proof options)) || SHA-256(JCS(document without proof)).
fn proof_input(doc_without_proof: &Value, proof_config: &Value) -> Result<[u8; 64], DidError> {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&Sha256::digest(jcs(proof_config)?.as_bytes()));
    out[32..].copy_from_slice(&Sha256::digest(jcs(doc_without_proof)?.as_bytes()));
    Ok(out)
}

/// Add an `eddsa-jcs-2022` `DataIntegrityProof` to `doc` (any JSON object without a `proof`). `verification_method`
/// is the DID URL of the signing key; `extra` is merged into the proof options before signing (for example
/// `domain` and `challenge`). Works for any document, not just DID documents: agent descriptions use it too.
pub fn add_proof(
    doc: &mut Value,
    sk: &SigningKey,
    verification_method: &str,
    purpose: &str,
    created: &str,
    extra: &Map<String, Value>,
) -> Result<(), DidError> {
    let obj = doc.as_object_mut().ok_or_else(|| DidError::Document("not an object".into()))?;
    if obj.contains_key("proof") {
        return Err(DidError::Document("already has a proof".into()));
    }
    let mut options = Map::new();
    options.insert("type".into(), json!("DataIntegrityProof"));
    options.insert("cryptosuite".into(), json!(CRYPTOSUITE));
    options.insert("proofPurpose".into(), json!(purpose));
    options.insert("verificationMethod".into(), json!(verification_method));
    options.insert("created".into(), json!(created));
    for (k, v) in extra {
        options.insert(k.clone(), v.clone());
    }
    // The proof options are signed together with the document's @context (when it has one).
    let mut config = options.clone();
    if let Some(c) = obj.get("@context") {
        config.insert("@context".into(), c.clone());
    }
    let sig = sk.sign(&proof_input(&Value::Object(obj.clone()), &Value::Object(config))?);
    options.insert("proofValue".into(), Value::String(format!("z{}", bs58::encode(sig.to_bytes()).into_string())));
    obj.insert("proof".into(), Value::Object(options));
    Ok(())
}

/// The same proof in the **legacy** form: the signature as plain base64url, signed over proof options *without* `@context`. This is
/// what the SDKs' own generators write by default (Python, Go and TypeScript all do), and the TypeScript SDK can read **only** this form,
/// so DID documents and agent descriptions are written this way: every SDK reads it. [`add_proof`] (the W3C multibase form) is still
/// used where the reader is known to read both (prekey bundles).
pub fn add_proof_legacy(
    doc: &mut Value,
    sk: &SigningKey,
    verification_method: &str,
    purpose: &str,
    created: &str,
    extra: &Map<String, Value>,
) -> Result<(), DidError> {
    let obj = doc.as_object_mut().ok_or_else(|| DidError::Document("not an object".into()))?;
    if obj.contains_key("proof") {
        return Err(DidError::Document("already has a proof".into()));
    }
    let mut options = Map::new();
    options.insert("type".into(), json!("DataIntegrityProof"));
    options.insert("cryptosuite".into(), json!(CRYPTOSUITE));
    options.insert("proofPurpose".into(), json!(purpose));
    options.insert("verificationMethod".into(), json!(verification_method));
    options.insert("created".into(), json!(created));
    for (k, v) in extra {
        options.insert(k.clone(), v.clone());
    }
    let sig = sk.sign(&proof_input(&Value::Object(obj.clone()), &Value::Object(options.clone()))?);
    options.insert("proofValue".into(), Value::String(B64.encode(sig.to_bytes())));
    obj.insert("proof".into(), Value::Object(options));
    Ok(())
}

/// Decode a `proofValue` and say which form of the suite it is. The ANP SDK writes, and reads, two:
/// * the **multibase** form: `z` + base58btc of the 64-byte signature, signed over proof options that include the
///   document's `@context` (the W3C suite, what [`add_proof`] writes);
/// * the **legacy** form: the signature as plain base64url, signed over proof options *without* `@context` (what the
///   SDK's `create_did_wba_document` still produces by default).
/// A value is the multibase form only if it starts with `z` and is exactly a canonical base58 encoding of 64 bytes;
/// otherwise it is read as base64url (a base64url string may well start with `z`). This is the SDK's own rule.
fn decode_proof_value(pv: &str) -> Result<(Vec<u8>, bool), DidError> {
    if let Some(rest) = pv.strip_prefix('z') {
        if let Ok(raw) = bs58::decode(rest).into_vec() {
            if raw.len() == 64 && format!("z{}", bs58::encode(&raw).into_string()) == pv {
                return Ok((raw, true));
            }
        }
    }
    let trimmed = pv.trim_end_matches('=');
    let raw = B64.decode(trimmed).map_err(|_| DidError::Proof("proofValue is neither multibase nor base64url".into()))?;
    Ok((raw, false))
}

/// Verify the `eddsa-jcs-2022` proof on `doc` against `key`. Reads both forms of the suite, see [`decode_proof_value`]. Checks the signature and the suite only: the caller
/// decides whether `key` is the right key for `proof.verificationMethod` and whether the purpose fits.
pub fn verify_proof(doc: &Value, key: &VerifyingKey) -> Result<(), DidError> {
    let proof = doc.get("proof").ok_or_else(|| DidError::Proof("no proof".into()))?;
    if proof["type"] != "DataIntegrityProof" || proof["cryptosuite"] != CRYPTOSUITE {
        return Err(DidError::Proof("expected a DataIntegrityProof, eddsa-jcs-2022".into()));
    }
    let pv = proof["proofValue"].as_str().ok_or_else(|| DidError::Proof("no proofValue".into()))?;
    let (raw, with_context) = decode_proof_value(pv)?;
    let sig = Signature::from_slice(&raw).map_err(|_| DidError::Proof("proofValue is not a 64-byte signature".into()))?;
    let mut config: Map<String, Value> = proof.as_object().cloned().ok_or_else(|| DidError::Proof("proof is not an object".into()))?;
    config.remove("proofValue");
    if with_context {
        if let Some(c) = doc.get("@context") {
            config.insert("@context".into(), c.clone());
        }
    }
    let mut bare = doc.as_object().cloned().ok_or_else(|| DidError::Document("not an object".into()))?;
    bare.remove("proof");
    let input = proof_input(&Value::Object(bare), &Value::Object(config))?;
    key.verify(&input, &sig).map_err(|_| DidError::Proof("signature does not verify".into()))
}

/// Create the DID document for `sk`, with the e1 `DataIntegrityProof`. `did` must be the DID built from this key
/// (see [`did_for_key`]); `services` are extra entries for the `service` array (for example an `AgentDescription`
/// endpoint); `created` is an RFC 3339 timestamp supplied by the caller.
pub fn build_document(did: &str, sk: &SigningKey, services: &[Value], created: &str) -> Result<Value, DidError> {
    build_document_with_agreement(did, sk, services, created, None)
}

/// The id of the key-agreement entry in a DID document: `<did>#key-agreement-1`.
pub fn key_agreement_id(did: &str) -> String {
    format!("{did}#key-agreement-1")
}

/// [`build_document`], with an X25519 `keyAgreement` entry for `agreement` (the public key used for end-to-end
/// encryption, kept separate from the signing key as ANP-03/09 require). Entry type `X25519KeyAgreementKey2019`,
/// the type ANP-03 recommends, with the key as `publicKeyBase58`.
pub fn build_document_with_agreement(
    did: &str,
    sk: &SigningKey,
    services: &[Value],
    created: &str,
    agreement: Option<&[u8; 32]>,
) -> Result<Value, DidError> {
    build_document_full(did, sk, services, created, agreement, None)
}

/// The profiles a device built on this project supports, as listed in its `deviceManifest` entry (ANP P2).
pub const DEVICE_PROFILES: [&str; 4] = ["anp.core.binding.v2", "anp.identity.discovery.v2", "anp.direct.base.v2", "anp.direct.e2ee.v2"];

/// [`build_document_with_agreement`], and with `device_id` also a `deviceManifest` (what P5 v2 requires of a DID that
/// advertises `anp.direct.e2ee.v2`): one device, signed with this key, encrypted to with the key-agreement key.
pub fn build_document_full(
    did: &str,
    sk: &SigningKey,
    services: &[Value],
    created: &str,
    agreement: Option<&[u8; 32]>,
    device_id: Option<&str>,
) -> Result<Value, DidError> {
    let parsed = WbaDid::parse(did)?;
    let pk = sk.verifying_key().to_bytes();
    let fp = parsed.e1().ok_or_else(|| DidError::Binding("the DID has no e1_ fingerprint".into()))?;
    if fp != thumbprint(&pk) {
        return Err(DidError::Binding("the DID's fingerprint is not this key's thumbprint".into()));
    }
    let vm_id = format!("{did}#{fp}");
    let mut doc = json!({
        "@context": [DID_CONTEXT, DI_CONTEXT, MULTIKEY_CONTEXT],
        "id": did,
        "verificationMethod": [{
            "id": vm_id, "type": "Multikey", "controller": did, "publicKeyMultibase": multibase(&pk),
        }],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    });
    if !services.is_empty() {
        doc["service"] = Value::Array(services.to_vec());
    }
    if let Some(ka) = agreement {
        // The layout the ANP SDK uses: the key is a verification method (X25519KeyAgreementKey2019, the raw key as
        // `z` + base58btc) and `keyAgreement` refers to it by id.
        doc["verificationMethod"].as_array_mut().expect("array").push(json!({
            "id": key_agreement_id(did),
            "type": "X25519KeyAgreementKey2019",
            "controller": did,
            "publicKeyMultibase": format!("z{}", bs58::encode(ka).into_string()),
        }));
        doc["keyAgreement"] = json!([key_agreement_id(did)]);
        doc["@context"].as_array_mut().expect("array").push(json!(X25519_CONTEXT));
        if let Some(dev) = device_id {
            doc["deviceManifest"] = json!({
                "type": "ANPDeviceManifest",
                "devices": [{
                    "device_id": dev,
                    "signing_key_id": vm_id,
                    "e2ee_key_id": key_agreement_id(did),
                    "profiles": DEVICE_PROFILES,
                }],
            });
        }
    }
    add_proof_legacy(&mut doc, sk, &vm_id, "assertionMethod", created, &Map::new())?;
    Ok(doc)
}

/// A document that passed every check.
#[derive(Debug, Clone)]
pub struct Verified {
    pub did: WbaDid,
    pub did_string: String,
    /// The Ed25519 key bound to the DID. This is the key to verify the agent's signatures with.
    pub key: VerifyingKey,
    pub document: Value,
}

impl Verified {
    pub fn services(&self) -> Vec<Value> {
        self.document.get("service").and_then(Value::as_array).cloned().unwrap_or_default()
    }
    /// The X25519 key-agreement key and its id, if the document publishes one. Reads the forms the ANP SDK and the
    /// spec use: `keyAgreement` entries that are embedded objects or ids of a `verificationMethod`, of type
    /// `X25519KeyAgreementKey2019`/`2020`, with the key as `publicKeyBase58` or `publicKeyMultibase` (`z` + base58btc of
    /// the raw 32 bytes, or of the 34 bytes with the `0xec01` multicodec prefix).
    pub fn key_agreement(&self) -> Option<(String, [u8; 32])> {
        let entries = self.document.get("keyAgreement")?.as_array()?;
        let methods = self.document.get("verificationMethod").and_then(Value::as_array);
        for e in entries {
            let method: &Value = match e {
                Value::String(r) => {
                    let id = if let Some(f) = r.strip_prefix('#') { format!("{}#{f}", self.did_string) } else { r.clone() };
                    match methods.and_then(|m| m.iter().find(|v| v["id"].as_str() == Some(id.as_str()))) {
                        Some(m) => m,
                        None => continue,
                    }
                }
                Value::Object(_) => e,
                _ => continue,
            };
            let ty = method["type"].as_str().unwrap_or("");
            if !(ty == "X25519KeyAgreementKey2019" || ty == "X25519KeyAgreementKey2020") || method["controller"] != self.did_string.as_str() {
                continue;
            }
            let Some(id) = method["id"].as_str() else { continue };
            let raw = if let Some(b58) = method["publicKeyBase58"].as_str() {
                bs58::decode(b58).into_vec().ok()
            } else {
                method["publicKeyMultibase"].as_str().and_then(|m| m.strip_prefix('z')).and_then(|b| bs58::decode(b).into_vec().ok())
            };
            let raw = match raw {
                Some(r) if r.len() == 34 && r[0] == 0xec && r[1] == 0x01 => r[2..].to_vec(),
                Some(r) => r,
                None => continue,
            };
            if let Ok(k) = <[u8; 32]>::try_from(raw.as_slice()) {
                return Some((id.to_string(), k));
            }
        }
        None
    }
    /// The id of the device whose `deviceManifest` entry lists `ka_id` as its `e2ee_key_id` (ANP P2).
    pub fn device_for_key_agreement(&self, ka_id: &str) -> Option<String> {
        let devices = self.document.pointer("/deviceManifest/devices")?.as_array()?;
        let mut hits = devices.iter().filter(|d| d["e2ee_key_id"].as_str() == Some(ka_id));
        let first = hits.next()?;
        hits.next().is_none().then(|| first["device_id"].as_str().map(str::to_string)).flatten()
    }

    /// The manifest entry for `device_id`: `(signing_key_id, e2ee_key_id)`. Exactly one entry must match.
    pub fn device_keys(&self, device_id: &str) -> Option<(String, String)> {
        let devices = self.document.pointer("/deviceManifest/devices")?.as_array()?;
        let mut hits = devices.iter().filter(|d| d["device_id"].as_str() == Some(device_id));
        let d = hits.next()?;
        if hits.next().is_some() {
            return None;
        }
        Some((d["signing_key_id"].as_str()?.to_string(), d["e2ee_key_id"].as_str()?.to_string()))
    }

    /// The endpoint of the first service of this type, if any.
    pub fn service_endpoint(&self, ty: &str) -> Option<String> {
        self.services().iter().find(|s| s["type"] == ty).and_then(|s| s["serviceEndpoint"].as_str().map(str::to_string))
    }
}

fn vm_matches(reference: &str, did: &str, vm_id: &str) -> bool {
    reference == vm_id || reference.strip_prefix('#').map(|f| format!("{did}#{f}") == vm_id).unwrap_or(false)
}

fn lists(doc: &Value, field: &str, did: &str, vm_id: &str) -> bool {
    doc.get(field)
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|x| x.as_str().map(|r| vm_matches(r, did, vm_id)).unwrap_or(false)))
        .unwrap_or(false)
}

/// Verify an e1 DID document: the id is the expected DID, a verification method binds the key to the DID's
/// fingerprint, that key is authorised for authentication and assertion, and the proof verifies over the document.
/// `expected` is the DID the caller asked for; pass `None` to accept whatever the document says it is.
pub fn verify_document(doc: &Value, expected: Option<&str>) -> Result<Verified, DidError> {
    let id = doc.get("id").and_then(Value::as_str).ok_or_else(|| DidError::Document("no id".into()))?;
    if let Some(want) = expected {
        if want != id {
            return Err(DidError::Document(format!("document is for {id}, not {want}")));
        }
    }
    let did = WbaDid::parse(id)?;
    let fp = did.e1().ok_or_else(|| DidError::Binding("only e1 path DIDs are accepted".into()))?.to_string();
    let ctx = doc.get("@context").and_then(Value::as_array).map(|a| a.iter().any(|c| c == DID_CONTEXT)).unwrap_or(false);
    if !ctx {
        return Err(DidError::Document("@context must include the DID v1 context".into()));
    }

    // the binding key: an Ed25519 Multikey whose thumbprint is the DID's fingerprint
    let vms = doc.get("verificationMethod").and_then(Value::as_array).ok_or_else(|| DidError::Document("no verificationMethod".into()))?;
    let mut binding: Option<(String, [u8; 32])> = None;
    for vm in vms {
        if vm["type"] != "Multikey" {
            continue;
        }
        let (Some(vid), Some(mb)) = (vm["id"].as_str(), vm["publicKeyMultibase"].as_str()) else { continue };
        let Ok(k) = decode_multibase(mb) else { continue };
        if thumbprint(&k) == fp {
            binding = Some((vid.to_string(), k));
            break;
        }
    }
    let (vm_id, pk) = binding.ok_or_else(|| DidError::Binding("no verification method matches the DID's e1 fingerprint".into()))?;
    if !lists(doc, "authentication", id, &vm_id) {
        return Err(DidError::Document("the binding key is not in authentication".into()));
    }
    if !lists(doc, "assertionMethod", id, &vm_id) {
        return Err(DidError::Document("the binding key is not in assertionMethod".into()));
    }

    // the proof
    let proof = doc.get("proof").ok_or_else(|| DidError::Proof("no proof".into()))?;
    if proof["type"] != "DataIntegrityProof" || proof["cryptosuite"] != CRYPTOSUITE || proof["proofPurpose"] != "assertionMethod" {
        return Err(DidError::Proof("expected a DataIntegrityProof, eddsa-jcs-2022, assertionMethod".into()));
    }
    let pvm = proof["verificationMethod"].as_str().ok_or_else(|| DidError::Proof("no verificationMethod".into()))?;
    if !vm_matches(pvm, id, &vm_id) {
        return Err(DidError::Proof("the proof is not made by the binding key".into()));
    }
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| DidError::Document("invalid Ed25519 key".into()))?;
    verify_proof(doc, &key)?;

    Ok(Verified { did, did_string: id.to_string(), key, document: doc.clone() })
}

// ── tests ───────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn doc_for(seed: u8) -> (SigningKey, String, Value) {
        let sk = key(seed);
        let did = did_for_key("branch.example.com", Some(8800), &["agents", "tablet"], &sk.verifying_key().to_bytes());
        let d = build_document(
            &did,
            &sk,
            &[json!({"id": format!("{did}#desc"), "type": "AgentDescription", "serviceEndpoint": "https://branch.example.com:8800/tablet/ad.json"})],
            "2026-11-13T10:00:00Z",
        )
        .unwrap();
        (sk, did, d)
    }

    #[test]
    fn fingerprint_is_the_rfc7638_thumbprint() {
        let pk = key(1).verifying_key().to_bytes();
        let jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, B64.encode(pk));
        assert_eq!(thumbprint(&pk), B64.encode(Sha256::digest(jwk.as_bytes())));
        assert_eq!(thumbprint(&pk).len(), 43);
        assert!(e1_segment(&pk).starts_with("e1_"));
        assert_ne!(thumbprint(&pk), thumbprint(&key(2).verifying_key().to_bytes()));
    }

    #[test]
    fn multibase_round_trips_and_looks_like_a_multikey() {
        let pk = key(3).verifying_key().to_bytes();
        let m = multibase(&pk);
        assert!(m.starts_with("z6Mk"), "{m}");
        assert_eq!(decode_multibase(&m).unwrap(), pk);
        assert!(decode_multibase("6Mk").is_err());
        assert!(decode_multibase("z1111").is_err());
    }

    #[test]
    fn did_parsing_and_resolution_urls_follow_the_spec() {
        let d = WbaDid::parse("did:wba:example.com").unwrap();
        assert_eq!(d.resolution_url(), "https://example.com/.well-known/did.json");
        let fp = thumbprint(&key(4).verifying_key().to_bytes());
        let s = format!("did:wba:example.com%3A3000:user:alice:e1_{fp}");
        let d = WbaDid::parse(&s).unwrap();
        assert_eq!(d.port, Some(3000));
        assert_eq!(d.e1(), Some(fp.as_str()));
        assert_eq!(d.resolution_url(), format!("https://example.com:3000/user/alice/e1_{fp}/did.json"));
        assert_eq!(d.to_string(), s, "round trip");
        assert!(WbaDid::parse("did:web:example.com").is_err());
        assert!(WbaDid::parse("did:wba:127.0.0.1").is_err(), "IP addresses are not allowed");
        assert!(WbaDid::parse("did:wba:example.com::x").is_err(), "empty segment");
        assert_eq!(WbaDid::parse("did:wba:example.com:user:alice").unwrap().e1(), None);
    }

    #[test]
    fn jcs_sorts_keys_and_writes_numbers_like_ecmascript() {
        assert_eq!(jcs(&json!({"b": 1, "a": "x", "c": [true, null]})).unwrap(), r#"{"a":"x","b":1,"c":[true,null]}"#);
        assert_eq!(jcs(&json!({"é": 1, "z": 2})).unwrap(), r#"{"z":2,"é":1}"#);
        assert_eq!(jcs(&json!({"a": 1.5, "b": 2.0, "c": -0.0, "d": 1e30, "e": 0.000001, "f": 1e-7, "g": 123456789012345680000.0, "h": 1e21})).unwrap(),
            r#"{"a":1.5,"b":2,"c":0,"d":1e+30,"e":0.000001,"f":1e-7,"g":123456789012345680000,"h":1e+21}"#);
        assert_eq!(es6_number(333333333.3333333).unwrap(), "333333333.3333333");
        assert_eq!(es6_number(f64::NAN), Err(DidError::Document("NaN and infinity cannot be canonicalised".into())));
    }

    #[test]
    fn a_document_verifies_and_yields_the_bound_key() {
        let (sk, did, d) = doc_for(7);
        let v = verify_document(&d, Some(&did)).unwrap();
        assert_eq!(v.key.to_bytes(), sk.verifying_key().to_bytes());
        assert_eq!(v.service_endpoint("AgentDescription").as_deref(), Some("https://branch.example.com:8800/tablet/ad.json"));
        verify_document(&d, None).unwrap();
    }

    #[test]
    fn building_for_the_wrong_key_is_refused() {
        let sk = key(7);
        let other = did_for_key("a.example.com", None, &[], &key(8).verifying_key().to_bytes());
        assert!(matches!(build_document(&other, &sk, &[], "2026-01-01T00:00:00Z"), Err(DidError::Binding(_))));
        assert!(build_document("did:wba:a.example.com", &sk, &[], "2026-01-01T00:00:00Z").is_err(), "no fingerprint");
    }

    #[test]
    fn tampering_with_any_part_is_caught() {
        let (_, did, d) = doc_for(7);
        // change a service endpoint
        let mut t = d.clone();
        t["service"][0]["serviceEndpoint"] = json!("https://evil.example.com/ad.json");
        assert!(matches!(verify_document(&t, Some(&did)), Err(DidError::Proof(_))));
        // add a second authentication key
        let mut t = d.clone();
        t["authentication"] = json!([format!("{did}#other")]);
        assert!(verify_document(&t, Some(&did)).is_err());
        // wrong expected DID
        let other = did_for_key("branch.example.com", Some(8800), &["agents", "tablet"], &key(9).verifying_key().to_bytes());
        assert!(verify_document(&d, Some(&other)).is_err());
        // missing proof
        let mut t = d.clone();
        t.as_object_mut().unwrap().remove("proof");
        assert!(matches!(verify_document(&t, Some(&did)), Err(DidError::Proof(_))));
        // corrupted signature
        let mut t = d.clone();
        let pv = t["proof"]["proofValue"].as_str().unwrap().to_string();
        let flipped = if pv.ends_with('A') { format!("{}B", &pv[..pv.len() - 1]) } else { format!("{}A", &pv[..pv.len() - 1]) };
        t["proof"]["proofValue"] = json!(flipped);
        assert!(verify_document(&t, Some(&did)).is_err());
    }

    #[test]
    fn a_document_signed_by_someone_else_cannot_claim_a_did() {
        // Mallory signs a document that says it is Alice's DID, with Mallory's key as the verification method.
        let alice = key(10);
        let alice_did = did_for_key("a.example.com", None, &["bot"], &alice.verifying_key().to_bytes());
        let mallory = key(11);
        let mut forged = doc_for(11).2;
        forged["id"] = json!(alice_did);
        assert!(verify_document(&forged, Some(&alice_did)).is_err(), "fingerprint binds the DID to Alice's key");
        // and Mallory cannot build one either
        assert!(build_document(&alice_did, &mallory, &[], "2026-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn legacy_path_dids_without_a_fingerprint_are_not_accepted() {
        let (_, _, mut d) = doc_for(7);
        d["id"] = json!("did:wba:branch.example.com%3A8800:agents:tablet");
        assert!(matches!(verify_document(&d, None), Err(DidError::Binding(_))));
    }

    #[test]
    fn a_key_agreement_key_is_published_covered_by_the_proof_and_read_back() {
        let sk = key(5);
        let did = did_for_key("a.example.com", None, &["agents", "alice"], &sk.verifying_key().to_bytes());
        let ka = [7u8; 32];
        let d = build_document_with_agreement(&did, &sk, &[], "2026-11-13T10:00:00Z", Some(&ka)).unwrap();
        let v = verify_document(&d, Some(&did)).unwrap();
        assert_eq!(v.key_agreement(), Some((key_agreement_id(&did), ka)));
        assert_eq!(d["keyAgreement"][0], json!(key_agreement_id(&did)), "referenced by id, like the SDK");
        assert_eq!(d["verificationMethod"][1]["type"], "X25519KeyAgreementKey2019");
        // swapping the key is caught by the document proof
        let mut t = d.clone();
        t["verificationMethod"][1]["publicKeyMultibase"] = json!(format!("z{}", bs58::encode([8u8; 32]).into_string()));
        assert!(verify_document(&t, Some(&did)).is_err());
        // a document without one just has none
        assert_eq!(verify_document(&build_document(&did, &sk, &[], "2026-11-13T10:00:00Z").unwrap(), None).unwrap().key_agreement(), None);
        // an entry whose controller is someone else is ignored
        let mut other = d.clone();
        other["verificationMethod"][1]["controller"] = json!("did:wba:evil.example.com:agents:x:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let vv = Verified { did: v.did.clone(), did_string: v.did_string.clone(), key: v.key, document: other };
        assert_eq!(vv.key_agreement(), None);
    }

    #[test]
    fn did_documents_carry_the_legacy_form_of_the_proof_that_every_sdk_reads() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let did = did_for_key("a.example.com", None, &["agents", "x"], &sk.verifying_key().to_bytes());
        let doc = build_document(&did, &sk, &[], "2026-11-15T10:00:00Z").unwrap();
        let pv = doc["proof"]["proofValue"].as_str().unwrap();
        assert_eq!(pv.len(), 86, "64 bytes as unpadded base64url");
        assert!(pv.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert!(decode_proof_value(pv).map(|(_, multibase)| !multibase).unwrap(), "read back as the legacy form");
        verify_document(&doc, Some(&did)).unwrap();
        // the multibase form is still read (and still written for prekey bundles)
        let mut m = json!({ "@context": ["https://www.w3.org/ns/did/v1"], "id": did });
        add_proof(&mut m, &sk, &format!("{did}#k"), "assertionMethod", "2026-11-15T10:00:00Z", &Map::new()).unwrap();
        assert!(m["proof"]["proofValue"].as_str().unwrap().starts_with('z'));
        verify_proof(&m, &sk.verifying_key()).unwrap();
        let mut l = json!({ "@context": ["https://www.w3.org/ns/did/v1"], "id": did });
        add_proof_legacy(&mut l, &sk, &format!("{did}#k"), "assertionMethod", "2026-11-15T10:00:00Z", &Map::new()).unwrap();
        verify_proof(&l, &sk.verifying_key()).unwrap();
        l["id"] = json!("did:wba:evil.example.com:x");
        assert!(verify_proof(&l, &sk.verifying_key()).is_err(), "and a changed document fails");
    }}
