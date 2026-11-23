//! The RFC 9421 **origin proof** (ANP P1 appendix A): a sender signs the *signed request object* `{method, meta, body}` of a
//! submission, so that the group host can relay it and a recipient can still verify who it came from.
//!
//! The payload is the RFC 8785 form of the signed request object; `contentDigest` is `sha-256=:<base64>:` of it; the signature base
//! has one line per covered component (`"@method"`, `"@target-uri"` which here is the logical URI `anp://<kind>/<did>` with the DID
//! percent-encoded except `-._~`, and `"content-digest"`) and a last `"@signature-params"` line; the signature is Ed25519 over that
//! base, written `sig1=:<base64>:`. The key is the sender's DID `authentication` key named by `keyid`.

use crate::wire::check_origin_auth;
use crate::*;
use anp_did::{SigningKey, VerifyingKey};
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, Verifier};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const COMPONENTS: [&str; 3] = ["@method", "@target-uri", "content-digest"];
const LABEL: &str = "sig1";

fn canonical_request(method: &str, meta: &Value, body: &Value) -> Result<Vec<u8>, GroupError> {
    if method.trim().is_empty() {
        return err("method is required");
    }
    object(meta, "meta")?;
    object(body, "body")?;
    anp_did::jcs(&json!({ "method": method, "meta": meta, "body": body })).map(String::into_bytes).map_err(|e| GroupError(e.to_string()))
}

fn percent_encode_safe(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `anp://<kind>/<did>` for the target of `meta`.
pub fn logical_target_uri(meta: &Value) -> Result<String, GroupError> {
    let (kind, did) = (meta["target"]["kind"].as_str().unwrap_or_default().trim(), meta["target"]["did"].as_str().unwrap_or_default().trim());
    if !matches!(kind, "agent" | "group" | "service") {
        return err(format!("unsupported target kind: {kind}"));
    }
    if did.is_empty() {
        return err("target did is required");
    }
    Ok(format!("anp://{kind}/{}", percent_encode_safe(did)))
}

fn content_digest(payload: &[u8]) -> String {
    format!("sha-256=:{}:", B64.encode(Sha256::digest(payload)))
}

struct Parsed {
    keyid: String,
    params: String,
}

fn parse_signature_input(s: &str) -> Result<Parsed, GroupError> {
    let s = s.trim();
    let (label, rest) = s.split_once('=').ok_or_else(|| GroupError("invalid signatureInput".into()))?;
    if label != LABEL {
        return err("RFC 9421 origin proof requires signature label sig1");
    }
    let rest = rest.trim();
    let close = rest.find(')').filter(|_| rest.starts_with('(')).ok_or_else(|| GroupError("invalid signatureInput".into()))?;
    let comps: Vec<&str> = rest[1..close].split_whitespace().map(|c| c.trim_matches('"')).collect();
    if comps != COMPONENTS {
        return err("RFC 9421 origin proof requires covered components (\"@method\" \"@target-uri\" \"content-digest\")");
    }
    let mut keyid = None;
    for p in rest[close + 1..].split(';') {
        if let Some((n, v)) = p.trim().split_once('=') {
            if n == "keyid" {
                keyid = Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    Ok(Parsed { keyid: keyid.filter(|k| !k.is_empty()).ok_or_else(|| GroupError("signatureInput must include keyid".into()))?, params: rest.to_string() })
}

fn signature_base(method: &str, target_uri: &str, digest: &str, params: &str) -> Vec<u8> {
    format!("\"@method\": {method}\n\"@target-uri\": {target_uri}\n\"content-digest\": {digest}\n\"@signature-params\": {params}").into_bytes()
}

/// Sign a submission. `keyid` is the DID URL of the sender's authentication key; `nonce` any fresh string.
pub fn generate(method: &str, meta: &Value, body: &Value, sk: &SigningKey, keyid: &str, created: i64, expires: Option<i64>, nonce: &str) -> Result<Value, GroupError> {
    let payload = canonical_request(method, meta, body)?;
    let target = logical_target_uri(meta)?;
    let comps = COMPONENTS.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" ");
    let mut params = format!("({comps});created={created}");
    if let Some(e) = expires {
        params.push_str(&format!(";expires={e}"));
    }
    if !nonce.is_empty() {
        params.push_str(&format!(";nonce=\"{nonce}\""));
    }
    params.push_str(&format!(";keyid=\"{keyid}\""));
    let digest = content_digest(&payload);
    let base = signature_base(method, &target, &digest, &params);
    let sig = sk.sign(&base);
    Ok(json!({ "contentDigest": digest, "signatureInput": format!("{LABEL}={params}"), "signature": format!("{LABEL}=:{}:", B64.encode(sig.to_bytes())) }))
}

/// Verify a submission's origin proof. The key is the `authentication` key of `signer_document` named by the proof's `keyid`; if
/// `expected_signer_did` is given the `keyid` must be a key of that DID.
pub fn verify(proof: &Value, method: &str, meta: &Value, body: &Value, signer_document: &Value, expected_signer_did: Option<&str>) -> Result<(), GroupError> {
    let payload = canonical_request(method, meta, body)?;
    let target = logical_target_uri(meta)?;
    let get = |k: &str| proof[k].as_str().filter(|s| !s.is_empty()).ok_or_else(|| GroupError(format!("missing proof field: {k}")));
    let (digest, input, signature) = (get("contentDigest")?, get("signatureInput")?, get("signature")?);
    let parsed = parse_signature_input(input)?;
    if content_digest(&payload) != digest.trim() {
        return err("proof contentDigest does not match the request payload");
    }
    if let Some(did) = expected_signer_did {
        if parsed.keyid.split('#').next() != Some(did) {
            return err("proof keyid must belong to the expected signer DID");
        }
    }
    let key: VerifyingKey = anp_did::authentication_key(signer_document, &parsed.keyid).ok_or_else(|| GroupError("the keyid is not an authentication key of the signer's DID document".into()))?;
    let b64 = signature.trim().strip_prefix(&format!("{LABEL}=")).unwrap_or(signature.trim()).trim_matches(':');
    let raw = B64.decode(b64).map_err(|_| GroupError("invalid proof.signature encoding".into()))?;
    let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| GroupError("the signature must be 64 bytes".into()))?;
    key.verify(&signature_base(method, &target, digest.trim(), &parsed.params), &sig).map_err(|_| GroupError("the origin proof does not verify".into()))
}

/// The signed request object a recipient re-assembles from a `group.incoming` delivery: the host rewrote the target and the
/// timestamp, so the preserved `origin_context` says what they were.
pub fn reconstruct_send_request(meta: &Value, body: &Value, auth: &Value) -> Result<Value, GroupError> {
    check_origin_auth(auth, true)?;
    let mut m = serde_json::Map::new();
    for k in ["profile", "security_profile", "sender_did", "sender_device_id", "operation_id", "message_id", "content_type"] {
        m.insert(k.into(), meta[k].clone());
    }
    m.insert("target".into(), json!({ "kind": "group", "did": body["group_did"] }));
    let ctx = &auth["origin_context"];
    if let Some(c) = ctx.get("created_at") {
        m.insert("created_at".into(), c.clone());
    }
    if let Some(extra) = ctx.get("extra_meta").and_then(Value::as_object) {
        for (k, v) in extra {
            if m.insert(k.clone(), v.clone()).is_some() {
                return err(format!("auth.origin_context.extra_meta conflicts with reconstructed field {k}"));
            }
        }
    }
    Ok(json!({ "method": METHOD_SEND, "meta": m, "body": body["group_cipher_object"] }))
}

/// Verify the sender's proof preserved on a `group.incoming` delivery.
pub fn verify_incoming(meta: &Value, body: &Value, auth: &Value, signer_document: &Value, expected_signer_did: Option<&str>) -> Result<(), GroupError> {
    let req = reconstruct_send_request(meta, body, auth)?;
    verify(&auth["origin_proof"], METHOD_SEND, &req["meta"], &req["body"], signer_document, expected_signer_did)
}