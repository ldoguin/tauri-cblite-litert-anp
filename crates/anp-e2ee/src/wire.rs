//! The P5 v2 wire objects: the `direct.send` request and result, the two prekey-bundle key-service calls and their
//! results, and the error table (ANP-09 `anp.direct.e2ee.v2`).
//!
//! These are the JSON-RPC `method` / `params` objects (a binding adds `jsonrpc` and `id`). Builders check what they are
//! given and parsers are strict in the way the ANP SDK's are: members that are not part of the object are refused,
//! `operation_id` must equal `message_id`, a published bundle must belong to the device that publishes it. Checked in the
//! tests against the SDK's published vectors and against its own builders and parsers (see `scripts/interop`).

use crate::{E2eeError, PROFILE, SECURITY_PROFILE, SUITE};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{json, Map, Value};

pub const TRANSPORT_PROTECTED: &str = "transport-protected";
pub const METHOD_DIRECT_SEND: &str = "direct.send";
pub const METHOD_PUBLISH: &str = "direct.e2ee.publish_prekey_bundle";
pub const METHOD_GET: &str = "direct.e2ee.get_prekey_bundle";
pub const INIT_CT: &str = crate::INIT_CONTENT_TYPE;
pub const CIPHER_CT: &str = crate::session::CIPHER_CONTENT_TYPE;

/// The P5 v2 error allocation: JSON-RPC code and ANP code.
pub const ERRORS: [(i32, &str); 13] = [
    (4000, "anp.direct.e2ee.bundle_not_found"),
    (4001, "anp.direct.e2ee.bundle_invalid"),
    (4002, "anp.direct.e2ee.bundle_expired"),
    (4003, "anp.direct.e2ee.opk_unavailable"),
    (4004, "anp.direct.e2ee.missing_key_agreement"),
    (4005, "anp.direct.e2ee.session_not_found"),
    (4006, "anp.direct.e2ee.session_conflict"),
    (4007, "anp.direct.e2ee.bad_init_message"),
    (4008, "anp.direct.e2ee.replay_detected"),
    (4009, "anp.direct.e2ee.decrypt_failed"),
    (4010, "anp.direct.e2ee.max_skip_exceeded"),
    (4011, "anp.direct.e2ee.reset_required"),
    (4012, "anp.direct.e2ee.invalid_security_binding"),
];

pub fn error_name(code: i32) -> Option<&'static str> {
    ERRORS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}
pub fn error_code(name: &str) -> Option<i32> {
    ERRORS.iter().find(|(_, n)| *n == name).map(|(c, _)| *c)
}

/// A JSON-RPC error object for a P5 failure: `{"code": 4009, "message": "anp.direct.e2ee.decrypt_failed", "data": {...}}`.
pub fn rpc_error(code: i32, detail: &str) -> Value {
    json!({ "code": code, "message": error_name(code).unwrap_or("unknown"), "data": { "anp_code": error_name(code), "detail": detail } })
}

/// Which P5 error a session failure is: replays and exhausted skip windows have their own codes.
pub fn error_code_for(e: &E2eeError) -> i32 {
    let m = e.0.as_str();
    if m.contains("too many messages skipped") {
        4010
    } else if m.contains("replay") {
        4008
    } else if m.contains("decryption failed") {
        4009
    } else if m.contains("session id") || m.contains("first reply") || m.contains("init") {
        4007
    } else {
        4012
    }
}

fn err<T>(s: impl Into<String>) -> Result<T, E2eeError> {
    Err(E2eeError(s.into()))
}

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, E2eeError> {
    v.as_object().ok_or_else(|| E2eeError(format!("{what} must be an object")))
}

/// `v` has exactly these members: all of `required`, and no member outside `required` and `optional`.
fn shape(v: &Value, what: &str, required: &[&str], optional: &[&str]) -> Result<(), E2eeError> {
    let m = obj(v, what)?;
    for k in required {
        if !m.contains_key(*k) {
            return err(format!("{what} needs {k}"));
        }
    }
    for k in m.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return err(format!("{what} has an unknown member {k}"));
        }
    }
    Ok(())
}
fn string<'a>(v: &'a Value, k: &str, what: &str) -> Result<&'a str, E2eeError> {
    match v[k].as_str() {
        Some(s) if !s.is_empty() => Ok(s),
        _ => err(format!("{what}.{k} must be a non-empty string")),
    }
}
fn opt_string(v: &Value, k: &str, what: &str) -> Result<(), E2eeError> {
    match v.get(k) {
        None => Ok(()),
        Some(Value::String(s)) if !s.is_empty() => Ok(()),
        _ => err(format!("{what}.{k} must be omitted rather than empty")),
    }
}
fn b64u_len(v: &Value, k: &str, what: &str, n: usize) -> Result<(), E2eeError> {
    let s = string(v, k, what)?;
    match B64U.decode(s) {
        Ok(b) if b.len() == n && B64U.encode(&b) == s => Ok(()),
        _ => err(format!("{what}.{k} must be {n} bytes of unpadded base64url")),
    }
}
fn b64u(v: &Value, k: &str, what: &str) -> Result<(), E2eeError> {
    let s = string(v, k, what)?;
    match B64U.decode(s) {
        Ok(_) => Ok(()),
        _ => err(format!("{what}.{k} must be unpadded base64url")),
    }
}
fn counter(v: &Value, k: &str, what: &str) -> Result<(), E2eeError> {
    let s = string(v, k, what)?;
    if s.chars().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0')) && s.parse::<u32>().is_ok() {
        Ok(())
    } else {
        err(format!("{what}.{k} must be a canonical decimal string"))
    }
}

/// RFC 3339 (the form `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`).
pub fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digit = |i: usize| b.get(i).map_or(false, u8::is_ascii_digit);
    let ok_date = (0..4).all(digit) && b[4] == b'-' && (5..7).all(digit) && b[7] == b'-' && (8..10).all(digit) && (b[10] == b'T' || b[10] == b't');
    let ok_time = (11..13).all(digit) && b[13] == b':' && (14..16).all(digit) && b[16] == b':' && (17..19).all(digit);
    if !(ok_date && ok_time) {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let s0 = i;
        while digit(i) {
            i += 1;
        }
        if i == s0 {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => b.len() == i + 6 && digit(i + 1) && digit(i + 2) && b[i + 3] == b':' && digit(i + 4) && digit(i + 5),
        _ => false,
    }
}
fn opt_time(v: &Value, k: &str, what: &str) -> Result<(), E2eeError> {
    match v.get(k) {
        None => Ok(()),
        Some(Value::String(s)) if is_rfc3339(s) => Ok(()),
        _ => err(format!("{what}.{k} must be RFC 3339")),
    }
}
fn time(v: &Value, k: &str, what: &str) -> Result<(), E2eeError> {
    if is_rfc3339(string(v, k, what)?) {
        Ok(())
    } else {
        err(format!("{what}.{k} must be RFC 3339"))
    }
}
fn target(v: &Value, kind: &str, what: &str) -> Result<(), E2eeError> {
    shape(&v["target"], &format!("{what}.target"), &["kind", "did"], &[])?;
    if v["target"]["kind"] != kind {
        return err(format!("{what}.target.kind must be {kind}"));
    }
    string(&v["target"], "did", &format!("{what}.target"))?;
    Ok(())
}

// ── metadata and bodies ─────────────────────────────────────────────────────────────────────────────────

/// Check the `meta` of a `direct.send` request.
pub fn validate_direct_meta(m: &Value) -> Result<(), E2eeError> {
    let what = "meta";
    shape(
        m,
        what,
        &["profile", "security_profile", "sender_did", "sender_device_id", "target", "recipient_device_id", "operation_id", "message_id", "content_type"],
        &["anp_version", "created_at"],
    )?;
    if m["profile"] != PROFILE || m["security_profile"] != SECURITY_PROFILE {
        return err("meta.profile or meta.security_profile is not P5 v2 direct E2EE");
    }
    for k in ["sender_did", "sender_device_id", "recipient_device_id", "operation_id", "message_id"] {
        string(m, k, what)?;
    }
    target(m, "agent", what)?;
    if m["content_type"] != INIT_CT && m["content_type"] != CIPHER_CT {
        return err("meta.content_type is not a P5 direct E2EE content type");
    }
    if m["operation_id"] != m["message_id"] {
        return err("operation_id must equal message_id");
    }
    opt_string(m, "anp_version", what)?;
    opt_time(m, "created_at", what)
}

/// Check the `meta` of a key-service call.
pub fn validate_service_meta(m: &Value) -> Result<(), E2eeError> {
    let what = "meta";
    shape(m, what, &["profile", "security_profile", "sender_did", "sender_device_id", "target", "operation_id"], &["anp_version", "created_at"])?;
    if m["profile"] != PROFILE || m["security_profile"] != TRANSPORT_PROTECTED {
        return err("meta.profile or meta.security_profile is not P5 v2 transport-protected");
    }
    for k in ["sender_did", "sender_device_id", "operation_id"] {
        string(m, k, what)?;
    }
    target(m, "service", what)?;
    opt_string(m, "anp_version", what)?;
    opt_time(m, "created_at", what)
}

pub fn validate_init_body(b: &Value) -> Result<(), E2eeError> {
    let what = "init body";
    shape(b, what, &["session_id", "suite", "sender_static_key_agreement_id", "recipient_bundle_id", "recipient_signed_prekey_id", "sender_ephemeral_pub_b64u", "ciphertext_b64u"], &["recipient_one_time_prekey_id"])?;
    if b["suite"] != SUITE {
        return err("unsupported cipher suite");
    }
    b64u_len(b, "session_id", what, 16)?;
    b64u_len(b, "sender_ephemeral_pub_b64u", what, 32)?;
    b64u(b, "ciphertext_b64u", what)?;
    for k in ["sender_static_key_agreement_id", "recipient_bundle_id", "recipient_signed_prekey_id"] {
        string(b, k, what)?;
    }
    opt_string(b, "recipient_one_time_prekey_id", what)
}

pub fn validate_cipher_body(b: &Value) -> Result<(), E2eeError> {
    let what = "cipher body";
    shape(b, what, &["session_id", "ratchet_header", "ciphertext_b64u"], &["suite"])?;
    b64u_len(b, "session_id", what, 16)?;
    b64u(b, "ciphertext_b64u", what)?;
    let h = &b["ratchet_header"];
    shape(h, "ratchet_header", &["dh_pub_b64u", "pn", "n"], &[])?;
    b64u_len(h, "dh_pub_b64u", "ratchet_header", 32)?;
    counter(h, "pn", "ratchet_header")?;
    counter(h, "n", "ratchet_header")?;
    if let Some(s) = b.get("suite") {
        if s != SUITE {
            return err("unsupported cipher suite");
        }
    }
    Ok(())
}

/// Check a signed prekey bundle's structure (its proof is checked against the owner's DID document by
/// [`crate::parse_bundle`]).
pub fn validate_bundle_shape(v: &Value) -> Result<(), E2eeError> {
    let what = "prekey_bundle";
    shape(v, what, &["bundle_id", "owner_did", "owner_device_id", "suite", "static_key_agreement_id", "signed_prekey", "proof"], &[])?;
    for k in ["bundle_id", "owner_did", "owner_device_id", "static_key_agreement_id"] {
        string(v, k, what)?;
    }
    if v["suite"] != SUITE {
        return err("unsupported cipher suite");
    }
    let spk = &v["signed_prekey"];
    shape(spk, "signed_prekey", &["key_id", "public_key_b64u", "expires_at"], &[])?;
    string(spk, "key_id", "signed_prekey")?;
    b64u_len(spk, "public_key_b64u", "signed_prekey", 32)?;
    time(spk, "expires_at", "signed_prekey")?;
    let p = &v["proof"];
    obj(p, "proof")?;
    if p["type"] != "DataIntegrityProof" || p["cryptosuite"] != "eddsa-jcs-2022" || p["proofPurpose"] != "assertionMethod" {
        return err("proof must be an eddsa-jcs-2022 DataIntegrityProof for assertionMethod");
    }
    for k in ["verificationMethod", "created", "proofValue"] {
        string(p, k, "proof")?;
    }
    Ok(())
}

fn validate_opk(v: &Value) -> Result<(), E2eeError> {
    shape(v, "one-time prekey", &["key_id", "public_key_b64u"], &[])?;
    string(v, "key_id", "one-time prekey")?;
    b64u_len(v, "public_key_b64u", "one-time prekey", 32)
}

// ── requests and results ────────────────────────────────────────────────────────────────────────────────

fn request(method: &str, meta: &Value, body: Value) -> Value {
    json!({ "method": method, "params": { "meta": meta, "body": body } })
}
fn parts<'a>(v: &'a Value, method: &str) -> Result<(&'a Value, &'a Value), E2eeError> {
    shape(v, "request", &["method", "params"], &[])?;
    if v["method"] != method {
        return err(format!("method must equal {method}"));
    }
    shape(&v["params"], "params", &["meta", "body"], &[])?;
    Ok((&v["params"]["meta"], &v["params"]["body"]))
}

/// A `direct.send` request carrying an init or a follow-up body; the body must match `meta.content_type`.
pub fn direct_send_request(meta: &Value, body: &Value) -> Result<Value, E2eeError> {
    validate_direct_meta(meta)?;
    if meta["content_type"] == INIT_CT {
        validate_init_body(body)?;
    } else {
        validate_cipher_body(body)?;
    }
    Ok(request(METHOD_DIRECT_SEND, meta, body.clone()))
}

/// Parse a `direct.send` request: the metadata, the body, and whether it is an init (`true`) or a follow-up.
pub fn parse_direct_send_request(v: &Value) -> Result<(Value, Value, bool), E2eeError> {
    let (meta, body) = parts(v, METHOD_DIRECT_SEND)?;
    validate_direct_meta(meta)?;
    let init = meta["content_type"] == INIT_CT;
    if init {
        validate_init_body(body)?;
    } else {
        validate_cipher_body(body)?;
    }
    Ok((meta.clone(), body.clone(), init))
}

pub fn direct_send_result(message_id: &str, target_did: &str, recipient_device_id: &str, accepted_at: &str) -> Value {
    json!({ "accepted": true, "message_id": message_id, "operation_id": message_id, "target_did": target_did, "recipient_device_id": recipient_device_id, "accepted_at": accepted_at })
}

pub fn parse_direct_send_result(v: &Value) -> Result<(), E2eeError> {
    shape(v, "result", &["accepted", "message_id", "operation_id", "target_did", "recipient_device_id", "accepted_at"], &[])?;
    if v["accepted"] != true {
        return err("accepted must be true in a successful result");
    }
    for k in ["message_id", "operation_id", "target_did", "recipient_device_id"] {
        string(v, k, "result")?;
    }
    if v["operation_id"] != v["message_id"] {
        return err("result.operation_id must equal result.message_id");
    }
    time(v, "accepted_at", "result")
}

/// `direct.e2ee.publish_prekey_bundle`: the sender publishes its own bundle and, optionally, one-time prekeys.
pub fn publish_prekey_bundle_request(meta: &Value, bundle: &Value, one_time_prekeys: &[Value]) -> Result<Value, E2eeError> {
    validate_service_meta(meta)?;
    validate_bundle_shape(bundle)?;
    for o in one_time_prekeys {
        validate_opk(o)?;
    }
    if bundle["owner_did"] != meta["sender_did"] || bundle["owner_device_id"] != meta["sender_device_id"] {
        return err("a published bundle must belong to the device that publishes it");
    }
    let mut body = json!({ "prekey_bundle": bundle });
    if !one_time_prekeys.is_empty() {
        body["one_time_prekeys"] = Value::Array(one_time_prekeys.to_vec());
    }
    Ok(request(METHOD_PUBLISH, meta, body))
}

pub fn parse_publish_prekey_bundle_request(v: &Value) -> Result<(Value, Value, Vec<Value>), E2eeError> {
    let (meta, body) = parts(v, METHOD_PUBLISH)?;
    validate_service_meta(meta)?;
    shape(body, "body", &["prekey_bundle"], &["one_time_prekeys"])?;
    validate_bundle_shape(&body["prekey_bundle"])?;
    let opks: Vec<Value> = match body.get("one_time_prekeys") {
        None => vec![],
        Some(Value::Array(a)) if !a.is_empty() => a.clone(),
        _ => return err("one_time_prekeys must be omitted or non-empty"),
    };
    for o in &opks {
        validate_opk(o)?;
    }
    if body["prekey_bundle"]["owner_did"] != meta["sender_did"] || body["prekey_bundle"]["owner_device_id"] != meta["sender_device_id"] {
        return err("a published bundle must belong to the device that publishes it");
    }
    Ok((meta.clone(), body["prekey_bundle"].clone(), opks))
}

pub fn publish_prekey_bundle_result(owner_did: &str, owner_device_id: &str, bundle_id: &str, published_at: &str, published_opk_count: u64) -> Value {
    json!({ "published": true, "owner_did": owner_did, "owner_device_id": owner_device_id, "bundle_id": bundle_id, "published_at": published_at, "published_opk_count": published_opk_count })
}

pub fn parse_publish_prekey_bundle_result(v: &Value) -> Result<(), E2eeError> {
    shape(v, "result", &["published", "owner_did", "owner_device_id", "bundle_id", "published_at", "published_opk_count"], &[])?;
    if v["published"] != true {
        return err("published must be true in a successful result");
    }
    for k in ["owner_did", "owner_device_id", "bundle_id"] {
        string(v, k, "result")?;
    }
    time(v, "published_at", "result")?;
    if v["published_opk_count"].as_u64().is_none() {
        return err("published_opk_count must be a non-negative integer");
    }
    Ok(())
}

/// `direct.e2ee.get_prekey_bundle`: ask the key service for a device's bundle (and a one-time prekey).
pub fn get_prekey_bundle_request(meta: &Value, target_did: &str, target_device_id: &str, preferred_suite: Option<&str>, require_opk: Option<bool>) -> Result<Value, E2eeError> {
    validate_service_meta(meta)?;
    if target_did.is_empty() || target_device_id.is_empty() {
        return err("target_did and target_device_id must be non-empty");
    }
    if preferred_suite == Some("") {
        return err("preferred_suite must be omitted rather than empty");
    }
    let mut body = json!({ "target_did": target_did, "target_device_id": target_device_id });
    if let Some(s) = preferred_suite {
        body["preferred_suite"] = json!(s);
    }
    if let Some(r) = require_opk {
        body["require_opk"] = json!(r);
    }
    Ok(request(METHOD_GET, meta, body))
}

/// Parse a get request: the metadata, the target DID and device, the preferred suite and whether a one-time prekey is required.
pub fn parse_get_prekey_bundle_request(v: &Value) -> Result<(Value, String, String, Option<String>, bool), E2eeError> {
    let (meta, body) = parts(v, METHOD_GET)?;
    validate_service_meta(meta)?;
    shape(body, "body", &["target_did", "target_device_id"], &["preferred_suite", "require_opk"])?;
    let (did, dev) = (string(body, "target_did", "body")?, string(body, "target_device_id", "body")?);
    opt_string(body, "preferred_suite", "body")?;
    if body.get("require_opk").map_or(false, |r| !r.is_boolean()) {
        return err("body.require_opk must be a boolean");
    }
    Ok((meta.clone(), did.to_string(), dev.to_string(), body["preferred_suite"].as_str().map(str::to_string), body["require_opk"].as_bool().unwrap_or(false)))
}

pub fn get_prekey_bundle_result(target_did: &str, target_device_id: &str, bundle: &Value, one_time_prekey: Option<&Value>) -> Value {
    let mut v = json!({ "target_did": target_did, "target_device_id": target_device_id, "prekey_bundle": bundle });
    if let Some(o) = one_time_prekey {
        v["one_time_prekey"] = o.clone();
    }
    v
}

pub fn parse_get_prekey_bundle_result(v: &Value) -> Result<(), E2eeError> {
    shape(v, "result", &["target_did", "target_device_id", "prekey_bundle"], &["one_time_prekey"])?;
    string(v, "target_did", "result")?;
    string(v, "target_device_id", "result")?;
    validate_bundle_shape(&v["prekey_bundle"])?;
    if v["prekey_bundle"]["owner_did"] != v["target_did"] || v["prekey_bundle"]["owner_device_id"] != v["target_device_id"] {
        return err("the returned bundle is not the one asked for");
    }
    if let Some(o) = v.get("one_time_prekey") {
        validate_opk(o)?;
    }
    Ok(())
}
