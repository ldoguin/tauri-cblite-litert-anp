//! ANP P6 (group end-to-end encryption), v2: the **wire layer**.
//!
//! This crate has the objects and rules of the `anp.group.e2ee.v2` profile that do not need an MLS implementation:
//!
//! * every request, result and notification of the seven methods (`publish_key_package`, `get_key_package`, `create`, `add`, `remove`,
//!   `send`, plus the host's `notice` and `incoming` notifications), built and parsed strictly (no unknown member, no `null` for an
//!   optional member, counters as canonical decimal strings, `base64url` without padding);
//! * the exact RFC 8785 bytes that P6 puts in MLS `authenticated_data` for a send, the submission bindings of add and remove, and the
//!   canonical form of the group application plaintext (`aad`);
//! * the DID-WBA **device binding** that ties an MLS leaf to a DID, a manifest device and a signature key (`binding`);
//! * the RFC 9421 **origin proof** a sender puts on a submission and a host preserves on delivery (`origin`).
//!
//! The MLS part (key packages, welcomes, commits, private messages) is not here: those fields are carried as opaque base64url.
//! The draft binding extension has no registered MLS code point (`DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED` is `false`), and the
//! SDK's own public-release check fails for that reason; so does [`ensure_public_release_ready`].

pub mod aad;
pub mod binding;
pub mod origin;
pub mod state;
pub mod wire;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use serde_json::{Map, Value};
use std::fmt;

pub const PROFILE: &str = "anp.group.e2ee.v2";
pub const SECURITY_PROFILE: &str = "group-e2ee";
pub const TRANSPORT_PROFILE: &str = "transport-protected";
pub const CIPHER_CONTENT_TYPE: &str = "application/anp-group-cipher+json";
pub const MTI_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
/// The draft MLS leaf extension that carries the DID-WBA binding.
pub const DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT: u16 = 0xF0A1;
pub const DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED: bool = false;
pub const ORIGIN_PROOF_SCHEME: &str = "anp-rfc9421-origin-proof-v1";

pub const METHOD_PUBLISH_KEY_PACKAGE: &str = "group.e2ee.publish_key_package";
pub const METHOD_GET_KEY_PACKAGE: &str = "group.e2ee.get_key_package";
pub const METHOD_CREATE: &str = "group.e2ee.create";
pub const METHOD_ADD: &str = "group.e2ee.add";
pub const METHOD_REMOVE: &str = "group.e2ee.remove";
pub const METHOD_SEND: &str = "group.e2ee.send";
pub const METHOD_NOTICE: &str = "group.e2ee.notice";
pub const METHOD_INCOMING: &str = "group.incoming";

/// The P6 v2 error allocation: JSON-RPC code and ANP code.
pub const ERRORS: [(i32, &str); 14] = [
    (5000, "group.e2ee.key_package_not_found"),
    (5001, "group.e2ee.invalid_key_package"),
    (5002, "group.e2ee.did_binding_invalid"),
    (5003, "group.e2ee.controller_required"),
    (5004, "group.e2ee.state_not_ready"),
    (5005, "group.e2ee.epoch_conflict"),
    (5006, "group.e2ee.crypto_group_mismatch"),
    (5007, "group.e2ee.private_message_invalid"),
    (5008, "group.e2ee.commit_invalid"),
    (5009, "group.e2ee.welcome_invalid"),
    (5010, "group.e2ee.fork_suspected"),
    (5011, "group.e2ee.notice_type_unsupported"),
    (5012, "group.e2ee.key_package_consumed"),
    (5013, "group.e2ee.leaf_not_current"),
];

pub fn error_name(code: i32) -> Option<&'static str> {
    ERRORS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// A JSON-RPC error object for a P6 failure.
pub fn rpc_error(code: i32, detail: &str) -> Value {
    serde_json::json!({ "code": code, "message": error_name(code).unwrap_or("unknown"), "data": { "anp_code": error_name(code), "detail": detail } })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupError(pub String);

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid P6 v2 object: {}", self.0)
    }
}
impl std::error::Error for GroupError {}

pub(crate) fn err<T>(s: impl Into<String>) -> Result<T, GroupError> {
    Err(GroupError(s.into()))
}

/// The SDK's public-release gate: the draft binding extension is not registered, so a release must not rely on it.
pub fn ensure_public_release_ready() -> Result<(), GroupError> {
    if DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED {
        Ok(())
    } else {
        err("public release is blocked until the draft MLS binding extension has a stable registered code point")
    }
}

// ── the checks every object uses ─────────────────────────────────────────────────────────────────────────

pub(crate) fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, GroupError> {
    v.as_object().ok_or_else(|| GroupError(format!("{what} must be an object")))
}

/// `v` has all of `required`, nothing outside `required` and `optional`, and no `null` anywhere among its members.
pub(crate) fn shape(v: &Value, what: &str, required: &[&str], optional: &[&str]) -> Result<(), GroupError> {
    let m = object(v, what)?;
    for k in required {
        if !m.contains_key(*k) {
            return err(format!("{what} needs {k}"));
        }
    }
    for (k, x) in m {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return err(format!("{what} has an unknown member {k}"));
        }
        if x.is_null() {
            return err(format!("{what}.{k} must not be null (leave it out)"));
        }
    }
    Ok(())
}

pub(crate) fn string<'a>(v: &'a Value, k: &str, what: &str) -> Result<&'a str, GroupError> {
    v[k].as_str().ok_or_else(|| GroupError(format!("{what}.{k} must be a string")))
}

pub(crate) fn non_empty<'a>(v: &'a Value, k: &str, what: &str) -> Result<&'a str, GroupError> {
    let s = string(v, k, what)?;
    if s.is_empty() {
        return err(format!("{what}.{k} must be a non-empty string"));
    }
    Ok(s)
}

pub(crate) fn opt_non_empty(v: &Value, k: &str, what: &str) -> Result<(), GroupError> {
    if v.get(k).is_some() {
        non_empty(v, k, what)?;
    }
    Ok(())
}

pub(crate) fn equals(v: &Value, k: &str, what: &str, expected: &str) -> Result<(), GroupError> {
    if string(v, k, what)? != expected {
        return err(format!("{what}.{k} must equal {expected}"));
    }
    Ok(())
}

/// A canonical unsigned decimal string: digits only, no leading zero (except `0` itself).
pub(crate) fn decimal(v: &Value, k: &str, what: &str) -> Result<(), GroupError> {
    let s = string(v, k, what)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s != "0" && s.starts_with('0')) {
        return err(format!("{what}.{k} must be a canonical unsigned decimal string"));
    }
    Ok(())
}

/// Unpadded, canonical, non-empty base64url; the decoded bytes.
pub(crate) fn b64u(v: &Value, k: &str, what: &str) -> Result<Vec<u8>, GroupError> {
    let s = non_empty(v, k, what)?;
    if s.contains('=') {
        return err(format!("{what}.{k} must be unpadded base64url"));
    }
    let raw = B64U.decode(s).map_err(|_| GroupError(format!("{what}.{k} must be base64url")))?;
    if raw.is_empty() || B64U.encode(&raw) != s {
        return err(format!("{what}.{k} must be canonical non-empty base64url"));
    }
    Ok(raw)
}

pub(crate) fn ed25519_b64u(v: &Value, k: &str, what: &str) -> Result<(), GroupError> {
    if b64u(v, k, what)?.len() != 32 {
        return err(format!("{what}.{k} must encode a 32-byte Ed25519 public key"));
    }
    Ok(())
}

pub(crate) fn rfc3339(v: &Value, k: &str, what: &str) -> Result<(), GroupError> {
    let s = string(v, k, what)?;
    chrono::DateTime::parse_from_rfc3339(s).map(|_| ()).map_err(|_| GroupError(format!("{what}.{k} must be RFC 3339")))
}

pub(crate) fn json_object(v: &Value, k: &str, what: &str) -> Result<(), GroupError> {
    if !v[k].is_object() {
        return err(format!("{what}.{k} must be a JSON object"));
    }
    Ok(())
}