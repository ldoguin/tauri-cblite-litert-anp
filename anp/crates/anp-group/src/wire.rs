//! The P6 v2 objects, requests, results and notifications. Everything is a `serde_json::Value`, checked strictly.

use crate::*;
use serde_json::{json, Value};

// ── building blocks ─────────────────────────────────────────────────────────────────────────────────────

pub fn check_state_ref(v: &Value, what: &str) -> Result<(), GroupError> {
    shape(v, what, &["group_did", "group_state_version"], &["policy_hash", "roster_hash"])?;
    non_empty(v, "group_did", what)?;
    non_empty(v, "group_state_version", what)?;
    opt_non_empty(v, "policy_hash", what)?;
    opt_non_empty(v, "roster_hash", what)
}

fn check_target(v: &Value, kind: &str) -> Result<(), GroupError> {
    shape(v, "meta.target", &["kind", "did"], &[])?;
    equals(v, "kind", "meta.target", kind)?;
    non_empty(v, "did", "meta.target").map(|_| ())
}

#[derive(Clone, Copy)]
enum Meta {
    /// Service-scoped: key packages (transport-protected) and create (group-e2ee), target kind `service`.
    Service(&'static str),
    /// Create-add-remove style, group target.
    Control,
    /// `send`, group target.
    Send,
    /// The host's notice to one device, agent target.
    Notice,
    /// The host's delivery to one device, agent target.
    Incoming,
}

pub fn check_send_meta(v: &Value) -> Result<(), GroupError> {
    check_meta(v, Meta::Send)
}

pub fn check_control_meta(v: &Value) -> Result<(), GroupError> {
    check_meta(v, Meta::Control)
}

fn check_meta(v: &Value, kind: Meta) -> Result<(), GroupError> {
    let (security, target_kind, extra_req, with_sender_device): (&str, &str, &[&str], bool) = match kind {
        Meta::Service(s) => (s, "service", &[], true),
        Meta::Control => (SECURITY_PROFILE, "group", &[], true),
        Meta::Send => (SECURITY_PROFILE, "group", &["message_id", "content_type"], true),
        Meta::Notice => (TRANSPORT_PROFILE, "agent", &["recipient_device_id"], false),
        Meta::Incoming => (SECURITY_PROFILE, "agent", &["recipient_device_id", "message_id", "content_type"], true),
    };
    let mut required = vec!["profile", "security_profile", "sender_did", "target", "operation_id"];
    if with_sender_device {
        required.push("sender_device_id");
    }
    required.extend_from_slice(extra_req);
    shape(v, "meta", &required, &["anp_version", "created_at"])?;
    equals(v, "profile", "meta", PROFILE)?;
    equals(v, "security_profile", "meta", security)?;
    non_empty(v, "sender_did", "meta")?;
    if with_sender_device {
        non_empty(v, "sender_device_id", "meta")?;
    }
    check_target(&v["target"], target_kind)?;
    non_empty(v, "operation_id", "meta")?;
    opt_non_empty(v, "anp_version", "meta")?;
    if v.get("created_at").is_some() {
        rfc3339(v, "created_at", "meta")?;
    }
    for k in extra_req {
        non_empty(v, k, "meta")?;
    }
    if extra_req.contains(&"content_type") {
        equals(v, "content_type", "meta", CIPHER_CONTENT_TYPE)?;
    }
    Ok(())
}

/// The origin authentication a submission carries: the scheme and the RFC 9421 origin proof.
pub fn check_origin_auth(v: &Value, delivered: bool) -> Result<(), GroupError> {
    if delivered {
        shape(v, "auth", &["scheme", "origin_proof", "origin_context"], &[])?;
    } else {
        shape(v, "auth", &["scheme", "origin_proof"], &[])?;
    }
    equals(v, "scheme", "auth", ORIGIN_PROOF_SCHEME)?;
    shape(&v["origin_proof"], "auth.origin_proof", &["contentDigest", "signatureInput", "signature"], &[])?;
    for k in ["contentDigest", "signatureInput", "signature"] {
        non_empty(&v["origin_proof"], k, "auth.origin_proof")?;
    }
    if delivered {
        let c = &v["origin_context"];
        shape(c, "auth.origin_context", &[], &["created_at", "extra_meta"])?;
        if c.get("created_at").is_some() {
            rfc3339(c, "created_at", "auth.origin_context")?;
        }
        if let Some(extra) = c.get("extra_meta") {
            let m = object(extra, "auth.origin_context.extra_meta")?;
            const RESERVED: [&str; 10] = ["profile", "security_profile", "sender_did", "sender_device_id", "target", "recipient_device_id", "message_id", "operation_id", "content_type", "created_at"];
            if let Some(k) = m.keys().find(|k| RESERVED.contains(&k.as_str())) {
                return err(format!("auth.origin_context.extra_meta must not contain reserved field {k}"));
            }
        }
    }
    Ok(())
}

fn check_object_proof(v: &Value) -> Result<(), GroupError> {
    shape(v, "proof", &["type", "cryptosuite", "created", "proofPurpose", "verificationMethod", "proofValue"], &[])?;
    equals(v, "type", "proof", "DataIntegrityProof")?;
    equals(v, "cryptosuite", "proof", "eddsa-jcs-2022")?;
    equals(v, "proofPurpose", "proof", "assertionMethod")?;
    rfc3339(v, "created", "proof")?;
    non_empty(v, "verificationMethod", "proof")?;
    non_empty(v, "proofValue", "proof").map(|_| ())
}

/// The structure of a DID-WBA device binding (its signature is checked by `binding::verify`).
pub fn check_binding_structure(v: &Value) -> Result<(), GroupError> {
    let w = "did_wba_binding";
    shape(v, w, &["agent_did", "device_id", "verification_method", "leaf_signature_key_b64u", "issued_at", "expires_at", "proof"], &[])?;
    for k in ["agent_did", "device_id", "verification_method"] {
        non_empty(v, k, w)?;
    }
    ed25519_b64u(v, "leaf_signature_key_b64u", w)?;
    rfc3339(v, "issued_at", w)?;
    rfc3339(v, "expires_at", w)?;
    check_object_proof(&v["proof"])?;
    if v["proof"]["verificationMethod"] != v["verification_method"] {
        return err("proof.verificationMethod must equal did_wba_binding.verification_method");
    }
    Ok(())
}

pub fn check_key_package(v: &Value) -> Result<(), GroupError> {
    let w = "group_key_package";
    shape(v, w, &["key_package_id", "owner_did", "owner_device_id", "suite", "mls_key_package_b64u", "did_wba_binding"], &["expires_at"])?;
    for k in ["key_package_id", "owner_did", "owner_device_id"] {
        non_empty(v, k, w)?;
    }
    equals(v, "suite", w, MTI_SUITE)?;
    b64u(v, "mls_key_package_b64u", w)?;
    check_binding_structure(&v["did_wba_binding"])?;
    if v["owner_did"] != v["did_wba_binding"]["agent_did"] || v["owner_device_id"] != v["did_wba_binding"]["device_id"] {
        return err("group_key_package owner pair must equal did_wba_binding pair");
    }
    if v.get("expires_at").is_some() {
        rfc3339(v, "expires_at", w)?;
    }
    Ok(())
}

/// The body of `group.e2ee.send`, and the `group_cipher_object` of a delivery.
pub fn check_cipher_object(v: &Value) -> Result<(), GroupError> {
    let w = "group_cipher_object";
    shape(v, w, &["crypto_group_id_b64u", "epoch", "private_message_b64u", "group_state_ref"], &["epoch_authenticator"])?;
    b64u(v, "crypto_group_id_b64u", w)?;
    decimal(v, "epoch", w)?;
    b64u(v, "private_message_b64u", w)?;
    check_state_ref(&v["group_state_ref"], "group_state_ref")?;
    if v.get("epoch_authenticator").is_some() {
        b64u(v, "epoch_authenticator", w)?;
    }
    Ok(())
}

pub fn check_notice(v: &Value) -> Result<(), GroupError> {
    let w = "notice";
    shape(
        v,
        w,
        &["notice_id", "notice_type", "group_did", "group_state_ref", "crypto_group_id_b64u", "epoch", "subject_did", "subject_device_id", "subject_status"],
        &["commit_b64u", "welcome_b64u", "ratchet_tree_b64u", "epoch_authenticator", "group_receipt"],
    )?;
    for k in ["notice_id", "group_did", "subject_did", "subject_device_id"] {
        non_empty(v, k, w)?;
    }
    check_state_ref(&v["group_state_ref"], "group_state_ref")?;
    if v["group_state_ref"]["group_did"] != v["group_did"] {
        return err("notice group_state_ref.group_did must equal group_did");
    }
    b64u(v, "crypto_group_id_b64u", w)?;
    decimal(v, "epoch", w)?;
    if !matches!(string(v, "subject_status", w)?, "active" | "removed") {
        return err("subject_status must be active or removed");
    }
    let has = |k: &str| v.get(k).is_some();
    match string(v, "notice_type", w)? {
        "commit-delivery" => {
            b64u(v, "commit_b64u", w)?;
            if has("welcome_b64u") || has("ratchet_tree_b64u") {
                return err("commit-delivery must omit welcome_b64u and ratchet_tree_b64u");
            }
        }
        "welcome-delivery" => {
            b64u(v, "welcome_b64u", w)?;
            b64u(v, "ratchet_tree_b64u", w)?;
            if has("commit_b64u") {
                return err("welcome-delivery must omit commit_b64u");
            }
        }
        _ => return err("notice_type must be commit-delivery or welcome-delivery"),
    }
    if has("epoch_authenticator") {
        b64u(v, "epoch_authenticator", w)?;
    }
    if has("group_receipt") {
        json_object(v, "group_receipt", w)?;
    }
    Ok(())
}

fn check_incoming_body(v: &Value) -> Result<(), GroupError> {
    let w = "body";
    shape(v, w, &["group_did", "group_state_version", "group_event_seq", "accepted_at", "group_receipt", "group_cipher_object"], &[])?;
    non_empty(v, "group_did", w)?;
    non_empty(v, "group_state_version", w)?;
    decimal(v, "group_event_seq", w)?;
    rfc3339(v, "accepted_at", w)?;
    json_object(v, "group_receipt", w)?;
    check_cipher_object(&v["group_cipher_object"])?;
    let r = &v["group_cipher_object"]["group_state_ref"];
    if r["group_did"] != v["group_did"] || r["group_state_version"] != v["group_state_version"] {
        return err("incoming ordering fields must equal group_cipher_object.group_state_ref");
    }
    Ok(())
}

// ── requests ────────────────────────────────────────────────────────────────────────────────────────────

pub fn check_add_body(body: &Value) -> Result<(), GroupError> {
    shape(body, "body", &["member_did", "member_device_id", "group_state_ref", "group_key_package", "crypto_group_id_b64u", "epoch", "commit_b64u", "welcome_b64u", "ratchet_tree_b64u"], &[])?;
    non_empty(body, "member_did", "body")?;
    non_empty(body, "member_device_id", "body")?;
    check_state_ref(&body["group_state_ref"], "group_state_ref")?;
    check_key_package(&body["group_key_package"])?;
    let p = &body["group_key_package"];
    if p["owner_did"] != body["member_did"] || p["owner_device_id"] != body["member_device_id"] {
        return err("group_key_package owner must equal add member pair");
    }
    for k in ["crypto_group_id_b64u", "commit_b64u", "welcome_b64u", "ratchet_tree_b64u"] {
        b64u(body, k, "body")?;
    }
    decimal(body, "epoch", "body")
}

pub fn check_remove_body(body: &Value) -> Result<(), GroupError> {
    shape(body, "body", &["member_did", "member_device_id", "group_state_ref", "crypto_group_id_b64u", "epoch", "commit_b64u"], &[])?;
    non_empty(body, "member_did", "body")?;
    non_empty(body, "member_device_id", "body")?;
    check_state_ref(&body["group_state_ref"], "group_state_ref")?;
    b64u(body, "crypto_group_id_b64u", "body")?;
    decimal(body, "epoch", "body")?;
    b64u(body, "commit_b64u", "body").map(|_| ())
}

fn same_group(target: &Value, state_ref: &Value) -> Result<(), GroupError> {
    if target["did"] != state_ref["group_did"] {
        return err("meta.target.did must equal group_state_ref.group_did");
    }
    Ok(())
}

fn validate(method: &str, meta: &Value, body: &Value, auth: Option<&Value>) -> Result<(), GroupError> {
    match method {
        METHOD_PUBLISH_KEY_PACKAGE => {
            check_meta(meta, Meta::Service(TRANSPORT_PROFILE))?;
            shape(body, "body", &["group_key_package"], &[])?;
            check_key_package(&body["group_key_package"])?;
            let p = &body["group_key_package"];
            if p["owner_did"] != meta["sender_did"] || p["owner_device_id"] != meta["sender_device_id"] {
                return err("published KeyPackage owner pair must equal sending device pair");
            }
        }
        METHOD_GET_KEY_PACKAGE => {
            check_meta(meta, Meta::Service(TRANSPORT_PROFILE))?;
            shape(body, "body", &["target_did", "target_device_id"], &["preferred_suite", "require_fresh"])?;
            non_empty(body, "target_did", "body")?;
            non_empty(body, "target_device_id", "body")?;
            if body.get("preferred_suite").is_some() {
                equals(body, "preferred_suite", "body", MTI_SUITE)?;
            }
            if body.get("require_fresh").map_or(false, |x| !x.is_boolean()) {
                return err("body.require_fresh must be a boolean");
            }
        }
        METHOD_CREATE => {
            check_meta(meta, Meta::Service(SECURITY_PROFILE))?;
            shape(body, "body", &["group_did", "group_state_ref", "suite", "creator_key_package", "crypto_group_id_b64u", "epoch"], &[])?;
            non_empty(body, "group_did", "body")?;
            check_state_ref(&body["group_state_ref"], "group_state_ref")?;
            if body["group_state_ref"]["group_did"] != body["group_did"] {
                return err("group_state_ref.group_did must equal group_did");
            }
            equals(body, "suite", "body", MTI_SUITE)?;
            check_key_package(&body["creator_key_package"])?;
            b64u(body, "crypto_group_id_b64u", "body")?;
            decimal(body, "epoch", "body")?;
            check_origin_auth(auth.ok_or_else(|| GroupError("auth is required".into()))?, false)?;
            let p = &body["creator_key_package"];
            if p["owner_did"] != meta["sender_did"] || p["owner_device_id"] != meta["sender_device_id"] {
                return err("creator KeyPackage owner pair must equal sending owner device pair");
            }
        }
        METHOD_ADD => {
            check_meta(meta, Meta::Control)?;
            check_add_body(body)?;
            check_origin_auth(auth.ok_or_else(|| GroupError("auth is required".into()))?, false)?;
            same_group(&meta["target"], &body["group_state_ref"])?;
        }
        METHOD_REMOVE => {
            check_meta(meta, Meta::Control)?;
            check_remove_body(body)?;
            check_origin_auth(auth.ok_or_else(|| GroupError("auth is required".into()))?, false)?;
            same_group(&meta["target"], &body["group_state_ref"])?;
        }
        METHOD_SEND => {
            check_meta(meta, Meta::Send)?;
            check_cipher_object(body)?;
            check_origin_auth(auth.ok_or_else(|| GroupError("auth is required".into()))?, false)?;
            same_group(&meta["target"], &body["group_state_ref"])?;
        }
        METHOD_NOTICE => {
            check_meta(meta, Meta::Notice)?;
            check_notice(body)?;
            if body["notice_type"] == "welcome-delivery" && (meta["target"]["did"] != body["subject_did"] || meta["recipient_device_id"] != body["subject_device_id"]) {
                return err("welcome-delivery target must equal the added subject device pair");
            }
        }
        METHOD_INCOMING => {
            check_meta(meta, Meta::Incoming)?;
            check_incoming_body(body)?;
            check_origin_auth(auth.ok_or_else(|| GroupError("auth is required".into()))?, true)?;
        }
        m => return err(format!("unknown method {m}")),
    }
    if auth.is_some() && !matches!(method, METHOD_CREATE | METHOD_ADD | METHOD_REMOVE | METHOD_SEND | METHOD_INCOMING) {
        return err(format!("{method} carries no auth"));
    }
    Ok(())
}

/// Build a request or notification of `method` (validated). `auth` is needed by create, add, remove, send and incoming only.
pub fn request(method: &str, meta: &Value, body: &Value, auth: Option<&Value>) -> Result<Value, GroupError> {
    validate(method, meta, body, auth)?;
    let mut params = json!({ "meta": meta, "body": body });
    if let Some(a) = auth {
        params["auth"] = a.clone();
    }
    Ok(json!({ "method": method, "params": params }))
}

/// Parse a request or notification: `(meta, body, auth)`.
pub fn parse_request(method: &str, v: &Value) -> Result<(Value, Value, Option<Value>), GroupError> {
    shape(v, "request", &["method", "params"], &[])?;
    if v["method"] != method {
        return err(format!("method must equal {method}"));
    }
    let needs_auth = matches!(method, METHOD_CREATE | METHOD_ADD | METHOD_REMOVE | METHOD_SEND | METHOD_INCOMING);
    if needs_auth {
        shape(&v["params"], "params", &["meta", "body", "auth"], &[])?;
    } else {
        shape(&v["params"], "params", &["meta", "body"], &[])?;
    }
    let p = &v["params"];
    let auth = p.get("auth");
    validate(method, &p["meta"], &p["body"], auth)?;
    Ok((p["meta"].clone(), p["body"].clone(), auth.cloned()))
}

// ── results ─────────────────────────────────────────────────────────────────────────────────────────────

fn must_be_true(v: &Value, k: &str) -> Result<(), GroupError> {
    if v[k] != true {
        return err(format!("{k} must be true in a successful result"));
    }
    Ok(())
}

pub fn check_publish_key_package_result(v: &Value) -> Result<(), GroupError> {
    shape(v, "result", &["published", "owner_did", "owner_device_id", "key_package_id", "published_at"], &[])?;
    must_be_true(v, "published")?;
    for k in ["owner_did", "owner_device_id", "key_package_id"] {
        non_empty(v, k, "result")?;
    }
    rfc3339(v, "published_at", "result")
}

pub fn check_get_key_package_result(v: &Value) -> Result<(), GroupError> {
    shape(v, "result", &["target_did", "target_device_id", "group_key_package"], &[])?;
    non_empty(v, "target_did", "result")?;
    non_empty(v, "target_device_id", "result")?;
    check_key_package(&v["group_key_package"])?;
    if v["target_did"] != v["group_key_package"]["owner_did"] || v["target_device_id"] != v["group_key_package"]["owner_device_id"] {
        return err("get result target pair must equal group_key_package owner pair");
    }
    Ok(())
}

pub fn check_create_result(v: &Value) -> Result<(), GroupError> {
    shape(v, "result", &["created", "group_did", "group_state_ref", "crypto_group_id_b64u", "epoch", "accepted_at"], &[])?;
    must_be_true(v, "created")?;
    non_empty(v, "group_did", "result")?;
    check_state_ref(&v["group_state_ref"], "group_state_ref")?;
    if v["group_state_ref"]["group_did"] != v["group_did"] {
        return err("result group_state_ref.group_did must equal group_did");
    }
    b64u(v, "crypto_group_id_b64u", "result")?;
    decimal(v, "epoch", "result")?;
    rfc3339(v, "accepted_at", "result")
}

/// The result of add and of remove.
pub fn check_membership_result(v: &Value) -> Result<(), GroupError> {
    shape(v, "result", &["accepted", "group_did", "member_did", "member_device_id", "group_state_ref", "crypto_group_id_b64u", "epoch", "accepted_at"], &[])?;
    must_be_true(v, "accepted")?;
    for k in ["group_did", "member_did", "member_device_id"] {
        non_empty(v, k, "result")?;
    }
    check_state_ref(&v["group_state_ref"], "group_state_ref")?;
    if v["group_state_ref"]["group_did"] != v["group_did"] {
        return err("result group_state_ref.group_did must equal group_did");
    }
    b64u(v, "crypto_group_id_b64u", "result")?;
    decimal(v, "epoch", "result")?;
    rfc3339(v, "accepted_at", "result")
}

pub fn check_send_result(v: &Value) -> Result<(), GroupError> {
    shape(v, "result", &["accepted", "group_did", "message_id", "operation_id", "group_event_seq", "group_state_version", "accepted_at", "epoch", "group_receipt"], &[])?;
    must_be_true(v, "accepted")?;
    for k in ["group_did", "message_id", "operation_id", "group_state_version"] {
        non_empty(v, k, "result")?;
    }
    decimal(v, "group_event_seq", "result")?;
    decimal(v, "epoch", "result")?;
    rfc3339(v, "accepted_at", "result")?;
    json_object(v, "group_receipt", "result")
}