//! The exact bytes P6 v2 signs or encrypts around: the MLS `authenticated_data` of a send, the submission bindings of add and
//! remove (which the origin proof covers), and the canonical form of the group application plaintext. All are RFC 8785 JCS.

use crate::wire::*;
use crate::*;
use serde_json::{json, Value};

fn jcs(v: &Value) -> Result<Vec<u8>, GroupError> {
    anp_did::jcs(v).map(String::into_bytes).map_err(|e| GroupError(e.to_string()))
}

/// What a sender puts in the MLS `authenticated_data` of a group application message, so that the host-visible routing fields
/// are bound to the ciphertext.
pub fn send_authenticated_data(meta: &Value, body: &Value) -> Result<Vec<u8>, GroupError> {
    check_send_meta(meta)?;
    check_cipher_object(body)?;
    if body["group_state_ref"]["group_did"] != meta["target"]["did"] {
        return err("body.group_state_ref.group_did must equal meta.target.did");
    }
    jcs(&json!({
        "content_type": CIPHER_CONTENT_TYPE,
        "group_did": meta["target"]["did"],
        "crypto_group_id_b64u": body["crypto_group_id_b64u"],
        "group_state_ref": body["group_state_ref"],
        "security_profile": SECURITY_PROFILE,
        "sender_did": meta["sender_did"],
        "sender_device_id": meta["sender_device_id"],
        "message_id": meta["message_id"],
        "operation_id": meta["operation_id"],
    }))
}

fn membership_binding(method: &str, meta: &Value, body: &Value) -> Result<Vec<u8>, GroupError> {
    check_control_meta(meta)?;
    if body["group_state_ref"]["group_did"] != meta["target"]["did"] {
        return err("group_state_ref.group_did must equal meta.target.did");
    }
    jcs(&json!({
        "group_did": meta["target"]["did"],
        "crypto_group_id_b64u": body["crypto_group_id_b64u"],
        "group_state_ref": body["group_state_ref"],
        "subject_method": method,
        "member_did": body["member_did"],
        "member_device_id": body["member_device_id"],
        "epoch": body["epoch"],
        "security_profile": SECURITY_PROFILE,
        "sender_did": meta["sender_did"],
        "sender_device_id": meta["sender_device_id"],
        "operation_id": meta["operation_id"],
    }))
}

/// The submission binding of an Add *before* the commit exists (the commit is made with these bytes as its authenticated data, and
/// they do not cover the commit, welcome or tree, so the same bytes come out of [`add_submission_binding`] on the finished body).
pub fn add_submission_binding_for(meta: &Value, member_did: &str, member_device_id: &str, group_state_ref: &Value, crypto_group_id_b64u: &str, epoch: &str) -> Result<Vec<u8>, GroupError> {
    membership_binding_for(METHOD_ADD, meta, member_did, member_device_id, group_state_ref, crypto_group_id_b64u, epoch)
}

/// The same for a Remove.
pub fn remove_submission_binding_for(meta: &Value, member_did: &str, member_device_id: &str, group_state_ref: &Value, crypto_group_id_b64u: &str, epoch: &str) -> Result<Vec<u8>, GroupError> {
    membership_binding_for(METHOD_REMOVE, meta, member_did, member_device_id, group_state_ref, crypto_group_id_b64u, epoch)
}

fn membership_binding_for(method: &str, meta: &Value, member_did: &str, member_device_id: &str, group_state_ref: &Value, crypto_group_id_b64u: &str, epoch: &str) -> Result<Vec<u8>, GroupError> {
    let body = json!({ "member_did": member_did, "member_device_id": member_device_id, "group_state_ref": group_state_ref, "crypto_group_id_b64u": crypto_group_id_b64u, "epoch": epoch });
    check_state_ref(group_state_ref, "group_state_ref")?;
    non_empty(&body, "member_did", "body")?;
    non_empty(&body, "member_device_id", "body")?;
    b64u(&body, "crypto_group_id_b64u", "body")?;
    decimal(&body, "epoch", "body")?;
    membership_binding(method, meta, &body)
}

/// The binding of an Add submission (what the MLS commit is tied to).
pub fn add_submission_binding(meta: &Value, body: &Value) -> Result<Vec<u8>, GroupError> {
    check_add_body(body)?;
    membership_binding(METHOD_ADD, meta, body)
}

/// The binding of a Remove submission.
pub fn remove_submission_binding(meta: &Value, body: &Value) -> Result<Vec<u8>, GroupError> {
    check_remove_body(body)?;
    membership_binding(METHOD_REMOVE, meta, body)
}

/// The group application plaintext, checked: exactly one of `text`, `payload` (an object) or `payload_b64u`; `text/plain` uses `text`,
/// JSON content types use `payload`.
pub fn check_application_plaintext(v: &Value) -> Result<(), GroupError> {
    let w = "plaintext";
    shape(v, w, &["application_content_type"], &["thread_id", "reply_to_message_id", "annotations", "text", "payload", "payload_b64u"])?;
    let ct = non_empty(v, "application_content_type", w)?;
    opt_non_empty(v, "thread_id", w)?;
    opt_non_empty(v, "reply_to_message_id", w)?;
    if v.get("annotations").map_or(false, |a| !a.is_object()) {
        return err("annotations must be a JSON object");
    }
    let present = ["text", "payload", "payload_b64u"].iter().filter(|k| v.get(**k).is_some()).count();
    if present != 1 {
        return err("exactly one of text, payload, or payload_b64u must be present");
    }
    if v.get("text").is_some() {
        non_empty(v, "text", w)?;
    }
    if v.get("payload").map_or(false, |p| !p.is_object()) {
        return err("payload must be a JSON object");
    }
    if v.get("payload_b64u").is_some() {
        b64u(v, "payload_b64u", w)?;
    }
    if ct == "text/plain" && v.get("text").is_none() {
        return err("text/plain plaintext must use text");
    }
    if matches!(ct, "application/json" | "application/anp-attachment-manifest+json") && v.get("payload").is_none() {
        return err("JSON group plaintext must use payload");
    }
    Ok(())
}

/// The bytes that go into the MLS private message.
pub fn canonical_application_plaintext(v: &Value) -> Result<Vec<u8>, GroupError> {
    check_application_plaintext(v)?;
    jcs(v)
}

/// Read a decrypted plaintext.
pub fn parse_application_plaintext(bytes: &[u8]) -> Result<Value, GroupError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| GroupError(format!("the plaintext is not JSON: {e}")))?;
    check_application_plaintext(&v)?;
    Ok(v)
}