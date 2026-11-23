//! The DID-WBA device binding: what ties an MLS leaf to a DID.
//!
//! A binding is a small signed object (`agent_did`, `device_id`, `verification_method`, the leaf's signature key, a validity window)
//! with an `eddsa-jcs-2022` object proof by the device's signing key, which the DID document must list under `assertionMethod` and in
//! its `deviceManifest` for that device with the group profile and its dependencies. The same canonical bytes are embedded in the MLS
//! LeafNode as a (draft) extension, the leaf's credential identity is the DID, and the leaf's key is the one the binding names: all
//! of that is checked by [`verify`], given the facts an MLS parser extracted ([`LeafEvidence`]).

use crate::wire::check_binding_structure;
use crate::*;
use anp_did::{SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const PROFILE_CORE_BINDING_V1: &str = "anp.core.binding.v1";
pub const PROFILE_IDENTITY_DISCOVERY_V1: &str = "anp.identity.discovery.v1";
pub const PROFILE_GROUP_BASE_V2: &str = "anp.group.base.v2";
pub const PROFILE_GROUP_E2EE_V2: &str = "anp.group.e2ee.v2";
/// What a device must list in its manifest entry to take part in P6 v2 (besides `anp.group.e2ee.v2`).
pub const P6_PROFILES: [&str; 4] = [PROFILE_CORE_BINDING_V1, PROFILE_IDENTITY_DISCOVERY_V1, PROFILE_GROUP_BASE_V2, PROFILE_GROUP_E2EE_V2];

/// An unsigned binding, checked.
pub fn unsigned_binding(agent_did: &str, device_id: &str, verification_method: &str, leaf_signature_key_b64u: &str, issued_at: &str, expires_at: &str) -> Result<Value, GroupError> {
    let v = json!({ "agent_did": agent_did, "device_id": device_id, "verification_method": verification_method, "leaf_signature_key_b64u": leaf_signature_key_b64u, "issued_at": issued_at, "expires_at": expires_at });
    check_unsigned(&v)?;
    Ok(v)
}

fn check_unsigned(v: &Value) -> Result<(), GroupError> {
    let w = "did_wba_binding";
    shape(v, w, &["agent_did", "device_id", "verification_method", "leaf_signature_key_b64u", "issued_at", "expires_at"], &[])?;
    for k in ["agent_did", "device_id", "verification_method"] {
        non_empty(v, k, w)?;
    }
    ed25519_b64u(v, "leaf_signature_key_b64u", w)?;
    rfc3339(v, "issued_at", w)?;
    rfc3339(v, "expires_at", w)
}

/// Sign a binding with the device's signing key (the one `verification_method` names). `created` is the proof's timestamp.
pub fn sign(unsigned: &Value, sk: &SigningKey, created: &str) -> Result<Value, GroupError> {
    check_unsigned(unsigned)?;
    let vm = unsigned["verification_method"].as_str().unwrap_or_default().to_string();
    let mut v = unsigned.clone();
    anp_did::add_proof(&mut v, sk, &vm, "assertionMethod", created, &Map::new()).map_err(|e| GroupError(e.to_string()))?;
    check_binding_structure(&v)?;
    Ok(v)
}

/// What an MLS parser found in a LeafNode (after verifying the KeyPackage's own signatures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafEvidence {
    pub credential_identity: Vec<u8>,
    pub leaf_signature_key_b64u: String,
    /// `(extension type, extension data)` of the LeafNode's extensions.
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// The extension types the leaf says it supports (capabilities).
    pub leaf_capability_extensions: Vec<u16>,
}

fn parse_time(what: &str, s: &str) -> Result<chrono::DateTime<chrono::Utc>, GroupError> {
    chrono::DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&chrono::Utc)).map_err(|_| GroupError(format!("{what} must be RFC 3339")))
}

fn require_capability_once(what: &str, exts: &[u16]) -> Result<(), GroupError> {
    if exts.iter().filter(|e| **e == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT).count() == 1 {
        Ok(())
    } else {
        err(format!("{what} must list the draft binding extension exactly once"))
    }
}

/// The manifest entry of `device_id` if it is currently eligible for P6 v2: its profiles include the group profile and everything
/// P6 depends on.
fn eligible_device<'a>(doc: &'a Value, device_id: &str) -> Option<&'a Value> {
    doc.pointer("/deviceManifest/devices")?.as_array()?.iter().find(|d| {
        d["device_id"] == device_id && {
            let profiles: Vec<&str> = d["profiles"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            P6_PROFILES.iter().all(|p| profiles.contains(p))
        }
    })
}

fn assertion_authorised(doc: &Value, vm: &str) -> bool {
    doc["assertionMethod"].as_array().map_or(false, |a| a.iter().any(|x| x.as_str() == Some(vm) || x["id"].as_str() == Some(vm)))
}

fn method_key(doc: &Value, vm: &str) -> Option<VerifyingKey> {
    let m = doc["verificationMethod"].as_array()?.iter().find(|m| m["id"].as_str() == Some(vm))?;
    if m["type"] != "Multikey" {
        return None;
    }
    let raw = anp_did::decode_multibase(m["publicKeyMultibase"].as_str()?).ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

/// Verify the whole chain: the structure; the DID document is the issuer's and (for a `did:wba`) is itself valid; the device is
/// P6-eligible and the binding's key is its manifest signing key; the object proof verifies against an `assertionMethod` key of the
/// document; the validity window holds at `now`; and the MLS evidence agrees (credential identity is the DID, the leaf key is the
/// binding's, exactly one binding extension whose data is the binding's canonical bytes, capabilities and group requirements list
/// the extension once). `negotiated` says that `anp.group.e2ee.v2` was explicitly negotiated: the extension is a draft.
pub fn verify(binding: &Value, issuer_document: &Value, evidence: &LeafEvidence, group_required_extensions: &[u16], now: &str, negotiated: bool) -> Result<(), GroupError> {
    check_binding_structure(binding)?;
    if !negotiated {
        return err("the draft MLS binding extension requires explicit anp.group.e2ee.v2 negotiation");
    }
    let did = binding["agent_did"].as_str().unwrap_or_default();
    if issuer_document["id"].as_str() != Some(did) {
        return err("did_wba_binding.agent_did must equal the issuer DID document id");
    }
    if did.starts_with("did:wba:") {
        anp_did::verify_document(issuer_document, None).map_err(|e| GroupError(format!("the issuer DID document does not verify: {e}")))?;
    }
    let device_id = binding["device_id"].as_str().unwrap_or_default();
    let device = eligible_device(issuer_document, device_id).ok_or_else(|| GroupError("did_wba_binding.device_id is not a current P6-eligible manifest device".into()))?;
    let vm = binding["verification_method"].as_str().unwrap_or_default();
    if device["signing_key_id"] != vm {
        return err("did_wba_binding.verification_method must equal the manifest signing_key_id");
    }
    // the object proof
    if !assertion_authorised(issuer_document, vm) {
        return err("the binding's signing key is not an assertionMethod of the DID document");
    }
    let key = method_key(issuer_document, vm).ok_or_else(|| GroupError("the binding's signing key is not an Ed25519 Multikey of the DID document".into()))?;
    anp_did::verify_proof(binding, &key).map_err(|e| GroupError(format!("the binding's proof does not verify: {e}")))?;
    // the validity window
    let (nowt, issued, expires) = (parse_time("now", now)?, parse_time("issued_at", binding["issued_at"].as_str().unwrap_or_default())?, parse_time("expires_at", binding["expires_at"].as_str().unwrap_or_default())?);
    if issued >= expires {
        return err("did_wba_binding issued_at must precede expires_at");
    }
    if nowt < issued || nowt >= expires {
        return err("did_wba_binding is not valid at the requested time");
    }
    // the MLS side
    if evidence.credential_identity.as_slice() != did.as_bytes() {
        return err("the MLS credential identity must equal the UTF-8 agent_did");
    }
    if evidence.leaf_signature_key_b64u != binding["leaf_signature_key_b64u"] {
        return err("the actual MLS leaf signature key must equal the binding's leaf key");
    }
    let found: Vec<&(u16, Vec<u8>)> = evidence.extensions.iter().filter(|(t, _)| *t == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT).collect();
    if found.len() != 1 {
        return err("the LeafNode must contain exactly one anp_did_wba_device_binding extension");
    }
    let canonical = anp_did::jcs(binding).map_err(|e| GroupError(e.to_string()))?;
    if found[0].1 != canonical.as_bytes() {
        return err("the embedded MLS binding extension must equal the canonical binding bytes");
    }
    require_capability_once("LeafNode capabilities.extensions", &evidence.leaf_capability_extensions)?;
    require_capability_once("GroupContext required_capabilities", group_required_extensions)
}

/// The GroupContext of a P6 group must require the binding extension (once).
pub fn check_group_required_capabilities(extensions: &[u16]) -> Result<(), GroupError> {
    require_capability_once("GroupContext required_capabilities", extensions)
}

/// A leaf of a group: DID, device and the MLS signature key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafIdentity {
    pub agent_did: String,
    pub device_id: String,
    pub leaf_signature_key_b64u: String,
}

/// Several devices of one DID may be in a group, but each `(DID, device)` pair once and every leaf with its own signature key.
pub fn check_leaf_identity_set(leaves: &[LeafIdentity]) -> Result<(), GroupError> {
    let (mut pairs, mut keys) = (BTreeSet::new(), BTreeSet::new());
    for l in leaves {
        if l.agent_did.is_empty() || l.device_id.is_empty() {
            return err("a leaf needs an agent_did and a device_id");
        }
        let probe = json!({ "k": l.leaf_signature_key_b64u });
        ed25519_b64u(&probe, "k", "leaf.leaf_signature_key_b64u")?;
        if !pairs.insert((l.agent_did.as_str(), l.device_id.as_str())) {
            return err("each (agent_did, device_id) leaf identity must be unique");
        }
        if !keys.insert(l.leaf_signature_key_b64u.as_str()) {
            return err("each device leaf must use a distinct MLS signature key");
        }
    }
    Ok(())
}