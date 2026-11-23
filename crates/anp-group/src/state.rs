//! The `policy_hash` and `roster_hash` of a `group_state_ref`.
//!
//! The P6 wire objects carry both as optional, opaque strings (the SDK's vectors only show a placeholder, `sha-256:policy-v42`): the spec
//! does not say what is hashed. This project gives them a definition, so that a controller and a host that both follow it can check each
//! other, and **nothing is required of a peer that does not**: a state reference without them is accepted as before, and one that carries
//! them must carry the right ones.
//!
//! * `roster_hash` = `sha-256:` + lowercase hex of SHA-256 over the RFC 8785 form of the member list: an array of
//!   `{"did", "device_id", "leaf_key"}` objects (`leaf_key` is the MLS leaf signature key, base64url) sorted by DID, then device id. It
//!   names the roster *of the state the reference points at*, so a submission that creates version N+1 carries the roster after the change.
//! * `policy_hash` = the same over `{"max_members": N | null, "membership_change": "controller-only", "profile": "anp.group.e2ee.v2"}`.
//!   The host enforces exactly this policy: only the controller changes membership, and (when set) the group never grows past
//!   `max_members`.

use crate::PROFILE;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// One member of a roster: DID, device id, MLS leaf signature key (base64url).
pub type Entry = (String, String, String);

fn digest(v: &Value) -> String {
    // the values are plain strings, numbers and null, which RFC 8785 writes the same way serde_json does once the keys are sorted
    let text = anp_did::jcs(v).expect("a roster or a policy is canonicalisable");
    let h = Sha256::digest(text.as_bytes());
    let mut out = String::from("sha-256:");
    for b in h {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The hash of a roster; the order of `members` does not matter.
pub fn roster_hash(members: &[Entry]) -> String {
    let mut m: Vec<&Entry> = members.iter().collect();
    m.sort();
    digest(&Value::Array(m.iter().map(|(d, v, k)| json!({ "did": d, "device_id": v, "leaf_key": k })).collect()))
}

/// The hash of a group's policy.
pub fn policy_hash(max_members: Option<u64>) -> String {
    digest(&json!({ "max_members": max_members, "membership_change": "controller-only", "profile": PROFILE }))
}

/// A `group_state_ref` with both hashes.
pub fn state_ref(group_did: &str, version: u64, max_members: Option<u64>, members: &[Entry]) -> Value {
    json!({ "group_did": group_did, "group_state_version": version.to_string(), "policy_hash": policy_hash(max_members), "roster_hash": roster_hash(members) })
}

/// Check the hashes a reference carries (if any) against what they must be; `Err` says which one is wrong.
pub fn check_hashes(reference: &Value, max_members: Option<u64>, members: &[Entry]) -> Result<(), String> {
    if let Some(h) = reference.get("roster_hash").and_then(Value::as_str) {
        if h != roster_hash(members) {
            return Err("the roster_hash is not the hash of the roster of that state".into());
        }
    }
    if let Some(h) = reference.get("policy_hash").and_then(Value::as_str) {
        if h != policy_hash(max_members) {
            return Err("the policy_hash is not the hash of this group's policy".into());
        }
    }
    Ok(())
}
