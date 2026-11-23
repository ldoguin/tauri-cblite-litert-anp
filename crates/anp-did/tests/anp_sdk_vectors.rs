//! Checks against test vectors published by the ANP SDK (agent-network-protocol/anp, Apache-2.0; see
//! `testdata/anp-sdk/NOTICE.md`): documents it signed and canonical forms it expects. A pass means this code agrees
//! with another implementation, not just with itself.

use anp_did::{decode_multibase, jcs, verify_document, verify_proof, VerifyingKey};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../testdata/anp-sdk/direct_e2ee_p5_v2_wire_vectors.json")).unwrap()
}

#[test]
fn the_sdks_signed_did_document_verifies() {
    // A real e1 document: key-1 is the binding key (its thumbprint is the DID's fingerprint), `dev-a-sign` is a second
    // Ed25519 key, the proof is the SDK's legacy form (raw base64url, no @context in the proof options), and the X25519
    // key agreement key is a verification method referenced from `keyAgreement`.
    let g = &vectors()["signed_bundle_golden"];
    let doc = &g["did_document"];
    let id = doc["id"].as_str().unwrap();
    let v = verify_document(doc, Some(id)).expect("the SDK's document must verify");
    assert_eq!(v.did_string, id);
    let (ka_id, ka) = v.key_agreement().expect("a key-agreement key");
    assert!(ka_id.ends_with("#key-3"));
    assert_eq!(ka.len(), 32);
    // and tampering is still caught
    let mut t = doc.clone();
    t["deviceManifest"]["devices"][0]["device_id"] = Value::String("dev-evil".into());
    assert!(verify_document(&t, Some(id)).is_err());
}

#[test]
fn the_sdks_signed_prekey_bundle_has_a_valid_proof_by_the_device_signing_key() {
    // The bundle is signed by a *different* key (`dev-a-sign`) than the DID's binding key, with the multibase proof form.
    let g = &vectors()["signed_bundle_golden"];
    let doc = &g["did_document"];
    let vm = doc["verificationMethod"].as_array().unwrap().iter().find(|m| m["id"].as_str().unwrap().ends_with("#dev-a-sign")).unwrap();
    let key = VerifyingKey::from_bytes(&decode_multibase(vm["publicKeyMultibase"].as_str().unwrap()).unwrap()).unwrap();
    let bundle = &g["prekey_bundle"];
    verify_proof(bundle, &key).expect("the bundle's proof must verify");
    let mut t = bundle.clone();
    t["signed_prekey"]["key_id"] = Value::String("spk-evil".into());
    assert!(verify_proof(&t, &key).is_err());
}

#[test]
fn canonical_forms_match_the_sdks() {
    let v = vectors();
    // the object a bundle proof covers (the bundle without its proof)
    let mut b = v["prekey_bundle"].clone();
    b.as_object_mut().unwrap().remove("proof");
    assert_eq!(jcs(&b).unwrap(), v["expected_signed_bundle_object_jcs"].as_str().unwrap());
    // application plaintext, including the numbers RFC 8785 pins down (shortest form, exponents, -0)
    assert_eq!(jcs(&v["application_plaintext"]).unwrap(), v["expected_application_plaintext_jcs"].as_str().unwrap());
    assert_eq!(jcs(&v["application_plaintext_numeric"]).unwrap(), v["expected_application_plaintext_numeric_jcs"].as_str().unwrap());
}
