//! ANP-07 agent descriptions.
//!
//! An agent description (AD) is a JSON document an agent publishes about itself: who it is (a `did:wba`), who runs
//! it, what information it offers and which interfaces it speaks, and how a caller authenticates. This crate builds
//! one, checks its shape against the ANP-07 field rules, signs it with the agent's DID key and verifies a signed one
//! against the agent's (already verified) DID document.
//!
//! Notes on the spec as written (v1.2): the member really is spelled `Infomations`; there is no `@context`; the only
//! proof it shows is ECDSA P-256, and it says nothing about EdDSA. Our agents hold Ed25519 keys, so the proof here is
//! the standard `DataIntegrityProof` / `eddsa-jcs-2022` suite (the same one the DID documents use), not the spec's
//! example suite. A strict ANP-07 verifier that only knows the example suite will not accept it; one that follows the
//! general rule (JCS, SHA-256, sign, `verificationMethod` is a key in the DID document) with this suite will.

pub mod discovery;
pub mod openrpc;

use anp_did::{VerifyingKey, Verified};
use serde_json::{json, Map, Value};
use std::fmt;

pub const PROTOCOL_TYPE: &str = "ANP";
pub const PROTOCOL_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdError(pub String);
impl fmt::Display for AdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent description: {}", self.0)
    }
}
impl std::error::Error for AdError {}
fn err<T>(s: impl Into<String>) -> Result<T, AdError> {
    Err(AdError(s.into()))
}

#[derive(Debug, Clone, Default)]
pub struct Info {
    /// `Product`, `Information`, `VideoObject`, …
    pub ty: String,
    pub description: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Interface {
    /// `NaturalLanguageInterface` or `StructuredInterface`.
    pub ty: String,
    /// `YAML`, `openrpc`, `MCP`, `WebRTC`, `A2A`, …
    pub protocol: String,
    pub version: Option<String>,
    pub url: String,
    pub description: Option<String>,
    pub human_authorization: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub name: String,
    pub did: String,
    /// Where this document is served.
    pub url: String,
    pub description: Option<String>,
    /// `(type, name, url)`, e.g. `("Organization", "Hotel Operator", "https://…")`.
    pub owner: Option<(String, String, String)>,
    /// RFC 3339.
    pub created: String,
    pub informations: Vec<Info>,
    pub interfaces: Vec<Interface>,
}

/// An unsigned AD. Authentication is advertised as `didwba` (ANP-02 request signatures in the `Authorization`
/// header), which is how every node in this mesh is reached.
pub fn build(s: &Spec) -> Value {
    let mut ad = Map::new();
    ad.insert("protocolType".into(), json!(PROTOCOL_TYPE));
    ad.insert("protocolVersion".into(), json!(PROTOCOL_VERSION));
    ad.insert("type".into(), json!("AgentDescription"));
    ad.insert("url".into(), json!(s.url));
    ad.insert("name".into(), json!(s.name));
    ad.insert("did".into(), json!(s.did));
    if let Some((ty, name, url)) = &s.owner {
        ad.insert("owner".into(), json!({ "type": ty, "name": name, "url": url }));
    }
    if let Some(d) = &s.description {
        ad.insert("description".into(), json!(d));
    }
    ad.insert("created".into(), json!(s.created));
    ad.insert("securityDefinitions".into(), json!({ "didwba_sc": { "scheme": "didwba", "in": "header", "name": "Authorization" } }));
    ad.insert("security".into(), json!("didwba_sc"));
    if !s.informations.is_empty() {
        let v: Vec<Value> = s
            .informations
            .iter()
            .map(|i| {
                let mut o = json!({ "type": i.ty, "description": i.description });
                if let Some(u) = &i.url {
                    o["url"] = json!(u);
                }
                o
            })
            .collect();
        ad.insert("Infomations".into(), Value::Array(v)); // sic, as in ANP-07
    }
    if !s.interfaces.is_empty() {
        let v: Vec<Value> = s
            .interfaces
            .iter()
            .map(|i| {
                let mut o = json!({ "type": i.ty, "protocol": i.protocol, "url": i.url });
                if let Some(x) = &i.version {
                    o["version"] = json!(x);
                }
                if let Some(x) = &i.description {
                    o["description"] = json!(x);
                }
                if let Some(x) = i.human_authorization {
                    o["humanAuthorization"] = json!(x);
                }
                o
            })
            .collect();
        ad.insert("interfaces".into(), Value::Array(v));
    }
    Value::Object(ad)
}

/// Describe an A2A agent card as an AD: the skills become `Infomations`, the A2A endpoint becomes a structured
/// interface. `a2a_url` is where the agent card is served.
pub fn from_a2a_card(card: &Value, did: &str, ad_url: &str, a2a_url: &str, created: &str) -> Value {
    let skills = card["skills"].as_array().cloned().unwrap_or_default();
    build(&Spec {
        name: card["name"].as_str().unwrap_or("agent").to_string(),
        did: did.to_string(),
        url: ad_url.to_string(),
        description: card["description"].as_str().map(str::to_string),
        owner: None,
        created: created.to_string(),
        informations: skills
            .iter()
            .map(|s| Info {
                ty: "Information".into(),
                description: format!("{}: {}", s["name"].as_str().unwrap_or(s["id"].as_str().unwrap_or("skill")), s["description"].as_str().unwrap_or("")),
                url: None,
            })
            .collect(),
        interfaces: vec![Interface {
            ty: "StructuredInterface".into(),
            protocol: "A2A".into(),
            version: card["version"].as_str().map(str::to_string),
            url: a2a_url.to_string(),
            description: Some("Agent2Agent task interface: SendMessage, GetTask, streaming".into()),
            human_authorization: None,
        }],
    })
}

/// Sign `ad` as `did`, with the key that the DID's document lists under `assertionMethod`
/// (`<did>#<e1 fingerprint>`). `binding` is an optional `(domain, challenge)`: the domain the document is served
/// from, which a verifier must check against where it fetched the document (ANP-07 requires `challenge` whenever
/// `domain` is given).
pub fn sign(ad: &mut Value, sk: &anp_did::SigningKey, did: &str, created: &str, binding: Option<(&str, &str)>) -> Result<(), AdError> {
    let parsed = anp_did::WbaDid::parse(did).map_err(|e| AdError(e.to_string()))?;
    let fp = parsed.e1().ok_or_else(|| AdError("the DID has no e1_ fingerprint".into()))?;
    if fp != anp_did::thumbprint(&sk.verifying_key().to_bytes()) {
        return err("the signing key is not the one this DID is bound to");
    }
    if ad["did"].as_str() != Some(did) {
        return err("the description does not name this DID");
    }
    let mut extra = Map::new();
    if let Some((domain, challenge)) = binding {
        if challenge.is_empty() {
            return err("a challenge is required with a domain");
        }
        extra.insert("domain".into(), json!(domain));
        extra.insert("challenge".into(), json!(challenge));
    }
    anp_did::add_proof_legacy(ad, sk, &format!("{did}#{fp}"), "assertionMethod", created, &extra).map_err(|e| AdError(e.to_string()))
}

const IN_VALUES: [&str; 6] = ["header", "query", "body", "cookie", "uri", "auto"];
/// Members a security scheme must not carry: ANP-07 forbids putting credentials in the description.
const SECRET_KEYS: [&str; 8] = ["password", "secret", "token", "apikey", "api_key", "privatekey", "private_key", "key"];

fn string_of<'a>(o: &'a Value, k: &str, what: &str) -> Result<&'a str, AdError> {
    match o.get(k).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => err(format!("{what} needs a non-empty string '{k}'")),
    }
}

/// Check the shape against the ANP-07 field rules. Does not look at the proof.
pub fn validate(ad: &Value) -> Result<(), AdError> {
    let o = ad.as_object().ok_or_else(|| AdError("not an object".into()))?;
    if o.get("protocolType").and_then(Value::as_str) != Some(PROTOCOL_TYPE) {
        return err("protocolType must be \"ANP\"");
    }
    string_of(ad, "protocolVersion", "the description")?;
    if o.get("type").and_then(Value::as_str) != Some("AgentDescription") {
        return err("type must be \"AgentDescription\"");
    }
    string_of(ad, "name", "the description")?;
    for k in ["url", "description", "created"] {
        if o.get(k).map_or(false, |v| !v.is_string()) {
            return err(format!("'{k}' must be a string"));
        }
    }
    if let Some(c) = o.get("created").and_then(Value::as_str) {
        let b = c.as_bytes();
        if c.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
            return err("'created' must be an ISO 8601 timestamp");
        }
    }
    if let Some(d) = o.get("did").and_then(Value::as_str) {
        anp_did::WbaDid::parse(d).map_err(|e| AdError(e.to_string()))?;
    } else if o.contains_key("did") {
        return err("'did' must be a string");
    }
    if let Some(ow) = o.get("owner") {
        if !ow.is_object() {
            return err("'owner' must be an object");
        }
    }
    // security
    let defs = o.get("securityDefinitions").and_then(Value::as_object).ok_or_else(|| AdError("securityDefinitions is required".into()))?;
    let active = string_of(ad, "security", "the description")?;
    if !defs.contains_key(active) {
        return err(format!("security names '{active}', which securityDefinitions does not define"));
    }
    for (name, def) in defs {
        let d = def.as_object().ok_or_else(|| AdError(format!("security definition '{name}' must be an object")))?;
        for k in d.keys() {
            if SECRET_KEYS.contains(&k.to_lowercase().as_str()) {
                return err(format!("security definition '{name}' must not carry credentials ('{k}')"));
            }
        }
        string_of(def, "scheme", &format!("security definition '{name}'"))?;
        let place = string_of(def, "in", &format!("security definition '{name}'"))?;
        if !IN_VALUES.contains(&place) {
            return err(format!("security definition '{name}': 'in' must be one of {IN_VALUES:?}"));
        }
        if place != "auto" {
            string_of(def, "name", &format!("security definition '{name}'"))?;
        }
    }
    // information and interfaces
    if let Some(v) = o.get("Infomations") {
        for (i, x) in v.as_array().ok_or_else(|| AdError("'Infomations' must be an array".into()))?.iter().enumerate() {
            for k in ["type", "description", "url"] {
                if x.get(k).map_or(false, |v| !v.is_string()) {
                    return err(format!("Infomations[{i}].{k} must be a string"));
                }
            }
        }
    }
    if let Some(v) = o.get("interfaces") {
        for (i, x) in v.as_array().ok_or_else(|| AdError("'interfaces' must be an array".into()))?.iter().enumerate() {
            let what = format!("interfaces[{i}]");
            string_of(x, "type", &what)?;
            string_of(x, "protocol", &what)?;
            string_of(x, "url", &what)?;
            if x.get("humanAuthorization").map_or(false, |v| !v.is_boolean()) {
                return err(format!("{what}.humanAuthorization must be a boolean"));
            }
        }
    }
    Ok(())
}

/// Verify a signed AD against the DID document of the agent that published it (verify that with
/// `anp_did::verify_document` first, from wherever you got it). Checks the shape, that the AD names this DID, that
/// the proof was made by an assertion key of that DID document, and the signature. `fetched_from` is the domain
/// (`host[:port]`) the AD was retrieved from: when the proof is bound to a domain it must match it.
pub fn verify(ad: &Value, did_doc: &Verified, fetched_from: Option<&str>) -> Result<(), AdError> {
    validate(ad)?;
    match ad["did"].as_str() {
        Some(d) if d == did_doc.did_string => {}
        Some(d) => return err(format!("describes {d}, not {}", did_doc.did_string)),
        None => return err("a signed description must name its DID"),
    }
    let proof = ad.get("proof").ok_or_else(|| AdError("not signed (no proof)".into()))?;
    if proof["proofPurpose"] != "assertionMethod" {
        return err("the proof's purpose must be assertionMethod");
    }
    let vm_ref = proof["verificationMethod"].as_str().ok_or_else(|| AdError("proof has no verificationMethod".into()))?;
    let vm_id = if let Some(frag) = vm_ref.strip_prefix('#') { format!("{}#{frag}", did_doc.did_string) } else { vm_ref.to_string() };
    if !did_doc.document["assertionMethod"].as_array().map_or(false, |a| a.iter().any(|x| x.as_str().map_or(false, |r| r == vm_id || r.strip_prefix('#').map_or(false, |f| format!("{}#{f}", did_doc.did_string) == vm_id)))) {
        return err("the signing key is not an assertionMethod of the DID document");
    }
    let vm = did_doc.document["verificationMethod"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["id"].as_str() == Some(vm_id.as_str())))
        .ok_or_else(|| AdError("the proof's key is not in the DID document".into()))?;
    let key_bytes = anp_did::decode_multibase(vm["publicKeyMultibase"].as_str().unwrap_or("")).map_err(|e| AdError(e.to_string()))?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AdError("invalid key".into()))?;

    match proof.get("domain").and_then(Value::as_str) {
        Some(domain) => {
            if proof.get("challenge").and_then(Value::as_str).map_or(true, str::is_empty) {
                return err("the proof names a domain but has no challenge");
            }
            if let Some(from) = fetched_from {
                if !domain.eq_ignore_ascii_case(from) {
                    return err(format!("signed for {domain} but fetched from {from}"));
                }
            }
        }
        None if proof.get("challenge").is_some() => {}
        None => {}
    }
    anp_did::verify_proof(ad, &key).map_err(|e| AdError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp_did::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn agent(seed: u8, name: &str) -> (SigningKey, String, Verified) {
        let sk = key(seed);
        let did = anp_did::did_for_key("hotel.example.com", Some(8800), &["agents", name], &sk.verifying_key().to_bytes());
        let doc = anp_did::build_document(&did, &sk, &[], "2026-11-13T10:00:00Z").unwrap();
        let v = anp_did::verify_document(&doc, Some(&did)).unwrap();
        (sk, did, v)
    }
    fn spec(did: &str, name: &str) -> Spec {
        Spec {
            name: name.into(),
            did: did.into(),
            url: format!("https://hotel.example.com:8800/agents/{name}/ad.json"),
            description: Some("Concierge".into()),
            owner: Some(("Organization".into(), "Hotel".into(), "https://hotel.example.com".into())),
            created: "2026-11-13T10:00:00Z".into(),
            informations: vec![Info { ty: "Information".into(), description: "Policies".into(), url: Some("https://hotel.example.com/info.json".into()) }],
            interfaces: vec![Interface {
                ty: "StructuredInterface".into(),
                protocol: "A2A".into(),
                version: Some("1.0".into()),
                url: "https://hotel.example.com:8800/.well-known/agent-card.json".into(),
                description: None,
                human_authorization: Some(false),
            }],
        }
    }
    fn signed(seed: u8, name: &str) -> (Value, Verified) {
        let (sk, did, v) = agent(seed, name);
        let mut ad = build(&spec(&did, name));
        sign(&mut ad, &sk, &did, "2026-11-13T10:05:00Z", Some(("hotel.example.com:8800", "n-123"))).unwrap();
        (ad, v)
    }

    #[test]
    fn a_built_description_has_the_anp07_shape() {
        let (_, did, _) = agent(1, "concierge");
        let ad = build(&spec(&did, "concierge"));
        validate(&ad).unwrap();
        assert_eq!(ad["protocolType"], "ANP");
        assert_eq!(ad["type"], "AgentDescription");
        assert_eq!(ad["security"], "didwba_sc");
        assert!(ad.get("Infomations").is_some(), "the member is spelled Infomations in the spec");
        assert!(ad.get("@context").is_none(), "ANP-07 defines no @context");
        assert_eq!(ad["securityDefinitions"]["didwba_sc"]["in"], "header");
    }

    #[test]
    fn a_signed_description_verifies_against_its_did_document() {
        let (ad, did_doc) = signed(1, "concierge");
        assert_eq!(ad["proof"]["cryptosuite"], "eddsa-jcs-2022");
        verify(&ad, &did_doc, Some("hotel.example.com:8800")).unwrap();
        verify(&ad, &did_doc, None).unwrap();
    }

    #[test]
    fn tampering_with_the_description_is_caught() {
        let (ad, did_doc) = signed(1, "concierge");
        let mut t = ad.clone();
        t["interfaces"][0]["url"] = json!("https://evil.example.com/a2a");
        assert!(verify(&t, &did_doc, None).unwrap_err().0.contains("signature"));
        let mut t = ad.clone();
        t["name"] = json!("Free money");
        assert!(verify(&t, &did_doc, None).is_err());
        let mut t = ad.clone();
        t.as_object_mut().unwrap().remove("proof");
        assert!(verify(&t, &did_doc, None).unwrap_err().0.contains("not signed"));
        let mut t = ad.clone();
        t["proof"]["domain"] = json!("evil.example.com"); // domain is covered by the signature
        assert!(verify(&t, &did_doc, None).is_err());
    }

    #[test]
    fn a_description_cannot_be_passed_off_as_another_agents() {
        let (ad, _) = signed(1, "concierge");
        let (_, other_did_doc) = (0, agent(2, "concierge").2);
        assert!(verify(&ad, &other_did_doc, None).unwrap_err().0.contains("describes"));
        // mallory signs a description that names the concierge's DID, pointing at the concierge's key
        let (_, did, real) = agent(1, "concierge");
        let mallory = key(9);
        let mut forged = build(&spec(&did, "concierge"));
        forged["name"] = json!("Concierge (totally)");
        anp_did::add_proof(&mut forged, &mallory, &format!("{did}#{}", anp_did::thumbprint(&real.key.to_bytes())), "assertionMethod", "2026-11-13T10:05:00Z", &Map::new()).unwrap();
        assert!(verify(&forged, &real, None).unwrap_err().0.contains("signature"));
        // and mallory cannot use the proper signing function without the key
        let mut ad2 = build(&spec(&did, "concierge"));
        assert!(sign(&mut ad2, &mallory, &did, "2026-11-13T10:05:00Z", None).is_err());
    }

    #[test]
    fn the_proof_can_be_bound_to_the_domain_it_is_served_from() {
        let (ad, did_doc) = signed(1, "concierge");
        assert!(verify(&ad, &did_doc, Some("elsewhere.example.com")).unwrap_err().0.contains("fetched from"));
        // a domain without a challenge is refused (ANP-07)
        let (sk, did, v) = agent(1, "concierge");
        let mut a = build(&spec(&did, "concierge"));
        assert!(sign(&mut a, &sk, &did, "2026-11-13T10:05:00Z", Some(("hotel.example.com:8800", ""))).is_err());
        let mut b = build(&spec(&did, "concierge"));
        let mut extra = Map::new();
        extra.insert("domain".into(), json!("hotel.example.com:8800"));
        anp_did::add_proof(&mut b, &sk, &format!("{did}#{}", anp_did::thumbprint(&sk.verifying_key().to_bytes())), "assertionMethod", "2026-11-13T10:05:00Z", &extra).unwrap();
        assert!(verify(&b, &v, None).unwrap_err().0.contains("no challenge"));
    }

    #[test]
    fn unsigned_descriptions_validate_but_do_not_verify() {
        let (_, did, v) = agent(1, "concierge");
        let ad = build(&spec(&did, "concierge"));
        validate(&ad).unwrap();
        assert!(verify(&ad, &v, None).is_err());
    }

    #[test]
    fn the_field_rules_are_enforced() {
        let (_, did, _) = agent(1, "x");
        let good = build(&spec(&did, "x"));
        let mutate = |f: &dyn Fn(&mut Value)| {
            let mut a = good.clone();
            f(&mut a);
            validate(&a)
        };
        assert!(mutate(&|a| a["protocolType"] = json!("MCP")).is_err());
        assert!(mutate(&|a| a["type"] = json!("Agent")).is_err());
        assert!(mutate(&|a| { a.as_object_mut().unwrap().remove("name"); }).is_err());
        assert!(mutate(&|a| { a.as_object_mut().unwrap().remove("securityDefinitions"); }).is_err());
        assert!(mutate(&|a| a["security"] = json!("nope")).unwrap_err().0.contains("does not define"));
        assert!(mutate(&|a| a["securityDefinitions"]["didwba_sc"]["in"] = json!("elsewhere")).is_err());
        assert!(mutate(&|a| { a["securityDefinitions"]["didwba_sc"].as_object_mut().unwrap().remove("name"); }).is_err(), "name is required unless in=auto");
        assert!(mutate(&|a| { a["securityDefinitions"]["didwba_sc"]["in"] = json!("auto"); a["securityDefinitions"]["didwba_sc"].as_object_mut().unwrap().remove("name"); }).is_ok());
        assert!(mutate(&|a| a["securityDefinitions"]["didwba_sc"]["password"] = json!("hunter2")).unwrap_err().0.contains("credentials"));
        assert!(mutate(&|a| a["interfaces"][0].as_object_mut().unwrap().remove("url").map(|_| ()).unwrap_or(())).is_err());
        assert!(mutate(&|a| a["interfaces"][0]["humanAuthorization"] = json!("yes")).is_err());
        assert!(mutate(&|a| a["did"] = json!("did:web:example.com")).is_err());
        assert!(mutate(&|a| a["created"] = json!("yesterday")).is_err());
        assert!(mutate(&|a| a["Infomations"] = json!("nope")).is_err());
        assert!(validate(&json!([])).is_err());
    }

    #[test]
    fn an_a2a_agent_card_becomes_a_valid_description() {
        let (sk, did, v) = agent(3, "reviewer");
        let card = json!({
            "name": "reviewer", "description": "Reviews inspection reports", "version": "1.0",
            "skills": [{ "id": "review-inspection", "name": "Review inspection", "description": "Checks a report" }],
        });
        let mut ad = from_a2a_card(&card, &did, "https://hotel.example.com:8800/agents/reviewer/ad.json", "https://hotel.example.com:8800/.well-known/agent-card.json", "2026-11-13T10:00:00Z");
        validate(&ad).unwrap();
        assert_eq!(ad["interfaces"][0]["protocol"], "A2A");
        assert!(ad["Infomations"][0]["description"].as_str().unwrap().contains("Review inspection"));
        sign(&mut ad, &sk, &did, "2026-11-13T10:00:01Z", Some(("hotel.example.com:8800", "c1"))).unwrap();
        verify(&ad, &v, Some("hotel.example.com:8800")).unwrap();
    }
}
