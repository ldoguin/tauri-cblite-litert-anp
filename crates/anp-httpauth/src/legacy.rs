//! The older ANP-02 scheme, for clients that do not speak RFC 9421: `Authorization: DIDWba ...` and the Bearer token the
//! server hands back after it.
//!
//! The header carries `did`, `nonce`, `timestamp`, `verification_method` and a signature over the SHA-256 of the RFC 8785 form
//! of `{"nonce", "timestamp", "aud" (or "service" before version 1.1), "did"}`. It names the server's domain, but it covers
//! neither the method, the path nor the body, so it proves who is calling and when, nothing about what is asked. That is why
//! the node only accepts it when asked to (`--allow-legacy-auth`), and why the Bearer token it returns is short-lived.
//!
//! The token is a compact JWT (HS256) signed with a secret only this node holds: `sub` is the caller's DID, with `iat` and `exp`.
//! Clients treat it as opaque. A node that restarts forgets the secret, and clients then sign in again.

use crate::AuthError;
use anp_did::VerifyingKey;
use base64::engine::general_purpose::{URL_SAFE_NO_PAD as B64U};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// How old a timestamp may be, and how far ahead of this clock (seconds), as the SDK's verifier has it.
pub const MAX_AGE: i64 = 300;
pub const MAX_AHEAD: i64 = 60;
/// Lifetime of an issued Bearer token (seconds).
pub const TOKEN_LIFETIME: i64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
    pub version: String,
    pub did: String,
    pub nonce: String,
    pub timestamp: String,
    /// The fragment, e.g. `key-1`.
    pub verification_method: String,
    pub signature: String,
}

impl Parts {
    pub fn key_id(&self) -> String {
        format!("{}#{}", self.did, self.verification_method)
    }
}

fn field(h: &str, name: &str) -> Option<String> {
    // name="value", matched case-insensitively and only at a parameter boundary (so `v` does not match inside `did`)
    let lower = h.to_ascii_lowercase();
    let pat = format!("{name}=\"");
    let mut from = 0;
    while let Some(i) = lower[from..].find(&pat) {
        let at = from + i;
        let boundary = at == 0 || matches!(lower.as_bytes()[at - 1], b' ' | b',');
        if boundary {
            let rest = &h[at + pat.len()..];
            return rest.find('"').map(|e| rest[..e].to_string());
        }
        from = at + pat.len();
    }
    None
}

/// Parse an `Authorization: DIDWba ...` value.
pub fn parse(h: &str) -> Result<Parts, AuthError> {
    let e = |m: &str| AuthError(format!("DIDWba header: {m}"));
    let h = h.trim();
    if !h.get(..6).map_or(false, |s| s.eq_ignore_ascii_case("didwba")) {
        return Err(e("not a DIDWba header"));
    }
    let get = |n: &str| field(h, n).filter(|v| !v.is_empty()).ok_or_else(|| e(&format!("missing {n}")));
    Ok(Parts {
        version: field(h, "v").unwrap_or_else(|| "1.1".into()),
        did: get("did")?,
        nonce: get("nonce")?,
        timestamp: get("timestamp")?,
        verification_method: get("verification_method")?,
        signature: get("signature")?,
    })
}

fn signed_content(p: &Parts, domain: &str) -> Result<[u8; 32], AuthError> {
    let aud_field = if p.version.parse::<f64>().map_or(false, |v| v < 1.1) { "service" } else { "aud" };
    let v = json!({ "nonce": p.nonce, "timestamp": p.timestamp, aud_field: domain, "did": p.did });
    let canon = anp_did::jcs(&v).map_err(|e| AuthError(e.to_string()))?;
    Ok(Sha256::digest(canon.as_bytes()).into())
}

/// Seconds since the epoch of an `YYYY-MM-DDTHH:MM:SSZ` timestamp (the form the SDK writes; offsets are accepted too).
fn parse_time(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp())
}

/// Check the header against the caller's key: the DID names this server's `domain` (a host, no port), the timestamp is
/// fresh, and the signature is made by `key`. The caller still has to see that the nonce is new (`NonceCache`).
pub fn verify(p: &Parts, key: &VerifyingKey, domain: &str, now: i64) -> Result<(), AuthError> {
    let t = parse_time(&p.timestamp).ok_or_else(|| AuthError("DIDWba timestamp is not RFC 3339".into()))?;
    if t - now > MAX_AHEAD {
        return Err(AuthError("DIDWba timestamp is in the future".into()));
    }
    if now - t > MAX_AGE {
        return Err(AuthError("DIDWba timestamp is too old".into()));
    }
    let sig = B64U.decode(p.signature.trim_end_matches('=')).map_err(|_| AuthError("DIDWba signature is not base64url".into()))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| AuthError("DIDWba signature must be 64 bytes (Ed25519)".into()))?;
    let content = signed_content(p, domain)?;
    key.verify_strict(&content, &sig).map_err(|_| AuthError("DIDWba signature does not verify".into()))
}

/// Produce the header value (for tests and clients written here).
pub fn sign(sk: &anp_did::SigningKey, did: &str, fragment: &str, domain: &str, nonce: &str, timestamp: &str) -> String {
    use ed25519_dalek::Signer;
    let p = Parts { version: "1.1".into(), did: did.into(), nonce: nonce.into(), timestamp: timestamp.into(), verification_method: fragment.into(), signature: String::new() };
    let sig = sk.sign(&signed_content(&p, domain).expect("canonical form"));
    format!("DIDWba v=\"1.1\", did=\"{did}\", nonce=\"{nonce}\", timestamp=\"{timestamp}\", verification_method=\"{fragment}\", signature=\"{}\"", B64U.encode(sig.to_bytes()))
}

/// Nonces seen in the window, per DID: a header is accepted once.
pub struct NonceCache {
    seen: Mutex<HashMap<String, i64>>,
}

impl Default for NonceCache {
    fn default() -> Self {
        NonceCache { seen: Mutex::new(HashMap::new()) }
    }
}

impl NonceCache {
    /// True the first time `(did, nonce)` is seen within the window.
    pub fn accept(&self, did: &str, nonce: &str, now: i64) -> bool {
        let mut s = self.seen.lock().unwrap();
        s.retain(|_, t| now - *t <= MAX_AGE + MAX_AHEAD);
        if s.len() >= 100_000 {
            return false; // refuse rather than forget: an attacker cannot make old nonces fall out
        }
        match s.entry(format!("{did}\n{nonce}")) {
            std::collections::hash_map::Entry::Occupied(_) => false, // a retry must not extend how long it is remembered
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(now);
                true
            }
        }
    }
}

// ── Bearer tokens ───────────────────────────────────────────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Issues and checks the node's Bearer tokens.
pub struct Tokens {
    secret: [u8; 32],
}

impl Tokens {
    pub fn new() -> Tokens {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("system randomness");
        Tokens { secret }
    }

    #[cfg(test)]
    fn with_secret(secret: [u8; 32]) -> Tokens {
        Tokens { secret }
    }

    /// A token for `did`, valid for `TOKEN_LIFETIME`.
    pub fn issue(&self, did: &str, now: i64) -> String {
        let head = B64U.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body = B64U.encode(json!({ "sub": did, "iat": now, "exp": now + TOKEN_LIFETIME }).to_string());
        let sig = B64U.encode(hmac_sha256(&self.secret, format!("{head}.{body}").as_bytes()));
        format!("{head}.{body}.{sig}")
    }

    /// The DID a valid, unexpired token was issued to.
    pub fn verify(&self, token: &str, now: i64) -> Result<String, AuthError> {
        let bad = |m: &str| AuthError(format!("Bearer token: {m}"));
        let mut it = token.split('.');
        let (Some(h), Some(b), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else { return Err(bad("not a JWT")) };
        let header: Value = serde_json::from_slice(&B64U.decode(h).map_err(|_| bad("bad header"))?).map_err(|_| bad("bad header"))?;
        if header["alg"] != "HS256" {
            return Err(bad("only HS256 is accepted")); // never the algorithm the token names for itself
        }
        let sig = B64U.decode(s).map_err(|_| bad("bad signature"))?;
        if !same(&sig, &hmac_sha256(&self.secret, format!("{h}.{b}").as_bytes())) {
            return Err(bad("signature does not verify"));
        }
        let c: Value = serde_json::from_slice(&B64U.decode(b).map_err(|_| bad("bad payload"))?).map_err(|_| bad("bad payload"))?;
        let (Some(sub), Some(iat), Some(exp)) = (c["sub"].as_str(), c["iat"].as_i64(), c["exp"].as_i64()) else { return Err(bad("missing sub, iat or exp")) };
        if iat > now + 5 {
            return Err(bad("issued in the future"));
        }
        if exp <= now - 5 {
            return Err(bad("expired"));
        }
        Ok(sub.to_string())
    }
}

impl Default for Tokens {
    fn default() -> Self {
        Tokens::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp_did::SigningKey;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    const DID: &str = "did:wba:client.example.com:agents:c:e1_abc";

    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hex(hmac_sha256(b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // a key longer than the block is hashed first (case 6)
        assert_eq!(hex(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn a_header_signed_for_this_domain_verifies_and_anything_else_does_not() {
        let sk = key();
        let h = sign(&sk, DID, "key-1", "node.example.com", "n1", "2026-11-14T10:00:00Z");
        let p = parse(&h).unwrap();
        assert_eq!((p.did.as_str(), p.verification_method.as_str(), p.version.as_str()), (DID, "key-1", "1.1"));
        let now = parse_time("2026-11-14T10:00:30Z").unwrap();
        verify(&p, &sk.verifying_key(), "node.example.com", now).unwrap();
        assert!(verify(&p, &sk.verifying_key(), "other.example.com", now).is_err(), "another server's domain");
        assert!(verify(&p, &SigningKey::from_bytes(&[8; 32]).verifying_key(), "node.example.com", now).is_err(), "another key");
        assert!(verify(&p, &sk.verifying_key(), "node.example.com", now + 301).is_err(), "too old");
        assert!(verify(&p, &sk.verifying_key(), "node.example.com", now - 100).is_err(), "from the future");
        let mut t = p.clone();
        t.nonce = "n2".into();
        assert!(verify(&t, &sk.verifying_key(), "node.example.com", now).is_err(), "a changed nonce");
    }

    #[test]
    fn parsing_is_strict_about_what_it_needs() {
        assert!(parse("Bearer abc").is_err());
        assert!(parse(r#"DIDWba did="d", nonce="n", timestamp="t", signature="s""#).is_err(), "no verification_method");
        let p = parse(r#"didwba DID="d", Nonce="n", timestamp="t", verification_method="key-1", signature="s""#).unwrap();
        assert_eq!(p.did, "d", "names are case-insensitive");
        assert_eq!(p.version, "1.1", "the default version");
        // `v` must not be found inside another parameter's name
        let p = parse(r#"DIDWba did="d", nonce="n", timestamp="t", verification_method="key-1", signature="s""#).unwrap();
        assert_eq!(p.version, "1.1");
    }

    #[test]
    fn a_nonce_is_good_once() {
        let c = NonceCache::default();
        assert!(c.accept(DID, "n1", 1000));
        assert!(!c.accept(DID, "n1", 1001));
        assert!(c.accept(DID, "n2", 1001));
        assert!(c.accept("did:wba:other.example.com:a:e1_x", "n1", 1001), "per DID");
        assert!(c.accept(DID, "n1", 1000 + MAX_AGE + MAX_AHEAD + 1), "forgotten once it could no longer pass the timestamp check");
    }

    #[test]
    fn tokens_are_bound_to_the_node_the_algorithm_and_the_clock() {
        let t = Tokens::with_secret([1; 32]);
        let tok = t.issue(DID, 1_000_000);
        assert_eq!(t.verify(&tok, 1_000_100).unwrap(), DID);
        assert!(t.verify(&tok, 1_000_000 + TOKEN_LIFETIME + 6).is_err(), "expired");
        assert!(t.verify(&tok, 999_000).is_err(), "not yet valid");
        assert!(Tokens::with_secret([2; 32]).verify(&tok, 1_000_100).is_err(), "another node's secret");
        let parts: Vec<&str> = tok.split('.').collect();
        let forged_body = B64U.encode(json!({ "sub": "did:wba:evil.example.com:a:e1_z", "iat": 1_000_000, "exp": 1_003_600 }).to_string());
        assert!(t.verify(&format!("{}.{forged_body}.{}", parts[0], parts[2]), 1_000_100).is_err(), "a changed payload");
        let none = format!("{}.{}.", B64U.encode(br#"{"alg":"none"}"#), parts[1]);
        assert!(t.verify(&none, 1_000_100).is_err(), "alg none");
        assert!(t.verify("abc", 1_000_100).is_err());
    }

    /// The SDK's own legacy vector (fixed key, timestamp and nonce; the SDK's generator made the header): it must verify here.
    #[test]
    fn the_sdks_legacy_vector_verifies() {
        let v: Value = serde_json::from_str(include_str!("../../../testdata/anp-sdk/authentication_legacy_compatibility_v1.json")).unwrap();
        let p = parse(v["header"].as_str().unwrap()).unwrap();
        assert_eq!((p.version.as_str(), p.verification_method.as_str()), ("1.1", "key-1"));
        let jwk = &v["document"]["verificationMethod"][0]["publicKeyJwk"];
        let raw: [u8; 32] = B64U.decode(jwk["x"].as_str().unwrap()).unwrap().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&raw).unwrap();
        let (now, domain) = (v["now"].as_i64().unwrap(), v["domain"].as_str().unwrap());
        verify(&p, &key, domain, now).unwrap();
        assert!(verify(&p, &key, "other.example", now).is_err());
        assert!(verify(&p, &key, domain, now + MAX_AGE + 3600).is_err(), "and it expires");
    }}
