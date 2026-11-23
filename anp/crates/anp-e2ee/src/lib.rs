//! End-to-end encryption for ANP agents.
//!
//! ANP-09 / P5 (`anp.direct.e2ee.v2`) is an X3DH handshake followed by a Double Ratchet, between per-device
//! sessions, carried by its own message RPC. This crate implements the part of it that suits agents exchanging
//! *documents* through a replicated store: each message is its own X3DH "init" (P5 §5: "each init carries a complete
//! application plaintext"), with the same suite (`ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1`), the same
//! three Diffie-Hellman operations and key-schedule structure, and an associated-data object bound to the sender,
//! the recipient and the message. There is **no ratchet and no session state**: nothing has to be synchronised
//! between devices, and messages can arrive in any order, any number of times, to a recipient that is offline.
//!
//! What that costs, and what this is not:
//! * It is **not wire-compatible** with P5: no `direct.send` RPC, no device manifest, no one-time prekeys, our own
//!   content type and a smaller associated-data object. It follows P5's primitives, not its envelope.
//! * Forward secrecy is only as good as prekey hygiene. Messages to a recipient are protected by their *signed
//!   prekey*, which is rotated; once an old prekey's private half is deleted, the messages sealed to it can no longer
//!   be opened by anyone, including a thief of the device. While it is kept, they can.
//! * The sender is authenticated by its static key-agreement key in the DH, and (in this project) by the signature
//!   on the document that carries the message.
//!
//! The DH shared secrets are `DH1 = DH(KA_sender, SPK_recipient)`, `DH2 = DH(EK, KA_recipient)`,
//! `DH3 = DH(EK, SPK_recipient)`; `SK = HKDF(zero salt, DH1 || DH2 || DH3, "ANP Direct E2EE v1 Initial Secret")`;
//! `RK0`, `CK0` and the session id are expanded from `SK`; the message key and nonce come from `kdf_ck(CK0)`.
//! The key schedule (x3dh_secrets, kdf_ck, kdf_rk) and the canonical form of the associated data are checked in the\n//! tests against the vectors published by the ANP SDK (	estdata/direct_e2ee/p5_shared_vectors.json): they match.\n//! What is *not* checked against another implementation: our own associated-data object and envelope, which are a\n//! subset (no device ids, no security_profile), and the signed bundle format.

pub mod session;
pub mod wire;

use anp_did::{SigningKey, Verified};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const SUITE: &str = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1";
pub const PROFILE: &str = "anp.direct.e2ee.v2";
pub const INIT_CONTENT_TYPE: &str = "application/anp-direct-init+json";
/// What the encrypted payload is: a JSON value (the fields of a replicated document).
pub const APP_CONTENT_TYPE: &str = "application/vnd.anp-cblite.fields+json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eeError(pub String);
impl std::fmt::Display for E2eeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "e2ee: {}", self.0)
    }
}
impl std::error::Error for E2eeError {}
fn err<T>(s: impl Into<String>) -> Result<T, E2eeError> {
    Err(E2eeError(s.into()))
}

// ── keys ────────────────────────────────────────────────────────────────────────────────────────────────

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the operating system has no randomness");
    b
}

/// The node's static key-agreement secret, derived from its signing seed with a domain-separated HKDF, so one seed
/// file is all a node keeps (the keys are still distinct: the DID document lists them under different roles).
pub fn ka_secret_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed).expand(b"anp-cblite key agreement x25519 v1", &mut out).expect("32 bytes");
    out
}

pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], E2eeError> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return err("a Diffie-Hellman input was a low-order point");
    }
    Ok(*shared.as_bytes())
}

/// A signed prekey: a medium-lived X25519 pair that senders encrypt to, rotated regularly.
#[derive(Debug, Clone)]
pub struct Prekey {
    pub id: String,
    pub secret: [u8; 32],
    pub public: [u8; 32],
    pub created_ms: i64,
}

pub fn new_prekey(created_ms: i64) -> Prekey {
    let secret = random32();
    let mut id = [0u8; 9];
    id.copy_from_slice(&random32()[..9]);
    Prekey { id: B64U.encode(id), public: public_of(&secret), secret, created_ms }
}

// ── bundles ─────────────────────────────────────────────────────────────────────────────────────────────

/// A verified prekey bundle: what a sender needs to encrypt to its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub bundle_id: String,
    pub owner_did: String,
    /// The owner's device (its `deviceManifest` entry).
    pub device_id: String,
    /// The owner's static key-agreement key (its id in the DID document, and the key).
    pub ka_id: String,
    pub ka_public: [u8; 32],
    pub spk_id: String,
    pub spk_public: [u8; 32],
    pub expires_at: String,
}

/// Create a prekey bundle for `owner_did`, signed with its DID key (`assertionMethod`, like P5). `created` and
/// `expires_at` are RFC 3339 UTC timestamps of the form `YYYY-MM-DDTHH:MM:SSZ`.
pub fn make_bundle(owner_did: &str, device_id: &str, ka_id: &str, spk: &Prekey, created: &str, expires_at: &str, sk: &SigningKey) -> Result<Value, E2eeError> {
    let parsed = anp_did::WbaDid::parse(owner_did).map_err(|e| E2eeError(e.to_string()))?;
    let fp = parsed.e1().ok_or_else(|| E2eeError("the DID has no e1_ fingerprint".into()))?;
    let mut b = json!({
        "bundle_id": format!("bundle-{}", spk.id),
        "owner_did": owner_did,
        "owner_device_id": device_id,
        "suite": SUITE,
        "static_key_agreement_id": ka_id,
        "signed_prekey": { "key_id": spk.id, "public_key_b64u": B64U.encode(spk.public), "expires_at": expires_at },
    });
    anp_did::add_proof(&mut b, sk, &format!("{owner_did}#{fp}"), "assertionMethod", created, &Default::default()).map_err(|e| E2eeError(e.to_string()))?;
    Ok(b)
}

/// Check a bundle against its owner's verified DID document, as P5 requires: the owner and suite; that the static key is
/// the key-agreement key of the document; that the `deviceManifest` has exactly one entry for `owner_device_id`, whose
/// `e2ee_key_id` is that key and whose `signing_key_id` is an assertion key; that this key made the proof (it need not
/// be the DID's binding key: the SDK signs bundles with a separate device key); and that the bundle has not expired at
/// `now` (same timestamp form as `make_bundle`).
pub fn parse_bundle(v: &Value, did: &Verified, now: &str) -> Result<Bundle, E2eeError> {
    if v["owner_did"].as_str() != Some(did.did_string.as_str()) {
        return err("the bundle is for another DID");
    }
    if v["suite"] != SUITE {
        return err("unsupported cipher suite");
    }
    let device_id = v["owner_device_id"].as_str().filter(|d| !d.is_empty()).ok_or_else(|| E2eeError("the bundle names no owner_device_id".into()))?;
    let (ka_id, ka_public) = did.key_agreement().ok_or_else(|| E2eeError("the DID document publishes no key-agreement key".into()))?;
    if v["static_key_agreement_id"].as_str() != Some(ka_id.as_str()) {
        return err("the bundle's static key is not the DID document's key-agreement key");
    }
    let (signing_key_id, e2ee_key_id) = did.device_keys(device_id).ok_or_else(|| E2eeError(format!("the DID document's deviceManifest has no single entry for device {device_id}")))?;
    if e2ee_key_id != ka_id {
        return err("the device's e2ee_key_id is not the bundle's static key");
    }
    let proof = v.get("proof").ok_or_else(|| E2eeError("the bundle is not signed".into()))?;
    if proof["proofPurpose"] != "assertionMethod" || proof["verificationMethod"].as_str() != Some(signing_key_id.as_str()) {
        return err("the bundle was not signed by the device's signing key");
    }
    let authorised = did.document["assertionMethod"].as_array().map_or(false, |a| a.iter().any(|x| x.as_str() == Some(signing_key_id.as_str())));
    if !authorised {
        return err("the device's signing key is not an assertionMethod of the DID document");
    }
    let vm = did.document["verificationMethod"].as_array().and_then(|a| a.iter().find(|m| m["id"].as_str() == Some(signing_key_id.as_str())));
    let vm = vm.filter(|m| m["type"] == "Multikey").ok_or_else(|| E2eeError("the signing key is not an Ed25519 Multikey of the DID document".into()))?;
    let raw = anp_did::decode_multibase(vm["publicKeyMultibase"].as_str().unwrap_or("")).map_err(|e| E2eeError(e.to_string()))?;
    let key = anp_did::VerifyingKey::from_bytes(&raw).map_err(|_| E2eeError("invalid signing key".into()))?;
    anp_did::verify_proof(v, &key).map_err(|e| E2eeError(e.to_string()))?;
    let spk = &v["signed_prekey"];
    let spk_id = spk["key_id"].as_str().ok_or_else(|| E2eeError("no signed prekey id".into()))?;
    let raw = B64U.decode(spk["public_key_b64u"].as_str().unwrap_or("")).map_err(|_| E2eeError("bad signed prekey encoding".into()))?;
    let spk_public: [u8; 32] = raw.try_into().map_err(|_| E2eeError("signed prekey must be 32 bytes".into()))?;
    let expires_at = spk["expires_at"].as_str().ok_or_else(|| E2eeError("no expiry".into()))?;
    if expires_at <= now {
        return err(format!("the bundle expired at {expires_at}"));
    }
    Ok(Bundle {
        bundle_id: v["bundle_id"].as_str().unwrap_or("").to_string(),
        owner_did: did.did_string.clone(),
        device_id: device_id.to_string(),
        ka_id,
        ka_public,
        spk_id: spk_id.to_string(),
        spk_public,
        expires_at: expires_at.to_string(),
    })
}
// ── sealing ─────────────────────────────────────────────────────────────────────────────────────────────

/// Everything the associated data binds a ciphertext to. A ciphertext cannot be moved to another message, sender,
/// device or recipient: opening it with different values fails.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    /// The message this travels in. A document id plus the field that is encrypted, e.g. `tasks/<id>#task`.
    pub message_id: &'a str,
    pub sender_did: &'a str,
    pub sender_device_id: &'a str,
    pub sender_ka_id: &'a str,
    pub recipient_did: &'a str,
    pub recipient_device_id: &'a str,
}
struct Keys {
    session_id: String,
    mk: [u8; 32],
    nonce: [u8; 12],
}

const INFO_SK: &[u8] = b"ANP Direct E2EE v1 Initial Secret";
const INFO_RK: &[u8] = b"ANP Direct E2EE v1 Root Key";
const INFO_CK: &[u8] = b"ANP Direct E2EE v1 Chain Key";
const INFO_SID: &[u8] = b"ANP Direct E2EE v1 Session ID";
const INFO_KDF_CK: &[u8] = b"ANP Direct E2EE v1 KDF_CK";

const INFO_KDF_RK: &[u8] = b"ANP Direct E2EE v1 KDF_RK";

/// The initial secret, root key, chain key and session id of an X3DH handshake (P5 §5): the concatenated
/// Diffie-Hellman outputs (`DH1 || DH2 || DH3`, plus `DH4` when a one-time prekey is used) go through
/// HKDF-Extract with a zero salt, then HKDF-Expand with the P5 labels.
pub fn x3dh_secrets(dhs: &[[u8; 32]]) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 16]) {
    let ikm: Vec<u8> = dhs.iter().flatten().copied().collect();
    let zero = [0u8; 32];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&zero), &ikm);
    let mut sk = [0u8; 32];
    Hkdf::<Sha256>::from_prk(&prk).expect("prk").expand(INFO_SK, &mut sk).expect("32");
    let from_sk = Hkdf::<Sha256>::from_prk(&sk).expect("prk");
    let (mut rk0, mut ck0, mut sid) = ([0u8; 32], [0u8; 32], [0u8; 16]);
    from_sk.expand(INFO_RK, &mut rk0).expect("32");
    from_sk.expand(INFO_CK, &mut ck0).expect("32");
    from_sk.expand(INFO_SID, &mut sid).expect("16");
    (sk, rk0, ck0, sid)
}

/// `kdf_ck` (P5 §6): the next chain key, the message key and the 12-byte nonce.
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 12]) {
    let zero = [0u8; 32];
    let mut out = [0u8; 76];
    Hkdf::<Sha256>::new(Some(&zero), ck).expand(INFO_KDF_CK, &mut out).expect("76");
    let (mut next, mut mk, mut nonce) = ([0u8; 32], [0u8; 32], [0u8; 12]);
    next.copy_from_slice(&out[..32]);
    mk.copy_from_slice(&out[32..64]);
    nonce.copy_from_slice(&out[64..76]);
    (next, mk, nonce)
}

/// `kdf_rk` (P5 §6): the next root key and the chain key. Not used by this subset (no ratchet); here so the
/// published vectors can check it, and for a future ratchet.
pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    Hkdf::<Sha256>::new(Some(rk), dh_out).expand(INFO_KDF_RK, &mut out).expect("64");
    let (mut next, mut ck) = ([0u8; 32], [0u8; 32]);
    next.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (next, ck)
}

fn schedule(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32]) -> Keys {
    let (_sk, _rk0, ck0, sid) = x3dh_secrets(&[*dh1, *dh2, *dh3]);
    // The first message uses message index 0: CK1, MK0, NONCE0 = kdf_ck(CK0). (The root key would start the
    // ratchet, which this subset does not run.)
    let (_ck1, mk, nonce) = kdf_ck(&ck0);
    Keys { session_id: B64U.encode(sid), mk, nonce }
}

pub const SECURITY_PROFILE: &str = "direct-e2ee";

/// The associated data of an init message: P5 v2's `AD_init`, serialised with RFC 8785. Checked in the tests against
/// the ANP SDK's `expected_ad_init`. An absent one-time prekey is omitted, never `null`.
pub fn init_aad(ctx: &Ctx, bundle_id: &str, spk_id: &str, opk_id: Option<&str>, session_id: &str) -> Result<Vec<u8>, E2eeError> {
    let mut ad = json!({
        "content_type": INIT_CONTENT_TYPE,
        "message_id": ctx.message_id,
        "operation_id": ctx.message_id,
        "profile": PROFILE,
        "security_profile": SECURITY_PROFILE,
        "sender_did": ctx.sender_did,
        "sender_device_id": ctx.sender_device_id,
        "recipient_did": ctx.recipient_did,
        "recipient_device_id": ctx.recipient_device_id,
        "suite": SUITE,
        "recipient_bundle_id": bundle_id,
        "sender_static_key_agreement_id": ctx.sender_ka_id,
        "recipient_signed_prekey_id": spk_id,
        "session_id": session_id,
    });
    if let Some(o) = opk_id {
        ad["recipient_one_time_prekey_id"] = json!(o);
    }
    anp_did::jcs(&ad).map(String::into_bytes).map_err(|e| E2eeError(e.to_string()))
}

fn aad(ctx: &Ctx, bundle_id: &str, spk_id: &str, session_id: &str) -> Result<Vec<u8>, E2eeError> {
    init_aad(ctx, bundle_id, spk_id, None, session_id)
}
/// Encrypt `payload` to the owner of `rcpt`. `sender_ka_secret` is the sender's static key-agreement secret.
/// Returns the init object (`session_id`, `suite`, ids, `sender_ephemeral_pub_b64u`, `ciphertext_b64u`).
pub fn seal(payload: &Value, ctx: &Ctx, sender_ka_secret: &[u8; 32], rcpt: &Bundle) -> Result<Value, E2eeError> {
    if ctx.recipient_did != rcpt.owner_did {
        return err("the bundle belongs to someone else");
    }
    let esk = random32();
    let epk = public_of(&esk);
    let k = schedule(&dh(sender_ka_secret, &rcpt.spk_public)?, &dh(&esk, &rcpt.ka_public)?, &dh(&esk, &rcpt.spk_public)?);
    // the application plaintext, serialised with RFC 8785 as P5 requires
    let plain = anp_did::jcs(&json!({ "application_content_type": APP_CONTENT_TYPE, "logical_message_id": ctx.message_id, "payload": payload }))
        .map_err(|e| E2eeError(e.to_string()))?
        .into_bytes();
    let ad = aad(ctx, &rcpt.bundle_id, &rcpt.spk_id, &k.session_id)?;
    let ct = ChaCha20Poly1305::new(Key::from_slice(&k.mk))
        .encrypt(Nonce::from_slice(&k.nonce), Payload { msg: &plain, aad: &ad })
        .map_err(|_| E2eeError("encryption failed".into()))?;
    Ok(json!({
        "session_id": k.session_id,
        "suite": SUITE,
        "sender_static_key_agreement_id": ctx.sender_ka_id,
        "recipient_bundle_id": rcpt.bundle_id,
        "recipient_signed_prekey_id": rcpt.spk_id,
        "sender_ephemeral_pub_b64u": B64U.encode(epk),
        "ciphertext_b64u": B64U.encode(ct),
    }))
}

/// The id of the recipient's signed prekey an init was sealed to: the caller looks the private half up.
pub fn init_spk_id(init: &Value) -> Option<&str> {
    init["recipient_signed_prekey_id"].as_str()
}

/// Decrypt an init to the whole application plaintext object (`application_content_type`, `payload`, …), whatever its
/// content type: what another implementation sends. [`open`] is the strict form for this project's own messages.
pub fn open_raw(init: &Value, ctx: &Ctx, my_ka_secret: &[u8; 32], spk_secret: &[u8; 32], sender_ka_public: &[u8; 32]) -> Result<Value, E2eeError> {
    open_inner(init, ctx, my_ka_secret, spk_secret, sender_ka_public)
}

/// Decrypt an init. `my_ka_secret` and `spk_secret` are the recipient's static and signed-prekey secrets (the latter
/// found with [`init_spk_id`]); `sender_ka_public` comes from the sender's verified DID document.
pub fn open(init: &Value, ctx: &Ctx, my_ka_secret: &[u8; 32], spk_secret: &[u8; 32], sender_ka_public: &[u8; 32]) -> Result<Value, E2eeError> {
    let v = open_inner(init, ctx, my_ka_secret, spk_secret, sender_ka_public)?;
    if v["application_content_type"] != APP_CONTENT_TYPE || v["logical_message_id"].as_str() != Some(ctx.message_id) {
        return err("unexpected plaintext envelope");
    }
    Ok(v["payload"].clone())
}

fn open_inner(init: &Value, ctx: &Ctx, my_ka_secret: &[u8; 32], spk_secret: &[u8; 32], sender_ka_public: &[u8; 32]) -> Result<Value, E2eeError> {
    if init["suite"] != SUITE {
        return err("unsupported cipher suite");
    }
    if init["sender_static_key_agreement_id"].as_str() != Some(ctx.sender_ka_id) {
        return err("the sender's key-agreement id does not match");
    }
    let field = |k: &str| init[k].as_str().ok_or_else(|| E2eeError(format!("init has no {k}")));
    let epk: [u8; 32] = B64U
        .decode(field("sender_ephemeral_pub_b64u")?)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| E2eeError("bad ephemeral key".into()))?;
    let ct = B64U.decode(field("ciphertext_b64u")?).map_err(|_| E2eeError("bad ciphertext encoding".into()))?;
    let k = schedule(&dh(spk_secret, sender_ka_public)?, &dh(my_ka_secret, &epk)?, &dh(spk_secret, &epk)?);
    if field("session_id")? != k.session_id {
        return err("the session id does not match the shared secret");
    }
    let ad = aad(ctx, field("recipient_bundle_id")?, field("recipient_signed_prekey_id")?, &k.session_id)?;
    let plain = ChaCha20Poly1305::new(Key::from_slice(&k.mk))
        .decrypt(Nonce::from_slice(&k.nonce), Payload { msg: &ct, aad: &ad })
        .map_err(|_| E2eeError("decryption failed (wrong key, or the message was altered or moved)".into()))?;
    serde_json::from_slice(&plain).map_err(|_| E2eeError("the plaintext is not JSON".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Party {
        sk: SigningKey,
        did: String,
        verified: Verified,
        ka: [u8; 32],
        ka_id: String,
        spk: Prekey,
        bundle: Bundle,
    }

    const NOW: &str = "2026-11-13T12:00:00Z";
    const LATER: &str = "2026-12-13T12:00:00Z";

    fn party(seed: u8, name: &str) -> Party {
        party_at(seed, name, "a.example.com", None, vec![])
    }

    /// A party whose DID lives at `host[:port]`, with extra services (a relative `id` such as `#message` becomes a DID URL).
    fn party_at(seed: u8, name: &str, host: &str, port: Option<u16>, services: Vec<Value>) -> Party {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let did = anp_did::did_for_key(host, port, &["agents", name], &sk.verifying_key().to_bytes());
        let services: Vec<Value> = services
            .into_iter()
            .map(|mut s| {
                if let Some(f) = s["id"].as_str().filter(|i| i.starts_with('#')).map(str::to_string) {
                    s["id"] = json!(format!("{did}{f}"));
                }
                s
            })
            .collect();
        let ka = ka_secret_from_seed(&[seed; 32]);
        let device = format!("dev-{name}");
        let doc = anp_did::build_document_full(&did, &sk, &services, "2026-11-13T10:00:00Z", Some(&public_of(&ka)), Some(&device)).unwrap();
        let verified = anp_did::verify_document(&doc, Some(&did)).unwrap();
        let ka_id = verified.key_agreement().unwrap().0;
        let spk = new_prekey(0);
        let b = make_bundle(&did, &device, &ka_id, &spk, "2026-11-13T10:00:00Z", LATER, &sk).unwrap();
        let bundle = parse_bundle(&b, &verified, NOW).unwrap();
        Party { sk, did, verified, ka, ka_id, spk, bundle }
    }

    fn ctx<'a>(from: &'a Party, to: &'a Party) -> Ctx<'a> {
        Ctx {
            message_id: "tasks/t1#task",
            sender_did: &from.did,
            sender_device_id: &from.bundle.device_id,
            sender_ka_id: &from.ka_id,
            recipient_did: &to.did,
            recipient_device_id: &to.bundle.device_id,
        }
    }

    fn seal_to(from: &Party, to: &Party, payload: &Value) -> Value {
        seal(payload, &ctx(from, to), &from.ka, &to.bundle).unwrap()
    }
    fn open_as(me: &Party, from: &Party, init: &Value) -> Result<Value, E2eeError> {
        open(init, &ctx(from, me), &me.ka, &me.spk.secret, &public_of(&from.ka))
    }

    #[test]
    fn the_recipient_reads_what_the_sender_sealed() {
        let (a, b) = (party(1, "alice"), party(2, "bob"));
        let payload = json!({ "status": { "state": "TASK_STATE_COMPLETED" }, "artifacts": [{ "parts": [{ "text": "the secret" }] }] });
        let init = seal_to(&a, &b, &payload);
        assert_eq!(open_as(&b, &a, &init).unwrap(), payload);
        assert_eq!(init["suite"], SUITE);
        assert!(!init.to_string().contains("the secret"), "the ciphertext does not contain the plaintext");
    }

    #[test]
    fn nobody_else_can_read_it() {
        let (a, b, c) = (party(1, "alice"), party(2, "bob"), party(3, "carol"));
        let init = seal_to(&a, &b, &json!({ "x": 1 }));
        // a relay that holds the ciphertext and its own keys
        assert!(open_as(&c, &a, &init).is_err());
        assert!(open(&init, &ctx(&a, &b), &c.ka, &c.spk.secret, &public_of(&a.ka)).is_err(), "even claiming to be the recipient");
        // the right static key but not the signed prekey, and the other way round
        assert!(open(&init, &ctx(&a, &b), &b.ka, &c.spk.secret, &public_of(&a.ka)).is_err());
        assert!(open(&init, &ctx(&a, &b), &c.ka, &b.spk.secret, &public_of(&a.ka)).is_err());
    }

    #[test]
    fn the_sender_is_part_of_the_secret() {
        let (a, b, m) = (party(1, "alice"), party(2, "bob"), party(9, "mallory"));
        let init = seal_to(&a, &b, &json!({ "x": 1 }));
        // opened as if from mallory: wrong static key in DH1, and the associated data differs
        assert!(open(&init, &ctx(&m, &b), &b.ka, &b.spk.secret, &public_of(&m.ka)).is_err());
        // mallory seals to bob claiming to be alice: she lacks alice's static key, so bob cannot open it as alice's
        let forged = seal(&json!({ "x": 2 }), &ctx(&a, &b), &m.ka, &b.bundle).unwrap();
        assert!(open_as(&b, &a, &forged).is_err());
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_or_edited() {
        let (a, b) = (party(1, "alice"), party(2, "bob"));
        let init = seal_to(&a, &b, &json!({ "x": 1 }));
        let mut c = ctx(&a, &b);
        c.message_id = "tasks/other#task";
        assert!(open(&init, &c, &b.ka, &b.spk.secret, &public_of(&a.ka)).is_err(), "another document");
        let mut c = ctx(&a, &b);
        c.message_id = "tasks/t1#message";
        assert!(open(&init, &c, &b.ka, &b.spk.secret, &public_of(&a.ka)).is_err(), "another field of the same document");
        let mut c = ctx(&a, &b);
        c.recipient_device_id = "dev-other";
        assert!(open(&init, &c, &b.ka, &b.spk.secret, &public_of(&a.ka)).is_err(), "another device");
        let mut c = ctx(&a, &b);
        c.recipient_did = "did:wba:a.example.com:agents:eve:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(open(&init, &c, &b.ka, &b.spk.secret, &public_of(&a.ka)).is_err(), "another recipient");
        let mut t = init.clone();
        let ct = t["ciphertext_b64u"].as_str().unwrap().to_string();
        t["ciphertext_b64u"] = json!(format!("{}{}", &ct[..ct.len() - 2], if ct.ends_with("AA") { "BB" } else { "AA" }));
        assert!(open_as(&b, &a, &t).is_err(), "a flipped byte");
        let mut t = init.clone();
        t["recipient_signed_prekey_id"] = json!("other");
        assert!(open_as(&b, &a, &t).is_err(), "a different prekey id is part of the associated data");
        let mut t = init.clone();
        t["sender_ephemeral_pub_b64u"] = json!(B64U.encode([5u8; 32]));
        assert!(open_as(&b, &a, &t).is_err(), "another ephemeral key");
    }

    #[test]
    fn every_message_gets_fresh_keys() {
        let (a, b) = (party(1, "alice"), party(2, "bob"));
        let p = json!({ "x": 1 });
        let (i1, i2) = (seal_to(&a, &b, &p), seal_to(&a, &b, &p));
        assert_ne!(i1["ciphertext_b64u"], i2["ciphertext_b64u"]);
        assert_ne!(i1["session_id"], i2["session_id"]);
        assert_ne!(i1["sender_ephemeral_pub_b64u"], i2["sender_ephemeral_pub_b64u"]);
        assert_eq!(open_as(&b, &a, &i1).unwrap(), p);
        assert_eq!(open_as(&b, &a, &i2).unwrap(), p, "any order, any number of times: there is no state");
        assert_eq!(open_as(&b, &a, &i1).unwrap(), p);
    }

    #[test]
    fn a_node_can_seal_to_itself() {
        let a = party(1, "alice");
        let init = seal_to(&a, &a, &json!({ "mine": true }));
        assert_eq!(open_as(&a, &a, &init).unwrap(), json!({ "mine": true }));
    }

    #[test]
    fn bundles_are_checked_against_the_owners_did_document() {
        let (a, b) = (party(1, "alice"), party(2, "bob"));
        let good = make_bundle(&a.did, &a.bundle.device_id, &a.ka_id, &a.spk, "2026-11-13T10:00:00Z", LATER, &a.sk).unwrap();
        assert!(parse_bundle(&good, &a.verified, NOW).is_ok());
        assert!(parse_bundle(&good, &b.verified, NOW).is_err(), "someone else's DID document");
        assert!(parse_bundle(&good, &a.verified, "2027-01-01T00:00:00Z").unwrap_err().0.contains("expired"));
        let mut t = good.clone();
        t["signed_prekey"]["public_key_b64u"] = json!(B64U.encode([9u8; 32]));
        assert!(parse_bundle(&t, &a.verified, NOW).unwrap_err().0.contains("signature"), "a swapped prekey");
        let mut t = good.clone();
        t["static_key_agreement_id"] = json!("did:wba:x#other");
        assert!(parse_bundle(&t, &a.verified, NOW).is_err());
        let mut t = good.clone();
        t.as_object_mut().unwrap().remove("proof");
        assert!(parse_bundle(&t, &a.verified, NOW).is_err());
        // signed by a key that is not the DID's
        let forged = make_bundle(&a.did, &a.bundle.device_id, &a.ka_id, &a.spk, "2026-11-13T10:00:00Z", LATER, &b.sk);
        assert!(forged.is_err() || parse_bundle(&forged.unwrap(), &a.verified, NOW).is_err());
    }

    #[test]
    fn sealing_to_the_wrong_bundle_is_refused_and_key_derivation_is_stable() {
        let (a, b, c) = (party(1, "alice"), party(2, "bob"), party(3, "carol"));
        assert!(seal(&json!({}), &ctx(&a, &b), &a.ka, &c.bundle).is_err());
        assert_eq!(ka_secret_from_seed(&[1; 32]), ka_secret_from_seed(&[1; 32]));
        assert_ne!(ka_secret_from_seed(&[1; 32]), ka_secret_from_seed(&[2; 32]));
        assert_ne!(ka_secret_from_seed(&[1; 32]), [1u8; 32], "not the seed itself");
        // an all-zero public key (a low-order point) is refused rather than producing a guessable secret
        let mut weak = b.bundle.clone();
        weak.spk_public = [0u8; 32];
        assert!(seal(&json!({}), &ctx(&a, &b), &a.ka, &weak).is_err());
    }

    // ── the ANP SDK's published test vectors ────────────────────────────────────────────────────────────
    // From agent-network-protocol/anp, testdata/direct_e2ee/p5_shared_vectors.json (version
    // "anp-direct-e2ee-p5-shared-vectors-v1"). The private keys there are repeated bytes, so the inputs are rebuilt here.

    fn b(s: &str) -> Vec<u8> {
        B64U.decode(s).unwrap()
    }
    fn arr(s: &str) -> [u8; 32] {
        b(s).try_into().unwrap()
    }

    #[test]
    fn the_x3dh_vectors_of_the_anp_sdk_match() {
        let (sender_static, eph, rcpt_static, spk, opk) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        assert_eq!(public_of(&rcpt_static), arr("Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"), "recipient static public key");
        assert_eq!(public_of(&spk), arr("rAGyIJ6GNU-4UyN7XeD0-rE8f8v0M6YcAZNpYX_s8Qs"), "signed prekey public key");
        assert_eq!(public_of(&opk), arr("UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0"), "one-time prekey public key");
        let dh1 = dh(&sender_static, &public_of(&spk)).unwrap();
        let dh2 = dh(&eph, &public_of(&rcpt_static)).unwrap();
        let dh3 = dh(&eph, &public_of(&spk)).unwrap();
        let dh4 = dh(&eph, &public_of(&opk)).unwrap();

        let (sk, rk, ck, sid) = x3dh_secrets(&[dh1, dh2, dh3]);
        assert_eq!(sk, arr("iYp1ZUZLNn9RD4Lr1bmWiHI4fF1ApLiTUJluPJJ2QpU"), "initial secret, no OPK");
        assert_eq!(rk, arr("1Ka99JVHEkEvDuQwJUZ7lvzjAT-P1WkH57w91dZ0vPc"), "root key, no OPK");
        assert_eq!(ck, arr("QpMaGGUNo7Fox5A4k2kvOYn1MLUql5sO9VTq-laXxmg"), "chain key, no OPK");
        assert_eq!(B64U.encode(sid), "zOhq6y_9zNOQTVwRqKEkoQ", "session id, no OPK");

        let (sk, rk, ck, sid) = x3dh_secrets(&[dh1, dh2, dh3, dh4]);
        assert_eq!(sk, arr("_IngCZtPEtnmzQwWzHZWjZ93RdytsivSHcGsXe1jZXg"), "initial secret, with OPK");
        assert_eq!(rk, arr("rfzOymlTnBWmK9IK6HNyaMXqARn_DPLxNfFcTTZXTfc"), "root key, with OPK");
        assert_eq!(ck, arr("8Zlwlzy_Irtpk8d3XADPaJuSaw47QS-r2QTyjhtjp0U"), "chain key, with OPK");
        assert_eq!(B64U.encode(sid), "or8NgG6Q0INmcN79HzN2Nw", "session id, with OPK");
    }

    #[test]
    fn the_chain_and_root_key_derivations_of_the_anp_sdk_match() {
        let (next, mk, nonce) = kdf_ck(&[9u8; 32]);
        assert_eq!(next, arr("yCAdzu9yOGZlIqjCyikVZojP53iZiOtDUtHKhIDPOW4"), "next chain key");
        assert_eq!(mk, arr("UTeRzg1yZgiAtpjEq8W2mrnt8dG1z0Q71jXu_FwpTBM"), "message key");
        assert_eq!(nonce.to_vec(), b("cpWTf3QHO3s9_VAm"), "nonce");
        let (rk, ck) = kdf_rk(&[10u8; 32], &[11u8; 32]);
        assert_eq!(rk, arr("yukSoIrVndezt584swiEbXaBN0EgWcMT98CLG-C-7ig"), "next root key");
        assert_eq!(ck, arr("f-kJw3tAYuub0A3XF565IXgvq3rT98OIQHFyMRIdjOQ"), "chain key");
    }

    #[test]
    fn the_jcs_of_the_sdks_init_and_cipher_aad_matches() {
        // p5_aad_init_no_opk, p5_aad_init_with_opk, p5_aad_msg: the AAD is the JCS of these members
        let init = json!({
            "content_type": "application/anp-direct-init+json", "message_id": "msg-001", "profile": "anp.direct.e2ee.v1",
            "security_profile": "direct-e2ee", "sender_did": "did:wba:a.example:agents:alice:e1", "recipient_did": "did:wba:b.example:agents:bob:e1",
            "session_id": "SESSION123", "suite": SUITE, "sender_static_key_agreement_id": "did:wba:a.example:agents:alice:e1#key-3",
            "recipient_bundle_id": "bundle-001", "recipient_signed_prekey_id": "spk-001",
        });
        assert_eq!(
            anp_did::jcs(&init).unwrap(),
            "{\"content_type\":\"application/anp-direct-init+json\",\"message_id\":\"msg-001\",\"profile\":\"anp.direct.e2ee.v1\",\"recipient_bundle_id\":\"bundle-001\",\"recipient_did\":\"did:wba:b.example:agents:bob:e1\",\"recipient_signed_prekey_id\":\"spk-001\",\"security_profile\":\"direct-e2ee\",\"sender_did\":\"did:wba:a.example:agents:alice:e1\",\"sender_static_key_agreement_id\":\"did:wba:a.example:agents:alice:e1#key-3\",\"session_id\":\"SESSION123\",\"suite\":\"ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1\"}"
        );
        let mut with_opk = init.clone();
        with_opk["recipient_one_time_prekey_id"] = json!("opk-001");
        assert_eq!(
            anp_did::jcs(&with_opk).unwrap(),
            "{\"content_type\":\"application/anp-direct-init+json\",\"message_id\":\"msg-001\",\"profile\":\"anp.direct.e2ee.v1\",\"recipient_bundle_id\":\"bundle-001\",\"recipient_did\":\"did:wba:b.example:agents:bob:e1\",\"recipient_one_time_prekey_id\":\"opk-001\",\"recipient_signed_prekey_id\":\"spk-001\",\"security_profile\":\"direct-e2ee\",\"sender_did\":\"did:wba:a.example:agents:alice:e1\",\"sender_static_key_agreement_id\":\"did:wba:a.example:agents:alice:e1#key-3\",\"session_id\":\"SESSION123\",\"suite\":\"ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1\"}"
        );
        let msg = json!({
            "content_type": "application/anp-direct-cipher+json", "message_id": "msg-001", "profile": "anp.direct.e2ee.v1",
            "security_profile": "direct-e2ee", "sender_did": "did:wba:a.example:agents:alice:e1", "recipient_did": "did:wba:b.example:agents:bob:e1",
            "session_id": "SESSION123", "ratchet_header": { "dh_pub_b64u": "RATCHETPUB", "pn": "0", "n": "1" },
        });
        assert_eq!(
            anp_did::jcs(&msg).unwrap(),
            "{\"content_type\":\"application/anp-direct-cipher+json\",\"message_id\":\"msg-001\",\"profile\":\"anp.direct.e2ee.v1\",\"ratchet_header\":{\"dh_pub_b64u\":\"RATCHETPUB\",\"n\":\"1\",\"pn\":\"0\"},\"recipient_did\":\"did:wba:b.example:agents:bob:e1\",\"security_profile\":\"direct-e2ee\",\"sender_did\":\"did:wba:a.example:agents:alice:e1\",\"session_id\":\"SESSION123\"}"
        );
    }

    // ── the SDK's v2 wire vectors ───────────────────────────────────────────────────────────────────────

    fn wire_vectors() -> Value {
        serde_json::from_str(include_str!("../../../testdata/anp-sdk/direct_e2ee_p5_v2_wire_vectors.json")).unwrap()
    }

    #[test]
    fn our_init_aad_is_byte_for_byte_the_sdks() {
        let v = wire_vectors();
        let ctx = Ctx {
            message_id: "msg-a-b-001",
            sender_did: "did:wba:a.example:agents:alice:e1_fixture",
            sender_device_id: "dev-a-7N3KQ2",
            sender_ka_id: "did:wba:a.example:agents:alice:e1_fixture#dev-a-e2ee",
            recipient_did: "did:wba:b.example:agents:bob:e1_fixture",
            recipient_device_id: "dev-b-9R5TLM",
        };
        let ad = init_aad(&ctx, "bundle-b-001", "spk-b-001", Some("opk-b-001"), "or8NgG6Q0INmcN79HzN2Nw").unwrap();
        assert_eq!(String::from_utf8(ad).unwrap(), v["expected_ad_init"].as_str().unwrap());
        // the same message without a one-time prekey omits the member rather than writing null
        let no_opk = String::from_utf8(init_aad(&ctx, "bundle-b-001", "spk-b-001", None, "or8NgG6Q0INmcN79HzN2Nw").unwrap()).unwrap();
        assert!(!no_opk.contains("recipient_one_time_prekey_id") && !no_opk.contains("null"));
        // and the init body has the members the SDK's init request has
        let body = &v["direct_init_request"]["params"]["body"];
        for k in ["session_id", "suite", "sender_static_key_agreement_id", "recipient_bundle_id", "recipient_signed_prekey_id", "sender_ephemeral_pub_b64u", "ciphertext_b64u"] {
            assert!(body.get(k).is_some(), "the SDK's init body has {k}");
        }
    }

    #[test]
    fn the_sdks_signed_bundle_is_accepted_against_its_device_manifest() {
        // The SDK's golden: a DID document with a deviceManifest, and a bundle signed by the device's own signing key
        // (not the DID's binding key), checked here with the SDK's own clock.
        let g = &wire_vectors()["signed_bundle_golden"];
        let doc = &g["did_document"];
        let did = anp_did::verify_document(doc, doc["id"].as_str()).expect("the SDK's DID document verifies");
        let now = g["now"].as_str().unwrap();
        let b = parse_bundle(&g["prekey_bundle"], &did, now).expect("the SDK's bundle is accepted");
        assert_eq!(b.device_id, "dev-a-vector");
        assert_eq!(b.spk_id, "spk-vector-001");
        assert_eq!(b.spk_public, <[u8; 32]>::try_from(B64U.decode("UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0").unwrap()).unwrap());
        assert!(b.ka_id.ends_with("#key-3"));
        // each MUST of the spec is enforced against this same golden
        assert!(parse_bundle(&g["prekey_bundle"], &did, "2036-01-01T00:00:00Z").unwrap_err().0.contains("expired"));
        let mut t = g["prekey_bundle"].clone();
        t["owner_device_id"] = json!("dev-unknown");
        assert!(parse_bundle(&t, &did, now).is_err(), "a device the manifest does not list");
        let mut t = g["prekey_bundle"].clone();
        t["signed_prekey"]["public_key_b64u"] = json!(B64U.encode([7u8; 32]));
        assert!(parse_bundle(&t, &did, now).unwrap_err().0.contains("signature"), "a swapped prekey");
        let mut t = g["prekey_bundle"].clone();
        t["proof"]["verificationMethod"] = json!(format!("{}#key-1", doc["id"].as_str().unwrap()));
        assert!(parse_bundle(&t, &did, now).is_err(), "signed by a key the manifest does not name for this device");
    }

    /// Writes what this crate produces to the file named by `ANP_FIXTURE_OUT`, for checking with another implementation
    /// (see `scripts/interop`). A no-op when the variable is not set.
    #[test]
    fn dump_interop_fixture() {
        let Ok(path) = std::env::var("ANP_FIXTURE_OUT") else { return };
        // ANP_FIXTURE_ALICE_DOMAIN=host[:port] puts the sending party's DID on a real domain (and ANP_FIXTURE_ALICE_ENDPOINT is its
        // ANPMessageService), so that a node can resolve it over HTTPS instead of being handed its document.
        let alice = match std::env::var("ANP_FIXTURE_ALICE_DOMAIN") {
            Ok(d) => {
                let (host, port) = match d.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
                    None => (d.clone(), None),
                };
                let svc = std::env::var("ANP_FIXTURE_ALICE_ENDPOINT").map(|e| vec![json!({ "id": "#message", "type": "ANPMessageService", "serviceEndpoint": e })]).unwrap_or_default();
                party_at(1, "alice", &host, port, svc)
            }
            Err(_) => party(1, "alice"),
        };
        let (a, b) = (alice, party(2, "bob"));
        let c = ctx(&a, &b);
        let payload = json!({ "status": { "state": "TASK_STATE_COMPLETED" }, "artifacts": [{ "parts": [{ "text": "hello" }] }], "n": [1.5, 1e30] });
        let init = seal(&payload, &c, &a.ka, &b.bundle).unwrap();
        let ad = init_aad(&c, &b.bundle.bundle_id, &b.bundle.spk_id, None, init["session_id"].as_str().unwrap()).unwrap();
        let plain = anp_did::jcs(&json!({ "application_content_type": APP_CONTENT_TYPE, "logical_message_id": c.message_id, "payload": payload })).unwrap();
        let bundle_json = make_bundle(&b.did, &b.bundle.device_id, &b.ka_id, &b.spk, "2026-11-13T10:00:00Z", LATER, &b.sk).unwrap();
        let out = json!({
            "now": NOW,
            "metadata": {
                "profile": PROFILE, "security_profile": SECURITY_PROFILE, "sender_did": a.did, "sender_device_id": a.bundle.device_id,
                "target": { "kind": "agent", "did": b.did }, "recipient_device_id": b.bundle.device_id,
                "operation_id": c.message_id, "message_id": c.message_id, "content_type": INIT_CONTENT_TYPE,
            },
            "keys": {
                "alice_ka_secret": B64U.encode(a.ka), "alice_ka_public": B64U.encode(public_of(&a.ka)),
                "bob_ka_secret": B64U.encode(b.ka), "bob_ka_public": B64U.encode(public_of(&b.ka)), "bob_spk_secret": B64U.encode(b.spk.secret),
                "alice_ka_id": a.ka_id, "bob_ka_id": b.ka_id,
            },
            "recipient": { "did_document": b.verified.document, "bundle": bundle_json, "device_id": b.bundle.device_id },
            "sender": { "did": a.did, "device_id": a.bundle.device_id, "ka_id": a.ka_id, "did_document": a.verified.document },
            "message_id": c.message_id,
            "init_body": init,
            "expected_ad_init": String::from_utf8(ad).unwrap(),
            "application_plaintext": { "application_content_type": APP_CONTENT_TYPE, "logical_message_id": c.message_id, "payload": payload },
            "expected_application_plaintext_jcs": plain,
        });
        std::fs::write(path, out.to_string()).unwrap();
    }

    /// Opens a message the ANP SDK sealed to the recipient of `ANP_FIXTURE` (see `scripts/interop`). The SDK's output is
    /// the file named by `ANP_SDK_SEALED`. A no-op when either is unset.
    #[test]
    fn opens_a_message_sealed_by_the_sdk() {
        let (Ok(fx_path), Ok(sealed_path)) = (std::env::var("ANP_FIXTURE"), std::env::var("ANP_SDK_SEALED")) else { return };
        let fx: Value = serde_json::from_str(&std::fs::read_to_string(fx_path).unwrap()).unwrap();
        let sealed: Value = serde_json::from_str(&std::fs::read_to_string(sealed_path).unwrap()).unwrap();
        let key = |k: &str| -> [u8; 32] { B64U.decode(fx["keys"][k].as_str().unwrap()).unwrap().try_into().unwrap() };
        let m = &sealed["metadata"];
        let ctx = Ctx {
            message_id: m["message_id"].as_str().unwrap(),
            sender_did: m["sender_did"].as_str().unwrap(),
            sender_device_id: m["sender_device_id"].as_str().unwrap(),
            sender_ka_id: sealed["init_body"]["sender_static_key_agreement_id"].as_str().unwrap(),
            recipient_did: m["target"]["did"].as_str().unwrap(),
            recipient_device_id: m["recipient_device_id"].as_str().unwrap(),
        };
        let plain = open_raw(&sealed["init_body"], &ctx, &key("bob_ka_secret"), &key("bob_spk_secret"), &key("alice_ka_public")).expect("the SDK's message must open");
        assert_eq!(plain["payload"], sealed["plaintext"]["payload"]);
        assert_eq!(plain["application_content_type"], sealed["plaintext"]["application_content_type"]);
        // and any change to what the associated data binds makes it fail
        let mut wrong = ctx;
        wrong.recipient_device_id = "dev-other";
        assert!(open_raw(&sealed["init_body"], &wrong, &key("bob_ka_secret"), &key("bob_spk_secret"), &key("alice_ka_public")).is_err());
    }
}