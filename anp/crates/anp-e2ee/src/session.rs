//! P5 sessions: the Double Ratchet that follows an init message (ANP-09, `anp.direct.e2ee.v2`).
//!
//! [`seal`](crate::seal) and [`open`](crate::open) treat every message as its own init and keep no state, which suits
//! documents in a replicated store. This module is the other half of P5: a session between one local and one peer
//! device, started by an init and continued by *follow-up* messages that ratchet forward, so that other ANP stacks can
//! hold a conversation with us. The behaviour follows the ANP Rust SDK's `v2_session` (read, then checked by exchanging
//! messages with it in both directions: see `scripts/interop`):
//!
//! * The initiator's session is **pending** after the init: it may not send follow-ups until the peer's first reply, which
//!   must carry `pn = 0, n = 0`. The responder is **established** at once and sends first.
//! * Every direction change turns the DH ratchet: a new ratchet key pair, a new root key and chain (`kdf_rk`), and the
//!   previous chain's length goes into the header as `pn`.
//! * Messages may arrive late or out of order: keys for the messages skipped are kept (at most [`MAX_SKIP`]); a key that
//!   matches is consumed even if authentication then fails, so it can never be used twice.
//! * Receiving changes nothing unless the message authenticates (apart from consuming a matching skipped key).

use crate::{
    init_aad, kdf_ck, kdf_rk, public_of, x3dh_secrets, Bundle, Ctx, E2eeError, APP_CONTENT_TYPE, PROFILE, SECURITY_PROFILE, SUITE,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

/// How many message keys may be skipped (and kept) per session.
pub const MAX_SKIP: u32 = 1000;
pub const CIPHER_CONTENT_TYPE: &str = "application/anp-direct-cipher+json";

fn err<T>(s: impl Into<String>) -> Result<T, E2eeError> {
    Err(E2eeError(s.into()))
}
fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the operating system has no randomness");
    b
}
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], E2eeError> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return err("a Diffie-Hellman input was a low-order point");
    }
    Ok(*shared.as_bytes())
}
fn aead_seal(mk: &[u8; 32], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, E2eeError> {
    ChaCha20Poly1305::new(Key::from_slice(mk)).encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad }).map_err(|_| E2eeError("encryption failed".into()))
}
fn aead_open(mk: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, E2eeError> {
    ChaCha20Poly1305::new(Key::from_slice(mk)).decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).map_err(|_| E2eeError("decryption failed (wrong key, or the message was altered or moved)".into()))
}
fn b64(v: &[u8]) -> String {
    B64U.encode(v)
}
fn unb64<const N: usize>(s: &str, what: &str) -> Result<[u8; N], E2eeError> {
    B64U.decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| E2eeError(format!("{what}: expected {N} bytes of base64url")))
}
fn u32_of(s: &str, what: &str) -> Result<u32, E2eeError> {
    if s.is_empty() || s.len() > 1 && s.starts_with('0') || !s.chars().all(|c| c.is_ascii_digit()) {
        return err(format!("{what} is not a canonical decimal string"));
    }
    s.parse().map_err(|_| E2eeError(format!("{what} is out of range")))
}

/// Who talks to whom: one local and one peer device, and the key-agreement keys they use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub local_did: String,
    pub local_device_id: String,
    pub local_ka_id: String,
    pub peer_did: String,
    pub peer_device_id: String,
    pub peer_ka_id: String,
}

/// A one-time prekey the recipient publishes with a bundle and uses once.
#[derive(Debug, Clone)]
pub struct OneTimePrekey {
    pub id: String,
    pub public: [u8; 32],
}

/// What a recipient holds of its own bundle, to accept an init.
pub struct LocalBundle<'a> {
    pub bundle_id: &'a str,
    pub signed_prekey_id: &'a str,
    pub signed_prekey_secret: &'a [u8; 32],
    /// The one-time prekey the sender used, if any: its id and secret. The caller must consume it atomically with
    /// persisting the session.
    pub one_time_prekey: Option<(&'a str, &'a [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Skipped {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
    nonce: [u8; 12],
}

/// A P5 session. Serialisable ([`Session::to_json`]) for a store that is itself protected: it holds secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub binding: Binding,
    session_id: String,
    root: [u8; 32],
    send_ck: Option<[u8; 32]>,
    recv_ck: Option<[u8; 32]>,
    ratchet_secret: [u8; 32],
    ratchet_public: [u8; 32],
    peer_ratchet: Option<[u8; 32]>,
    send_n: u32,
    recv_n: u32,
    pn: u32,
    skipped: Vec<Skipped>,
    initiator: bool,
    established: bool,
}

/// The associated data of a follow-up message: P5 v2's `AD_msg`, serialised with RFC 8785. Checked in the tests against
/// the ANP SDK's `expected_ad_msg`.
pub fn message_aad(ctx: &Ctx, session_id: &str, dh_pub_b64u: &str, pn: &str, n: &str) -> Result<Vec<u8>, E2eeError> {
    let ad = json!({
        "content_type": CIPHER_CONTENT_TYPE,
        "message_id": ctx.message_id,
        "operation_id": ctx.message_id,
        "profile": PROFILE,
        "security_profile": SECURITY_PROFILE,
        "sender_did": ctx.sender_did,
        "sender_device_id": ctx.sender_device_id,
        "recipient_did": ctx.recipient_did,
        "recipient_device_id": ctx.recipient_device_id,
        "session_id": session_id,
        "ratchet_header": { "dh_pub_b64u": dh_pub_b64u, "pn": pn, "n": n },
    });
    anp_did::jcs(&ad).map(String::into_bytes).map_err(|e| E2eeError(e.to_string()))
}

fn plain_bytes(plaintext: &Value) -> Result<Vec<u8>, E2eeError> {
    if plaintext["application_content_type"].as_str().map_or(true, str::is_empty) {
        return err("the application plaintext needs an application_content_type");
    }
    let present = ["text", "payload", "payload_b64u"].iter().filter(|k| plaintext.get(**k).is_some()).count();
    if present != 1 {
        return err("exactly one of text, payload or payload_b64u is required");
    }
    anp_did::jcs(plaintext).map(String::into_bytes).map_err(|e| E2eeError(e.to_string()))
}

fn parse_plain(bytes: &[u8]) -> Result<Value, E2eeError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| E2eeError("the plaintext is not JSON".into()))?;
    // P5: the decoded plaintext must be exactly its canonical form
    let canon = anp_did::jcs(&v).map_err(|e| E2eeError(e.to_string()))?;
    if canon.as_bytes() != bytes {
        return err("the plaintext is not in canonical form");
    }
    Ok(v)
}

/// A plaintext carrying a JSON object payload (what this project exchanges), with our content type.
pub fn payload_plaintext(message_id: &str, payload: &Value) -> Value {
    json!({ "application_content_type": APP_CONTENT_TYPE, "logical_message_id": message_id, "payload": payload })
}

impl Session {
    fn ctx_out<'a>(&'a self, message_id: &'a str) -> Ctx<'a> {
        Ctx {
            message_id,
            sender_did: &self.binding.local_did,
            sender_device_id: &self.binding.local_device_id,
            sender_ka_id: &self.binding.local_ka_id,
            recipient_did: &self.binding.peer_did,
            recipient_device_id: &self.binding.peer_device_id,
        }
    }
    fn ctx_in<'a>(&'a self, message_id: &'a str) -> Ctx<'a> {
        Ctx {
            message_id,
            sender_did: &self.binding.peer_did,
            sender_device_id: &self.binding.peer_device_id,
            sender_ka_id: &self.binding.peer_ka_id,
            recipient_did: &self.binding.local_did,
            recipient_device_id: &self.binding.local_device_id,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn is_established(&self) -> bool {
        self.established
    }
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Start a session with the owner of `rcpt` and produce the init message body. `local_ka_secret` is our static
    /// key-agreement secret; `opk` a one-time prekey of the recipient, if the key service issued one. The session is
    /// pending until the first reply.
    pub fn initiate(binding: &Binding, message_id: &str, local_ka_secret: &[u8; 32], rcpt: &Bundle, opk: Option<&OneTimePrekey>, plaintext: &Value) -> Result<(Session, Value), E2eeError> {
        if binding.peer_did != rcpt.owner_did || binding.peer_device_id != rcpt.device_id || binding.peer_ka_id != rcpt.ka_id {
            return err("the bundle does not belong to the peer of this session");
        }
        let esk = random32();
        let epk = public_of(&esk);
        let mut dhs = vec![dh(local_ka_secret, &rcpt.spk_public)?, dh(&esk, &rcpt.ka_public)?, dh(&esk, &rcpt.spk_public)?];
        if let Some(o) = opk {
            dhs.push(dh(&esk, &o.public)?);
        }
        let (_sk, rk0, ck0, sid) = x3dh_secrets(&dhs);
        let (ck1, mk, nonce) = kdf_ck(&ck0);
        let session_id = b64(&sid);
        let mut s = Session {
            binding: binding.clone(),
            session_id: session_id.clone(),
            root: rk0,
            send_ck: Some(ck1),
            recv_ck: None,
            ratchet_secret: esk,
            ratchet_public: epk,
            peer_ratchet: None,
            send_n: 1,
            recv_n: 0,
            pn: 0,
            skipped: vec![],
            initiator: true,
            established: false,
        };
        let aad = init_aad(&s.ctx_out(message_id), &rcpt.bundle_id, &rcpt.spk_id, opk.map(|o| o.id.as_str()), &session_id)?;
        let ct = aead_seal(&mk, &nonce, &plain_bytes(plaintext)?, &aad)?;
        s.skipped.clear();
        let mut body = json!({
            "session_id": session_id,
            "suite": SUITE,
            "sender_static_key_agreement_id": binding.local_ka_id,
            "recipient_bundle_id": rcpt.bundle_id,
            "recipient_signed_prekey_id": rcpt.spk_id,
            "sender_ephemeral_pub_b64u": b64(&epk),
            "ciphertext_b64u": b64(&ct),
        });
        if let Some(o) = opk {
            body["recipient_one_time_prekey_id"] = json!(o.id);
        }
        Ok((s, body))
    }

    /// Accept an init message: returns the established session and the plaintext. `sender_ka_public` is the sender's
    /// static key-agreement key from its verified DID document.
    pub fn accept(binding: &Binding, message_id: &str, local_ka_secret: &[u8; 32], local: &LocalBundle, sender_ka_public: &[u8; 32], init: &Value) -> Result<(Session, Value), E2eeError> {
        let field = |k: &str| init[k].as_str().ok_or_else(|| E2eeError(format!("init has no {k}")));
        if field("suite")? != SUITE {
            return err("unsupported cipher suite");
        }
        if field("sender_static_key_agreement_id")? != binding.peer_ka_id {
            return err("the sender's key-agreement id does not match");
        }
        if field("recipient_bundle_id")? != local.bundle_id || field("recipient_signed_prekey_id")? != local.signed_prekey_id {
            return err("the init is not addressed to our current bundle");
        }
        let opk_secret = match (init.get("recipient_one_time_prekey_id").and_then(Value::as_str), local.one_time_prekey) {
            (None, None) => None,
            (Some(want), Some((have, secret))) if want == have => Some(secret),
            _ => return err("the one-time prekey of the init is not the one supplied"),
        };
        let epk: [u8; 32] = unb64(field("sender_ephemeral_pub_b64u")?, "sender_ephemeral_pub_b64u")?;
        let ct = B64U.decode(field("ciphertext_b64u")?).map_err(|_| E2eeError("bad ciphertext encoding".into()))?;
        let mut dhs = vec![dh(local.signed_prekey_secret, sender_ka_public)?, dh(local_ka_secret, &epk)?, dh(local.signed_prekey_secret, &epk)?];
        if let Some(o) = opk_secret {
            dhs.push(dh(o, &epk)?);
        }
        let (_sk, rk0, ck0, sid) = x3dh_secrets(&dhs);
        if field("session_id")? != b64(&sid) {
            return err("the session id does not match the shared secret");
        }
        let (ck1, mk, nonce) = kdf_ck(&ck0);
        let mut s = Session {
            binding: binding.clone(),
            session_id: b64(&sid),
            root: rk0,
            send_ck: None,
            recv_ck: Some(ck1),
            ratchet_secret: [0; 32],
            ratchet_public: [0; 32],
            peer_ratchet: Some(epk),
            send_n: 0,
            recv_n: 1,
            pn: 0,
            skipped: vec![],
            initiator: false,
            established: true,
        };
        let aad = init_aad(&s.ctx_in(message_id), local.bundle_id, local.signed_prekey_id, init.get("recipient_one_time_prekey_id").and_then(Value::as_str), &s.session_id)?;
        let plain = parse_plain(&aead_open(&mk, &nonce, &ct, &aad)?)?;
        // the responder turns the ratchet at once, so it can send first
        let rsecret = random32();
        let (root, send_ck) = kdf_rk(&rk0, &dh(&rsecret, &epk)?);
        s.root = root;
        s.send_ck = Some(send_ck);
        s.ratchet_secret = rsecret;
        s.ratchet_public = public_of(&rsecret);
        Ok((s, plain))
    }

    /// Encrypt a follow-up message. Only an established session can send: the initiator must wait for the first reply.
    pub fn encrypt(&mut self, message_id: &str, plaintext: &Value) -> Result<Value, E2eeError> {
        if !self.established {
            return err("the session is pending: the first reply has not arrived yet");
        }
        let ck = self.send_ck.ok_or_else(|| E2eeError("no send chain".into()))?;
        let (next, mk, nonce) = kdf_ck(&ck);
        let (dh_pub, pn, n) = (b64(&self.ratchet_public), self.pn.to_string(), self.send_n.to_string());
        let aad = message_aad(&self.ctx_out(message_id), &self.session_id, &dh_pub, &pn, &n)?;
        let ct = aead_seal(&mk, &nonce, &plain_bytes(plaintext)?, &aad)?;
        let next_n = self.send_n.checked_add(1).ok_or_else(|| E2eeError("send counter overflow".into()))?;
        self.send_ck = Some(next);
        self.send_n = next_n;
        Ok(json!({
            "session_id": self.session_id,
            "suite": SUITE,
            "ratchet_header": { "dh_pub_b64u": dh_pub, "pn": pn, "n": n },
            "ciphertext_b64u": b64(&ct),
        }))
    }

    /// Decrypt a follow-up message. Late and out-of-order messages work (within [`MAX_SKIP`]); a replay does not.
    pub fn decrypt(&mut self, message_id: &str, body: &Value) -> Result<Value, E2eeError> {
        if body["session_id"].as_str() != Some(self.session_id.as_str()) {
            return err("the message belongs to another session");
        }
        if let Some(s) = body["suite"].as_str() {
            if s != SUITE {
                return err("unsupported cipher suite");
            }
        }
        let h = &body["ratchet_header"];
        let dh_pub_s = h["dh_pub_b64u"].as_str().ok_or_else(|| E2eeError("no ratchet header".into()))?;
        let dh_pub: [u8; 32] = unb64(dh_pub_s, "dh_pub_b64u")?;
        let (pn_s, n_s) = (h["pn"].as_str().unwrap_or(""), h["n"].as_str().unwrap_or(""));
        let (pn, n) = (u32_of(pn_s, "pn")?, u32_of(n_s, "n")?);
        let ct = B64U.decode(body["ciphertext_b64u"].as_str().unwrap_or("")).map_err(|_| E2eeError("bad ciphertext encoding".into()))?;
        let aad = message_aad(&self.ctx_in(message_id), &self.session_id, dh_pub_s, pn_s, n_s)?;

        if !self.established {
            return self.first_reply(&dh_pub, pn, n, &ct, &aad);
        }
        // a key we kept for a message that arrived late: used at most once, even if it fails
        if let Some(i) = self.skipped.iter().position(|k| k.dh == dh_pub && k.n == n) {
            let k = self.skipped.remove(i);
            return parse_plain(&aead_open(&k.mk, &k.nonce, &ct, &aad)?);
        }
        let mut next = self.clone();
        if next.peer_ratchet != Some(dh_pub) {
            next.skip_to(pn)?;
            next.ratchet(&dh_pub)?;
        }
        if n < next.recv_n {
            return err("a replay, or a message whose key is gone");
        }
        next.skip_to(n)?;
        let (next_ck, mk, nonce) = kdf_ck(&next.recv_ck.ok_or_else(|| E2eeError("no receive chain".into()))?);
        let plain = parse_plain(&aead_open(&mk, &nonce, &ct, &aad)?)?;
        next.recv_ck = Some(next_ck);
        next.recv_n = n.checked_add(1).ok_or_else(|| E2eeError("receive counter overflow".into()))?;
        *self = next;
        Ok(plain)
    }

    /// The first reply to our init: it must start the peer's first chain (`pn = 0`, `n = 0`).
    fn first_reply(&mut self, dh_pub: &[u8; 32], pn: u32, n: u32, ct: &[u8], aad: &[u8]) -> Result<Value, E2eeError> {
        if pn != 0 || n != 0 {
            return err("the first reply must have pn = 0 and n = 0");
        }
        let (root1, recv_ck) = kdf_rk(&self.root, &dh(&self.ratchet_secret, dh_pub)?);
        let new_secret = random32();
        let (root2, send_ck) = kdf_rk(&root1, &dh(&new_secret, dh_pub)?);
        let (next_ck, mk, nonce) = kdf_ck(&recv_ck);
        let plain = parse_plain(&aead_open(&mk, &nonce, ct, aad)?)?;
        self.root = root2;
        self.recv_ck = Some(next_ck);
        self.send_ck = Some(send_ck);
        self.peer_ratchet = Some(*dh_pub);
        self.pn = self.send_n;
        self.send_n = 0;
        self.recv_n = 1;
        self.ratchet_secret = new_secret;
        self.ratchet_public = public_of(&new_secret);
        self.established = true;
        Ok(plain)
    }

    /// Keep the keys of the messages of the current receive chain up to (not including) `until`.
    fn skip_to(&mut self, until: u32) -> Result<(), E2eeError> {
        if until < self.recv_n {
            return Ok(());
        }
        if until - self.recv_n > MAX_SKIP {
            return err("too many messages skipped");
        }
        let mut ck = self.recv_ck.ok_or_else(|| E2eeError("no receive chain for skipped messages".into()))?;
        let dhk = self.peer_ratchet.ok_or_else(|| E2eeError("no peer ratchet key".into()))?;
        while self.recv_n < until {
            let (next, mk, nonce) = kdf_ck(&ck);
            if self.skipped.len() >= MAX_SKIP as usize {
                self.skipped.remove(0); // the oldest goes first
            }
            self.skipped.push(Skipped { dh: dhk, n: self.recv_n, mk, nonce });
            ck = next;
            self.recv_n += 1;
        }
        self.recv_ck = Some(ck);
        Ok(())
    }

    /// The peer has a new ratchet key: derive the new receive chain, then a new sending chain of our own.
    fn ratchet(&mut self, peer_new: &[u8; 32]) -> Result<(), E2eeError> {
        let (root1, recv_ck) = kdf_rk(&self.root, &dh(&self.ratchet_secret, peer_new)?);
        let new_secret = random32();
        let (root2, send_ck) = kdf_rk(&root1, &dh(&new_secret, peer_new)?);
        self.root = root2;
        self.recv_ck = Some(recv_ck);
        self.send_ck = Some(send_ck);
        self.peer_ratchet = Some(*peer_new);
        self.pn = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;
        self.ratchet_secret = new_secret;
        self.ratchet_public = public_of(&new_secret);
        Ok(())
    }

    /// How many skipped keys are being kept.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    // ── persistence ─────────────────────────────────────────────────────────────────────────────────────

    /// The session as JSON, secrets included: keep it where the rest of the node's secrets are.
    pub fn to_json(&self) -> Value {
        let opt = |k: &Option<[u8; 32]>| k.map(|v| json!(b64(&v))).unwrap_or(Value::Null);
        json!({
            "format": "anp-cblite.p5-session.v1",
            "binding": {
                "local_did": self.binding.local_did, "local_device_id": self.binding.local_device_id, "local_ka_id": self.binding.local_ka_id,
                "peer_did": self.binding.peer_did, "peer_device_id": self.binding.peer_device_id, "peer_ka_id": self.binding.peer_ka_id,
            },
            "session_id": self.session_id,
            "root": b64(&self.root), "send_ck": opt(&self.send_ck), "recv_ck": opt(&self.recv_ck),
            "ratchet_secret": b64(&self.ratchet_secret), "ratchet_public": b64(&self.ratchet_public), "peer_ratchet": opt(&self.peer_ratchet),
            "send_n": self.send_n, "recv_n": self.recv_n, "pn": self.pn,
            "skipped": self.skipped.iter().map(|k| json!({ "dh": b64(&k.dh), "n": k.n, "mk": b64(&k.mk), "nonce": b64(&k.nonce) })).collect::<Vec<_>>(),
            "initiator": self.initiator, "established": self.established,
        })
    }

    pub fn from_json(v: &Value) -> Result<Session, E2eeError> {
        if v["format"] != "anp-cblite.p5-session.v1" {
            return err("not a session of this format");
        }
        let s = |k: &str| v["binding"][k].as_str().map(str::to_string).ok_or_else(|| E2eeError(format!("binding.{k} missing")));
        let key = |k: &str| -> Result<[u8; 32], E2eeError> { unb64(v[k].as_str().unwrap_or(""), k) };
        let opt = |k: &str| -> Result<Option<[u8; 32]>, E2eeError> {
            match v[k].as_str() {
                Some(x) => unb64(x, k).map(Some),
                None => Ok(None),
            }
        };
        let num = |k: &str| v[k].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| E2eeError(format!("{k} missing")));
        let mut skipped = Vec::new();
        for k in v["skipped"].as_array().ok_or_else(|| E2eeError("skipped missing".into()))? {
            skipped.push(Skipped {
                dh: unb64(k["dh"].as_str().unwrap_or(""), "skipped.dh")?,
                n: k["n"].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| E2eeError("skipped.n".into()))?,
                mk: unb64(k["mk"].as_str().unwrap_or(""), "skipped.mk")?,
                nonce: unb64(k["nonce"].as_str().unwrap_or(""), "skipped.nonce")?,
            });
        }
        if skipped.len() > MAX_SKIP as usize {
            return err("more skipped keys than allowed");
        }
        let ratchet_secret = key("ratchet_secret")?;
        let ratchet_public = key("ratchet_public")?;
        if public_of(&ratchet_secret) != ratchet_public {
            return err("the ratchet public key does not match its secret");
        }
        Ok(Session {
            binding: Binding {
                local_did: s("local_did")?,
                local_device_id: s("local_device_id")?,
                local_ka_id: s("local_ka_id")?,
                peer_did: s("peer_did")?,
                peer_device_id: s("peer_device_id")?,
                peer_ka_id: s("peer_ka_id")?,
            },
            session_id: v["session_id"].as_str().ok_or_else(|| E2eeError("session_id missing".into()))?.to_string(),
            root: key("root")?,
            send_ck: opt("send_ck")?,
            recv_ck: opt("recv_ck")?,
            ratchet_secret,
            ratchet_public,
            peer_ratchet: opt("peer_ratchet")?,
            send_n: num("send_n")?,
            recv_n: num("recv_n")?,
            pn: num("pn")?,
            skipped,
            initiator: v["initiator"].as_bool().unwrap_or(false),
            established: v["established"].as_bool().unwrap_or(false),
        })
    }
}
