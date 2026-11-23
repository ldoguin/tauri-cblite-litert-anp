//! The MLS (RFC 9420) half of ANP P6 v2: what a **device** does with `openmls`, and nothing about the host.
//!
//! One [`Member`] is one device (a DID and a device id, with its own MLS signature key). It can
//!
//! * make a **key package** whose LeafNode carries the DID-WBA device binding as the draft extension `0xF0A1` (credential identity =
//!   the DID, capabilities and required capabilities listing the extension),
//! * **create** a group (the creator's own leaf carries its binding, the group requires the extension, a 32-byte random group id),
//! * **add** another device from its key package (a commit and a welcome, plus the ratchet tree; the commit's authenticated data is
//!   the P6 add submission binding), and **finalize** that commit once the host accepted it,
//! * **join** from a welcome, **process** a commit made by someone else, **remove** a device,
//! * **encrypt** an application message (authenticated data = the P6 send binding) and **decrypt** one.
//!
//! The suite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; handshake messages are public messages (the host reads commits),
//! application messages are private. The wire objects around all this are in `anp-group`.
//!
//! State is in memory; [`Member::export_state`] and [`Member::import_state`] keep it across processes.

use anp_group::binding::LeafEvidence;
use anp_group::DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT as EXT;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsError(pub String);

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MlsError {}

fn e<T: fmt::Display>(what: &str) -> impl Fn(T) -> MlsError + '_ {
    move |x| MlsError(format!("{what}: {x}"))
}

fn suite() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn ext_type() -> ExtensionType {
    ExtensionType::Unknown(EXT)
}

fn capabilities() -> Capabilities {
    Capabilities::builder().extensions(vec![ext_type()]).credentials(vec![CredentialType::Basic]).build()
}

fn leaf_extensions(binding: &Value) -> Result<Extensions<LeafNode>, MlsError> {
    let bytes = anp_did::jcs(binding).map_err(e("canonical binding"))?.into_bytes();
    Extensions::single(Extension::Unknown(EXT, UnknownExtension(bytes))).map_err(e("leaf extensions"))
}

fn create_config(binding: &Value) -> Result<MlsGroupCreateConfig, MlsError> {
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(suite())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(capabilities())
        .with_leaf_node_extensions(leaf_extensions(binding)?)
        .map_err(e("leaf extensions"))?
        .with_group_context_extensions(Extensions::single(Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[ext_type()], &[], &[]))).map_err(e("required capabilities"))?)
        .use_ratchet_tree_extension(true)
        .build())
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder().wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY).use_ratchet_tree_extension(true).build()
}

/// Run a call into openmls that handles bytes from outside. In a debug build openmls *panics* (a `debug_assert!`) when an AEAD
/// check fails, instead of returning the error it returns in a release build; a damaged message must not be able to take the process
/// down in either, so a panic here becomes an error. (The message key is gone by then, as for any failed decryption.)
fn guarded<T, E: fmt::Display>(f: impl FnOnce() -> Result<T, E>) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r.map_err(|x| x.to_string()),
        Err(_) => Err("the ciphertext could not be decrypted".to_string()),
    }
}

fn tls<T: TlsSerialize>(x: &T, what: &str) -> Result<Vec<u8>, MlsError> {
    x.tls_serialize_detached().map_err(e(what))
}

/// What a leaf of a group says about itself, with the facts [`anp_group::binding::verify`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    pub leaf_index: u32,
    pub evidence: LeafEvidence,
}

impl LeafInfo {
    /// The binding the leaf embeds (its draft extension's data, as JSON), if it has exactly one.
    pub fn binding(&self) -> Option<Value> {
        let mut it = self.evidence.extensions.iter().filter(|(t, _)| *t == EXT);
        let first = it.next()?;
        if it.next().is_some() {
            return None;
        }
        serde_json::from_slice(&first.1).ok()
    }
}

fn evidence_of(leaf: &LeafNode) -> Result<LeafEvidence, MlsError> {
    let mut extensions = Vec::new();
    for x in leaf.extensions().iter() {
        if let Extension::Unknown(t, UnknownExtension(data)) = x {
            extensions.push((*t, data.clone()));
        }
    }
    let caps = leaf.capabilities().extensions().iter().map(|x| u16::from(*x)).collect();
    Ok(LeafEvidence { credential_identity: leaf.credential().serialized_content().to_vec(), leaf_signature_key_b64u: B64U.encode(leaf.signature_key().as_slice()), extensions, leaf_capability_extensions: caps })
}

/// A key package's TLS bytes parsed and checked (its own signatures and lifetime), and what its leaf says.
pub fn inspect_key_package(provider_bytes: &[u8]) -> Result<LeafEvidence, MlsError> {
    let provider = OpenMlsRustCrypto::default();
    let kp = KeyPackageIn::tls_deserialize_exact(provider_bytes).map_err(e("key package"))?;
    let kp = kp.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(e("key package validation"))?;
    evidence_of(kp.leaf_node())
}

/// What `add` produced: bytes to put in the P6 add body, and the epoch the group moves to once the commit is finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOutput {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
    pub next_epoch: u64,
}

/// What the host can read of a commit without being a member: it is a public message, so its framing is clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    /// The leaf index of the member that made it.
    pub sender_leaf: u32,
    pub authenticated_data: Vec<u8>,
    pub is_commit: bool,
}

/// Read the framing of an MLS public message (RFC 9420 sections 6 and 6.1): version, wire format, then the framed content's group id,
/// epoch, sender, authenticated data and content type. Nothing is verified (the host holds no group secrets); the point is to see which
/// group, epoch and authenticated data a commit claims, so that the P6 submission binding can be compared with it.
pub fn inspect_commit(bytes: &[u8]) -> Result<CommitInfo, MlsError> {
    struct R<'a>(&'a [u8]);
    impl<'a> R<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], MlsError> {
            if self.0.len() < n {
                return Err(MlsError("a truncated MLS message".into()));
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Ok(a)
        }
        fn u8(&mut self) -> Result<u8, MlsError> {
            Ok(self.take(1)?[0])
        }
        fn u16(&mut self) -> Result<u16, MlsError> {
            let b = self.take(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]))
        }
        fn u32(&mut self) -> Result<u32, MlsError> {
            let b = self.take(4)?;
            Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
        fn u64(&mut self) -> Result<u64, MlsError> {
            let b = self.take(8)?;
            Ok(u64::from_be_bytes(b.try_into().unwrap()))
        }
        /// A variable-length vector: its length is a QUIC-style variable-length integer.
        fn vec(&mut self) -> Result<&'a [u8], MlsError> {
            let first = *self.0.first().ok_or_else(|| MlsError("a truncated MLS message".into()))?;
            let n = match first >> 6 {
                0 => self.u8()? as usize,
                1 => (self.u16()? & 0x3fff) as usize,
                2 => (self.u32()? & 0x3fff_ffff) as usize,
                _ => return Err(MlsError("an MLS vector length of 8 bytes is not accepted".into())),
            };
            self.take(n)
        }
    }
    let mut r = R(bytes);
    if r.u16()? != 1 {
        return Err(MlsError("not MLS 1.0".into()));
    }
    if r.u16()? != 1 {
        return Err(MlsError("not a public message".into()));
    }
    let group_id = r.vec()?.to_vec();
    let epoch = r.u64()?;
    let sender_leaf = match r.u8()? {
        1 => r.u32()?,
        _ => return Err(MlsError("a commit must come from a member".into())),
    };
    let authenticated_data = r.vec()?.to_vec();
    let is_commit = r.u8()? == 3;
    Ok(CommitInfo { group_id, epoch, sender_leaf, authenticated_data, is_commit })
}
pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    pub did: String,
    pub device_id: String,
    groups: HashMap<Vec<u8>, MlsGroup>,
}

impl Member {
    /// A new device with a fresh MLS signature key.
    pub fn new(did: &str, device_id: &str) -> Result<Member, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(suite().signature_algorithm()).map_err(e("signature key"))?;
        signer.store(provider.storage()).map_err(e("store signature key"))?;
        Ok(Member { provider, signer, did: did.to_string(), device_id: device_id.to_string(), groups: HashMap::new() })
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey { credential: BasicCredential::new(self.did.as_bytes().to_vec()).into(), signature_key: self.signer.to_public_vec().into() }
    }

    /// The MLS signature key of this device's leaf (what the binding names), base64url.
    pub fn leaf_signature_key_b64u(&self) -> String {
        B64U.encode(self.signer.to_public_vec())
    }

    /// A key package whose leaf carries `binding` (a signed binding for this device's leaf key). TLS-serialized.
    pub fn key_package(&mut self, binding: &Value) -> Result<Vec<u8>, MlsError> {
        if binding["leaf_signature_key_b64u"] != self.leaf_signature_key_b64u() {
            return Err(MlsError("the binding names another leaf key than this device's".into()));
        }
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(leaf_extensions(binding)?)
            .build(suite(), &self.provider, &self.signer, self.credential())
            .map_err(e("key package"))?;
        tls(bundle.key_package(), "key package")
    }

    /// Create a group (epoch 0). `binding` is this device's binding, embedded in its own leaf. The group id is 32 random bytes.
    pub fn create_group(&mut self, binding: &Value) -> Result<Vec<u8>, MlsError> {
        let id = self.provider.rand().random_vec(32).map_err(e("random group id"))?;
        let group = MlsGroup::new_with_group_id(&self.provider, &self.signer, &create_config(binding)?, GroupId::from_slice(&id), self.credential()).map_err(e("create group"))?;
        self.groups.insert(id.clone(), group);
        Ok(id)
    }

    pub fn epoch(&self, gid: &[u8]) -> Option<u64> {
        self.groups.get(gid).map(|g| g.epoch().as_u64())
    }

    /// The secret-derived value the members of an epoch share (`epoch_authenticator` of a cipher object).
    pub fn epoch_authenticator(&self, gid: &[u8]) -> Option<Vec<u8>> {
        self.groups.get(gid).map(|g| g.epoch_authenticator().as_slice().to_vec())
    }

    /// The extension types the group requires of its members.
    pub fn required_extensions(&self, gid: &[u8]) -> Vec<u16> {
        self.groups.get(gid).and_then(|g| g.extensions().required_capabilities().map(|r| r.extension_types().iter().map(|t| u16::from(*t)).collect())).unwrap_or_default()
    }

    /// Every leaf of the group with what it carries.
    pub fn leaves(&self, gid: &[u8]) -> Result<Vec<LeafInfo>, MlsError> {
        let g = self.groups.get(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        let public = PublicGroup::load(self.provider.storage(), g.group_id()).map_err(e("public group"))?.ok_or_else(|| MlsError("the public group is not stored".into()))?;
        let mut out = Vec::new();
        for m in g.members() {
            let leaf = public.leaf(m.index).ok_or_else(|| MlsError("a member without a leaf".into()))?;
            out.push(LeafInfo { leaf_index: m.index.u32(), evidence: evidence_of(leaf)? });
        }
        Ok(out)
    }

    /// Add the device behind `key_package` (TLS bytes). The commit's authenticated data is `aad` (the P6 add submission binding).
    /// The commit is pending: [`Member::finalize_commit`] applies it once the host accepted it, [`Member::abort_commit`] drops it.
    pub fn add_member(&mut self, gid: &[u8], key_package: &[u8], aad: &[u8]) -> Result<AddOutput, MlsError> {
        let kp = KeyPackageIn::tls_deserialize_exact(key_package).map_err(e("key package"))?;
        let kp = kp.validate(self.provider.crypto(), ProtocolVersion::Mls10).map_err(e("key package validation"))?;
        let signer = &self.signer;
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        let next_epoch = group.epoch().as_u64() + 1;
        group.set_aad(aad.to_vec());
        let original = group.export_ratchet_tree();
        let (commit, welcome, _) = group.add_members(&self.provider, signer, &[kp]).map_err(e("add"))?;
        let pending = group.pending_commit().ok_or_else(|| MlsError("no pending commit after add".into()))?;
        let tree: RatchetTreeIn = pending.export_ratchet_tree(self.provider.crypto(), original).map_err(e("ratchet tree"))?.ok_or_else(|| MlsError("the pending commit has no ratchet tree".into()))?.into();
        let welcome = match welcome.body() {
            MlsMessageBodyOut::Welcome(w) => tls(w, "welcome")?,
            _ => return Err(MlsError("add did not produce a welcome".into())),
        };
        Ok(AddOutput { commit: tls(&commit, "commit")?, welcome, ratchet_tree: tls(&tree, "ratchet tree")?, next_epoch })
    }

    /// Remove the device `(did, device_id)` (found by its credential and the binding in its leaf). The commit's authenticated data is
    /// `aad` (the P6 remove submission binding); it is pending like an add's. Returns the commit's TLS bytes.
    pub fn remove_member(&mut self, gid: &[u8], did: &str, device_id: &str, aad: &[u8]) -> Result<Vec<u8>, MlsError> {
        let leaf = self.leaves(gid)?.into_iter().find(|l| l.evidence.credential_identity == did.as_bytes() && l.binding().map_or(false, |b| b["device_id"] == device_id)).ok_or_else(|| MlsError("no such leaf in the group".into()))?;
        let signer = &self.signer;
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        group.set_aad(aad.to_vec());
        let (commit, _, _) = group.remove_members(&self.provider, signer, &[LeafNodeIndex::new(leaf.leaf_index)]).map_err(e("remove"))?;
        tls(&commit, "commit")
    }

    /// The host accepted our commit: apply it.
    pub fn finalize_commit(&mut self, gid: &[u8]) -> Result<u64, MlsError> {
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        group.merge_pending_commit(&self.provider).map_err(e("merge"))?;
        Ok(group.epoch().as_u64())
    }

    /// The host refused our commit: drop it.
    pub fn abort_commit(&mut self, gid: &[u8]) -> Result<(), MlsError> {
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        group.clear_pending_commit(self.provider.storage()).map_err(e("clear pending commit"))
    }

    /// Join the group a welcome (with its ratchet tree) is for. Returns the group id and the epoch.
    pub fn join(&mut self, welcome: &[u8], ratchet_tree: &[u8]) -> Result<(Vec<u8>, u64), MlsError> {
        let welcome = Welcome::tls_deserialize_exact(welcome).map_err(e("welcome"))?;
        let tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree).map_err(e("ratchet tree"))?;
        let staged = StagedWelcome::build_from_welcome(&self.provider, &join_config(), welcome).map_err(e("welcome"))?.with_ratchet_tree(tree).build().map_err(e("welcome"))?;
        let group = staged.into_group(&self.provider).map_err(e("join"))?;
        let (id, epoch) = (group.group_id().as_slice().to_vec(), group.epoch().as_u64());
        self.groups.insert(id.clone(), group);
        Ok((id, epoch))
    }

    /// Process a commit somebody else made. Its authenticated data must be `expected_aad` (the P6 binding of the submission it came
    /// with). Returns the new epoch.
    pub fn process_commit(&mut self, gid: &[u8], commit: &[u8], expected_aad: &[u8]) -> Result<u64, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(commit).map_err(e("commit"))?;
        let protocol = message.try_into_protocol_message().map_err(e("commit"))?;
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        let provider = &self.provider;
        let processed = guarded(|| group.process_message(provider, protocol)).map_err(e("commit"))?;
        if processed.aad() != expected_aad {
            return Err(MlsError("the commit's authenticated data is not the submission binding".into()));
        }
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group.merge_staged_commit(&self.provider, *staged).map_err(e("merge"))?;
                Ok(group.epoch().as_u64())
            }
            _ => Err(MlsError("not a commit".into())),
        }
    }

    /// Encrypt `plaintext` (the canonical group application plaintext) as a private message with `aad` (the send binding).
    pub fn encrypt(&mut self, gid: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MlsError> {
        let signer = &self.signer;
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        group.set_aad(aad.to_vec());
        let m = group.create_message(&self.provider, signer, plaintext).map_err(e("encrypt"))?;
        match m.body() {
            MlsMessageBodyOut::PrivateMessage(p) => tls(p, "private message"),
            _ => Err(MlsError("openmls did not produce a private message".into())),
        }
    }

    /// Decrypt a private message. Its authenticated data must be `expected_aad` (checked first, so that a wrong context costs nothing).
    /// A message that fails after that point (a damaged ciphertext) has already used up its key: MLS keeps no key it has used.
    /// Returns the plaintext and the sender's leaf.
    pub fn decrypt(&mut self, gid: &[u8], private_message: &[u8], expected_aad: &[u8]) -> Result<(Vec<u8>, LeafInfo), MlsError> {
        let pm = PrivateMessageIn::tls_deserialize_exact(private_message).map_err(e("private message"))?;
        // Look at the authenticated data *before* the message is processed: openmls deletes the message key as it decrypts (forward
        // secrecy), so a message that is refused for the wrong context after decryption could never be read again.
        if pm.aad() != expected_aad {
            return Err(MlsError("the message's authenticated data is not the send binding".into()));
        }
        let protocol: ProtocolMessage = pm.into();
        let group = self.groups.get_mut(gid).ok_or_else(|| MlsError("no such group here".into()))?;
        let provider = &self.provider;
        let processed = guarded(|| group.process_message(provider, protocol)).map_err(e("decrypt"))?;
        if processed.aad() != expected_aad {
            return Err(MlsError("the message's authenticated data is not the send binding".into()));
        }
        let sender = match processed.sender() {
            Sender::Member(i) => i.u32(),
            _ => return Err(MlsError("the sender is not a member".into())),
        };
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => a.into_bytes(),
            _ => return Err(MlsError("not an application message".into())),
        };
        let leaf = self.leaves(gid)?.into_iter().find(|l| l.leaf_index == sender).ok_or_else(|| MlsError("the sender's leaf is not in the group".into()))?;
        Ok((plaintext, leaf))
    }

    // ── keeping the state across processes ────────────────────────────────────────────────────────────

    /// Everything this device holds, as JSON: the key store of openmls and the group ids.
    pub fn export_state(&self) -> Value {
        let values = self.provider.storage().values.read().unwrap();
        let map: serde_json::Map<String, Value> = values.iter().map(|(k, v)| (B64U.encode(k), json!(B64U.encode(v)))).collect();
        json!({
            "did": self.did, "device_id": self.device_id,
            "signer_public": B64U.encode(self.signer.to_public_vec()),
            "storage": map,
            "groups": self.groups.keys().map(|k| B64U.encode(k)).collect::<Vec<_>>(),
        })
    }

    pub fn import_state(state: &Value) -> Result<Member, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider.storage().values.write().unwrap();
            for (k, v) in state["storage"].as_object().ok_or_else(|| MlsError("no storage".into()))? {
                values.insert(B64U.decode(k).map_err(e("storage key"))?, B64U.decode(v.as_str().unwrap_or_default()).map_err(e("storage value"))?);
            }
        }
        let public = B64U.decode(state["signer_public"].as_str().unwrap_or_default()).map_err(e("signer"))?;
        let signer = SignatureKeyPair::read(provider.storage(), &public, suite().signature_algorithm()).ok_or_else(|| MlsError("the signature key is not in the stored state".into()))?;
        let mut groups = HashMap::new();
        for g in state["groups"].as_array().into_iter().flatten() {
            let id = B64U.decode(g.as_str().unwrap_or_default()).map_err(e("group id"))?;
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&id)).map_err(e("load group"))?.ok_or_else(|| MlsError("a group is missing from the stored state".into()))?;
            groups.insert(id, group);
        }
        Ok(Member { provider, signer, did: state["did"].as_str().unwrap_or_default().to_string(), device_id: state["device_id"].as_str().unwrap_or_default().to_string(), groups })
    }
}