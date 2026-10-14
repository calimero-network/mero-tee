//! The wire protocol between an agent's owner and the gate in its TD.
//!
//! One agent TD hosts several agents, each in its own slot under its own Unix
//! user, each claimed by its own owner. A request names the agent it is for by
//! its **agent id** (`[a-z0-9][a-z0-9-]{0,62}`), which whoever places the agent
//! (mdma) chooses.
//!
//! For each agent the gate holds the public keys a verifier cares about:
//!
//! * the **provisioning key**, an X25519 HPKE key generated in memory at each
//!   start and shared by every agent on the TD. Secrets are sealed to it, so
//!   only this boot of this TD can open them. It is never written anywhere.
//! * the agent's **signing key**, the Ed25519 key it signs warrants with. An
//!   account owner authorizes it as a device. Generated in the TD when the
//!   agent is claimed and kept on the encrypted data disk, readable only by
//!   that agent's user.
//! * the agent's **owner key**, the X25519 key of whoever claimed it: the
//!   sender of the first secrets bundle the gate accepted for that agent id.
//!   Kept on the encrypted disk; only its holder can provision or release the
//!   agent from then on. Nobody chooses it at build time -- not the operator,
//!   not the release.
//!
//! `/attest` returns a TDX quote whose report data is
//! `nonce ‖ SHA-256(ATTEST_DOMAIN ‖ provisioning_pub ‖ len(agent_id) ‖ agent_id
//! ‖ signing_pub ‖ owner_pub)` (`signing_pub` and `owner_pub` all zeros while
//! the agent is unclaimed), so one quote proves which owner and signing key that
//! agent id has, on a TD with the measured agent image. An owner who finds
//! someone else's key there walks away: it sends no secrets and authorizes no
//! device. A quote with an empty agent id names no agent: it measures the TD.
//!
//! `/provision` and `/release` take an RFC 9180 HPKE message (DHKEM(X25519,
//! HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) sealed to the provisioning key
//! in **Auth mode** under the sender's static X25519 key, so the gate knows who
//! sent it. `info` binds the message to the recipient key and the agent id, so
//! it cannot be replayed to another gate, across a restart, or to another agent.

use std::collections::BTreeMap;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::os_rng;

/// Domain of the report-data binding over an agent's keys. v3: v2 bound one
/// agent per TD, with no agent id; v1 bound no owner.
pub const ATTEST_DOMAIN: &[u8] = b"mero-agent-gate/attest/v3";
/// HPKE `info` prefix; the recipient's public key and the agent id follow it.
/// v2: v1 named no agent.
pub const PROVISION_INFO_DOMAIN: &[u8] = b"mero-agent-gate/provision/v2";

/// At most this many bytes in an agent id.
pub const MAX_AGENT_ID_LEN: usize = 63;

/// At most this many secrets in one bundle.
pub const MAX_SECRETS: usize = 64;
/// At most this many bytes in one secret's value.
pub const MAX_SECRET_LEN: usize = 64 * 1024;

pub type Kem = X25519HkdfSha256;
pub type Kdf = HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
pub type PublicKey = <Kem as KemTrait>::PublicKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

/// An agent id: what whoever places the agent calls it, and the name its claim
/// is kept under. `[a-z0-9][a-z0-9-]{0,62}`.
pub fn validate_agent_id(id: &str) -> Result<(), String> {
    let bytes = id.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if !first_ok || !rest_ok || bytes.len() > MAX_AGENT_ID_LEN {
        return Err(format!(
            "agent id '{}' must match [a-z0-9][a-z0-9-]{{0,62}}",
            id.escape_debug()
        ));
    }
    Ok(())
}

/// The agent id, length first, so no id is a prefix of another's encoding.
fn agent_id_bytes(agent_id: &str) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(agent_id.len()).unwrap_or(u8::MAX)];
    bytes.extend_from_slice(agent_id.as_bytes());
    bytes
}

/// The 32 bytes after the nonce in the gate's quote, for `agent_id` (empty: the
/// TD itself, no agent). An unclaimed agent binds an all-zero signing key and
/// owner, which no key a provisioner holds can equal in practice.
pub fn key_binding(
    provisioning_public: &[u8; 32],
    agent_id: &str,
    signing_public: Option<&[u8; 32]>,
    owner_public: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ATTEST_DOMAIN);
    hasher.update(provisioning_public);
    hasher.update(agent_id_bytes(agent_id));
    hasher.update(signing_public.unwrap_or(&[0u8; 32]));
    hasher.update(owner_public.unwrap_or(&[0u8; 32]));
    hasher.finalize().into()
}

/// The 64 bytes of report data the gate's quote carries.
pub fn report_data(nonce: &[u8; 32], binding: &[u8; 32]) -> [u8; 64] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(nonce);
    data[32..].copy_from_slice(binding);
    data
}

/// `POST /attest` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestRequest {
    /// Base64 32-byte nonce the verifier chose.
    pub nonce_b64: String,
    /// The agent the quote is for; absent, a quote for the TD alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// `POST /attest` response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    /// Base64 raw TDX quote.
    pub quote_b64: String,
    /// Hex of the quote's 64 bytes of report data.
    pub report_data_hex: String,
    /// Base64 X25519 HPKE key to seal secrets to; valid until the gate restarts.
    pub provisioning_public_key_b64: String,
    /// The agent the quote is for; absent for the TD alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Base64 Ed25519 key the agent signs with, absent while it is unclaimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key_b64: Option<String>,
    /// Base64 X25519 key of the owner, absent while the agent is unclaimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_public_key_b64: Option<String>,
}

/// `POST /provision` and `POST /release` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRequest {
    /// The agent the message is for; also bound into the sealed message.
    pub agent_id: String,
    /// The provisioning key the message is sealed to, so a gate that restarted
    /// since `/attest` says so instead of failing to open it.
    pub provisioning_public_key_b64: String,
    /// Base64 X25519 key the message is sealed under (HPKE Auth mode): the
    /// owner's, or, for an unclaimed agent, the key that claims it.
    pub sender_public_key_b64: String,
    /// Base64 HPKE encapsulated key.
    pub encapped_key_b64: String,
    /// Base64 HPKE ciphertext of a JSON [`SecretsBundle`] (`/provision`) or
    /// [`ReleaseOrder`] (`/release`).
    pub ciphertext_b64: String,
}

/// `POST /provision` response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResponse {
    /// Names of the secrets written, sorted.
    pub written: Vec<String>,
    /// Whether this bundle claimed the agent for its sender.
    #[serde(default)]
    pub claimed: bool,
}

/// `POST /release` response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResponse {
    /// The agent whose slot was emptied: its claim, keys, secrets and state.
    pub released: String,
}

/// What an owner seals to release its agent: the agent stops, and its claim,
/// signing key, secrets and state are erased, freeing the slot for another.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseOrder {
    /// Must be true; a message that opens but asks for nothing is refused.
    pub release: bool,
}

/// What a provisioner seals: secret name to value. A value replaces the one
/// stored under its name; names not in the bundle are left alone.
#[derive(Serialize, Deserialize)]
pub struct SecretsBundle {
    pub secrets: BTreeMap<String, String>,
}

impl std::fmt::Debug for SecretsBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names only: values are the secrets.
        f.debug_struct("SecretsBundle")
            .field("names", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretsBundle {
    /// Every name a plain file name the agent can find, every value bounded.
    pub fn validate(&self) -> Result<(), String> {
        if self.secrets.is_empty() {
            return Err("the bundle holds no secrets".to_owned());
        }
        if self.secrets.len() > MAX_SECRETS {
            return Err(format!("at most {MAX_SECRETS} secrets per bundle"));
        }
        for (name, value) in &self.secrets {
            validate_secret_name(name)?;
            if value.len() > MAX_SECRET_LEN {
                return Err(format!("secret '{name}' is over {MAX_SECRET_LEN} bytes"));
            }
        }
        Ok(())
    }
}

/// A secret's name is its file name under the secrets directory, so it is one
/// path component that is neither hidden nor a temporary file of the gate's:
/// `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.
pub fn validate_secret_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let first_ok = bytes.first().is_some_and(|b| b.is_ascii_alphanumeric());
    let rest_ok = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !first_ok || !rest_ok || bytes.len() > 64 {
        return Err(format!(
            "secret name '{}' must match [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}",
            name.escape_debug()
        ));
    }
    Ok(())
}

/// HPKE `info`: the domain, the recipient key and the agent id.
fn info(recipient_public: &[u8; 32], agent_id: &str) -> Vec<u8> {
    let mut info = PROVISION_INFO_DOMAIN.to_vec();
    info.extend_from_slice(recipient_public);
    info.extend_from_slice(&agent_id_bytes(agent_id));
    info
}

/// An X25519 key pair from 32 secret bytes.
pub fn keypair_from_secret(secret: &[u8; 32]) -> Result<(PrivateKey, [u8; 32]), String> {
    let private = PrivateKey::from_bytes(secret).map_err(|e| format!("bad X25519 key: {e}"))?;
    let public = public_bytes(&Kem::sk_to_pk(&private));
    Ok((private, public))
}

pub fn public_bytes(public: &PublicKey) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&public.to_bytes());
    bytes
}

pub fn public_from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, String> {
    PublicKey::from_bytes(bytes).map_err(|e| format!("bad X25519 public key: {e}"))
}

/// Seal `message` (a [`SecretsBundle`] or a [`ReleaseOrder`]) for `agent_id`
/// to `recipient_public` in Auth mode as the holder of `sender_secret`.
///
/// Returns the encapsulated key and the ciphertext.
pub fn seal_message<T: Serialize>(
    recipient_public: &[u8; 32],
    agent_id: &str,
    sender_secret: &[u8; 32],
    message: &T,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let recipient = public_from_bytes(recipient_public)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(message).map_err(|e| format!("could not encode the message: {e}"))?,
    );
    let (private, public) = keypair_from_secret(sender_secret)?;
    let mode = OpModeS::Auth((private, public_from_bytes(&public)?));
    let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &mode,
        &recipient,
        &info(recipient_public, agent_id),
        &plaintext,
        &[],
        &mut os_rng(),
    )
    .map_err(|e| format!("HPKE seal failed: {e}"))?;
    Ok((encapped.to_bytes().to_vec(), ciphertext))
}

/// Why a message did not open.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("the message was not sealed by the key it names, for this agent")]
    NotFromSender,
}

/// Open a message for `agent_id` sealed to `recipient` in Auth mode by
/// `sender`. Whether that sender may act on this agent (it owns it, or it is
/// unclaimed) is the caller's decision; this only proves the sender sealed it,
/// for this agent.
pub fn open_message<T: DeserializeOwned>(
    recipient: &PrivateKey,
    recipient_public: &[u8; 32],
    agent_id: &str,
    sender: &[u8; 32],
    encapped_key: &[u8],
    ciphertext: &[u8],
) -> Result<T, OpenError> {
    let encapped = EncappedKey::from_bytes(encapped_key)
        .map_err(|e| OpenError::Malformed(format!("encapsulated key: {e}")))?;
    let sender_key = public_from_bytes(sender).map_err(OpenError::Malformed)?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Auth(sender_key),
            recipient,
            &encapped,
            &info(recipient_public, agent_id),
            ciphertext,
            &[],
        )
        .map_err(|_| OpenError::NotFromSender)?,
    );
    serde_json::from_slice(&plaintext)
        .map_err(|e| OpenError::Malformed(format!("the message is not the JSON expected: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(pairs: &[(&str, &str)]) -> SecretsBundle {
        SecretsBundle {
            secrets: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn the_binding_commits_to_the_agent_and_all_its_keys() {
        let a = key_binding(&[1; 32], "ana", Some(&[2; 32]), Some(&[4; 32]));
        assert_eq!(
            a,
            key_binding(&[1; 32], "ana", Some(&[2; 32]), Some(&[4; 32]))
        );
        assert_ne!(
            a,
            key_binding(&[3; 32], "ana", Some(&[2; 32]), Some(&[4; 32]))
        );
        assert_ne!(
            a,
            key_binding(&[1; 32], "bob", Some(&[2; 32]), Some(&[4; 32]))
        );
        assert_ne!(
            a,
            key_binding(&[1; 32], "ana", Some(&[3; 32]), Some(&[4; 32]))
        );
        assert_ne!(
            a,
            key_binding(&[1; 32], "ana", Some(&[2; 32]), Some(&[5; 32]))
        );
        // Swapping keys is a different binding, so none can pose as another.
        assert_ne!(
            a,
            key_binding(&[2; 32], "ana", Some(&[1; 32]), Some(&[4; 32]))
        );
        assert_ne!(
            a,
            key_binding(&[1; 32], "ana", Some(&[4; 32]), Some(&[2; 32]))
        );
    }

    /// The bytes are a format: the attestation verifier (api/verify.js)
    /// recomputes them, so they may never change by accident.
    #[test]
    fn the_binding_is_pinned() {
        assert_eq!(
            hex::encode(key_binding(&[1; 32], "ana", Some(&[2; 32]), Some(&[4; 32]))),
            "61c86ed9782e4b7f3d2a0d2146f66934ce5a2c99a79be440d8419c301dfeb1f5"
        );
        assert_eq!(
            hex::encode(key_binding(&[1; 32], "", None, None)),
            "315a41492f5b7820a5dd9d72c5223a4a5efd7d4c96f9991d23c9c8b54fb18f6f"
        );
    }

    #[test]
    fn an_unclaimed_agent_binds_no_signing_key_and_no_owner() {
        assert_eq!(
            key_binding(&[1; 32], "ana", None, None),
            key_binding(&[1; 32], "ana", Some(&[0; 32]), Some(&[0; 32]))
        );
        assert_ne!(
            key_binding(&[1; 32], "ana", None, None),
            key_binding(&[1; 32], "ana", Some(&[2; 32]), Some(&[4; 32]))
        );
    }

    #[test]
    fn agent_ids_are_short_lowercase_names() {
        for good in ["a", "agent-1", "0f3c", &"a".repeat(63)] {
            validate_agent_id(good).unwrap();
        }
        for bad in ["", "-a", "A", "a_b", "a/b", "a.b", "é", &"a".repeat(64)] {
            assert!(validate_agent_id(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn report_data_is_nonce_then_binding() {
        let data = report_data(&[7; 32], &[9; 32]);
        assert_eq!(&data[..32], &[7; 32]);
        assert_eq!(&data[32..], &[9; 32]);
    }

    fn open(
        gate: &PrivateKey,
        gate_public: &[u8; 32],
        agent: &str,
        sender: &[u8; 32],
        enc: &[u8],
        ct: &[u8],
    ) -> Result<SecretsBundle, OpenError> {
        open_message(gate, gate_public, agent, sender, enc, ct)
    }

    #[test]
    fn a_bundle_opens_under_the_key_that_sealed_it() {
        let (gate, gate_public) = keypair_from_secret(&[0x11; 32]).unwrap();
        let (_, sender) = keypair_from_secret(&[0x22; 32]).unwrap();
        let (enc, ct) = seal_message(
            &gate_public,
            "ana",
            &[0x22; 32],
            &bundle(&[("API_KEY", "s3cret")]),
        )
        .unwrap();
        let opened = open(&gate, &gate_public, "ana", &sender, &enc, &ct).unwrap();
        assert_eq!(opened.secrets["API_KEY"], "s3cret");
    }

    #[test]
    fn a_bundle_for_one_agent_does_not_open_for_another() {
        let (gate, gate_public) = keypair_from_secret(&[0x11; 32]).unwrap();
        let (_, sender) = keypair_from_secret(&[0x22; 32]).unwrap();
        let (enc, ct) =
            seal_message(&gate_public, "ana", &[0x22; 32], &bundle(&[("A", "b")])).unwrap();
        assert_eq!(
            open(&gate, &gate_public, "bob", &sender, &enc, &ct).unwrap_err(),
            OpenError::NotFromSender
        );
    }

    #[test]
    fn a_bundle_claimed_under_another_key_does_not_open() {
        // Someone seals with their own key but names the owner's: Auth mode
        // makes that fail, so nobody can provision in the owner's name.
        let (gate, gate_public) = keypair_from_secret(&[0x11; 32]).unwrap();
        let (_, owner) = keypair_from_secret(&[0x22; 32]).unwrap();
        let (enc, ct) =
            seal_message(&gate_public, "ana", &[0x33; 32], &bundle(&[("A", "b")])).unwrap();
        assert_eq!(
            open(&gate, &gate_public, "ana", &owner, &enc, &ct).unwrap_err(),
            OpenError::NotFromSender
        );
    }

    #[test]
    fn a_message_for_another_gate_does_not_open() {
        let (_, first_public) = keypair_from_secret(&[0x11; 32]).unwrap();
        let (second, second_public) = keypair_from_secret(&[0x12; 32]).unwrap();
        let (_, sender) = keypair_from_secret(&[0x22; 32]).unwrap();
        let (enc, ct) =
            seal_message(&first_public, "ana", &[0x22; 32], &bundle(&[("A", "b")])).unwrap();
        assert_eq!(
            open(&second, &second_public, "ana", &sender, &enc, &ct).unwrap_err(),
            OpenError::NotFromSender
        );
    }

    #[test]
    fn secret_names_are_single_plain_path_components() {
        for good in ["API_KEY", "model.token", "a", "x-1_2"] {
            validate_secret_name(good).unwrap();
        }
        for bad in [
            "",
            ".hidden",
            "../etc",
            "a/b",
            "-x",
            "_x",
            "é",
            &"a".repeat(65),
        ] {
            assert!(validate_secret_name(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn the_debug_form_of_a_bundle_has_no_values() {
        let shown = format!("{:?}", bundle(&[("API_KEY", "s3cret")]));
        assert!(shown.contains("API_KEY"));
        assert!(!shown.contains("s3cret"));
    }
}
