//! Sealed key release: the key `/get-key` releases is encrypted to the node.
//!
//! Without this the key crossed the wire as plain hex inside TLS, and TLS ended
//! wherever the node's `kms-phala-url` pointed. That URL comes from instance
//! metadata, which the node's operator writes, so an HTTPS proxy with any
//! public-CA certificate could sit in front of this service, forward every
//! request unchanged, and read every storage key it released. Every quote on
//! both sides was genuine; the transport was the hole.
//!
//! So the key is sealed end to end, TD to TD:
//!
//! * This service holds a long-lived X25519 **transport key**, derived from
//!   dstack ([`TRANSPORT_KEY_PATH`]) so every replica of one KMS app holds the
//!   same key. `/attest` returns its public half and commits to it in the quote
//!   ([`attest_binding`]), so a node knows the key belongs to a genuine KMS.
//! * A node names a one-time X25519 key in `sealToB64` and commits to it in ITS
//!   quote ([`request_binding`]), so nobody in the middle can swap it.
//! * The released key is sealed to that key ([`seal`]). Only the node can open
//!   it, and it authenticates only under the transport key the node attested, so
//!   a proxy can neither read the key nor substitute one of its own.
//!
//! The wire format is merod's `kms::sealed` module, byte for byte; the vectors in
//! the tests below are repeated verbatim there.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::handlers::errors::ServiceError;

/// The dstack derivation path of the transport key. Never a peer key's path:
/// those are `{namespace}/{profile}/{peerId}` under a configured namespace.
pub(crate) const TRANSPORT_KEY_PATH: &str = "mero-kms/transport/x25519/v1";

const ATTEST_DOMAIN: &[u8] = b"mero-kms/attest-transport-key/v1";
const REQUEST_DOMAIN: &[u8] = b"mero-kms/sealed-get-key/v1";
const SEAL_DOMAIN: &[u8] = b"mero-kms/sealed-key/v1";

/// The transport keypair, from the 32+ bytes dstack derives at
/// [`TRANSPORT_KEY_PATH`].
pub(crate) struct TransportKey {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl TransportKey {
    pub(crate) fn from_derived_bytes(derived: &[u8]) -> Result<Self, ServiceError> {
        let Some(bytes) = derived.get(..32) else {
            return Err(ServiceError::KeyDerivationFailed(
                "dstack returned fewer than 32 bytes for the transport key".to_owned(),
            ));
        };
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(bytes);
        let public = MontgomeryPoint::mul_base_clamped(*secret).0;
        Ok(Self { secret, public })
    }

    pub(crate) fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// The 32 bytes `/attest` puts after the nonce when it reports a transport key.
pub(crate) fn attest_binding(binding: &[u8; 32], transport_public: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ATTEST_DOMAIN);
    hasher.update(binding);
    hasher.update(transport_public);
    hasher.finalize().into()
}

/// The 32 bytes a sealed request's quote carries after the challenge nonce.
pub(crate) fn request_binding(seal_to: &[u8; 32], peer_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(seal_to);
    hasher.update(peer_id.as_bytes());
    hasher.finalize().into()
}

/// Seal `key_hex` to `seal_to`. Returns the 12-byte nonce and the ciphertext.
pub(crate) fn seal(
    transport: &TransportKey,
    seal_to: &[u8; 32],
    challenge_nonce: &[u8; 32],
    peer_id: &str,
    key_hex: &str,
) -> Result<([u8; NONCE_LEN], Vec<u8>), ServiceError> {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let ciphertext = seal_with_nonce(transport, seal_to, challenge_nonce, peer_id, nonce, key_hex)?;
    Ok((nonce, ciphertext))
}

fn seal_with_nonce(
    transport: &TransportKey,
    seal_to: &[u8; 32],
    challenge_nonce: &[u8; 32],
    peer_id: &str,
    nonce: [u8; NONCE_LEN],
    key_hex: &str,
) -> Result<Vec<u8>, ServiceError> {
    let shared = Zeroizing::new(MontgomeryPoint(*seal_to).mul_clamped(*transport.secret).0);
    // A low-order point gives an all-zero secret anybody can compute.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(ServiceError::InvalidAttestationRequest(
            "sealToB64 is a low-order point".to_owned(),
        ));
    }
    let info: [&[u8]; 4] = [SEAL_DOMAIN, &transport.public, seal_to, peer_id.as_bytes()];
    let prk = Salt::new(HKDF_SHA256, challenge_nonce).extract(shared.as_ref());
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| ServiceError::KeyDerivationFailed("HKDF expansion failed".to_owned()))?;
    let key = LessSafeKey::new(UnboundKey::from(okm));
    let mut buffer = key_hex.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(peer_id.as_bytes()),
        &mut buffer,
    )
    .map_err(|_| ServiceError::KeyDerivationFailed("sealing the key failed".to_owned()))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWPeer";
    const NONCE: [u8; 32] = [0x11; 32];
    const KMS_SECRET: [u8; 32] = [0x22; 32];
    const NODE_SECRET: [u8; 32] = [0x33; 32];
    const SEAL_NONCE: [u8; NONCE_LEN] = [0x44; NONCE_LEN];
    const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// Fixed vectors, repeated verbatim in merod's `kms::sealed` tests: the two
    /// sides are separate implementations of one wire format, and these are
    /// what keep them the same format.
    #[test]
    fn the_wire_format_matches_the_published_vectors() {
        let transport = TransportKey::from_derived_bytes(&KMS_SECRET).unwrap();
        let node_public = MontgomeryPoint::mul_base_clamped(NODE_SECRET).0;
        assert_eq!(
            hex::encode(attest_binding(&[0x77; 32], transport.public())),
            ATTEST_BINDING_VECTOR
        );
        assert_eq!(
            hex::encode(request_binding(&node_public, PEER)),
            REQUEST_BINDING_VECTOR
        );
        let sealed =
            seal_with_nonce(&transport, &node_public, &NONCE, PEER, SEAL_NONCE, KEY_HEX).unwrap();
        assert_eq!(hex::encode(sealed), SEALED_KEY_VECTOR);
    }

    #[test]
    fn a_low_order_seal_key_is_refused() {
        let transport = TransportKey::from_derived_bytes(&KMS_SECRET).unwrap();
        assert!(seal(&transport, &[0; 32], &NONCE, PEER, KEY_HEX).is_err());
    }

    #[test]
    fn a_short_derivation_is_refused() {
        assert!(TransportKey::from_derived_bytes(&[0; 31]).is_err());
    }

    // Also reproduced independently with Python's `cryptography` (X25519, HKDF,
    // AESGCM), so the format is standard and not merely self-consistent.
    const ATTEST_BINDING_VECTOR: &str =
        "9554b7960a1e1e3493ba075885680dc2c8c17f3c0caf7c5fc97a80400703acf7";
    const REQUEST_BINDING_VECTOR: &str =
        "9ef1ee8c46f5fa7b8ed4bcec0255cd88ec847674a6c6aca13eb5076c85af9f17";
    const SEALED_KEY_VECTOR: &str = "ebb35e8aa078b188ac8118d8a5c57f63ebe9431c41d887a1df61425b18d8f6b1\
        7287f6c7e3d81ea1af1ce06ce3cdc9ccce726b637498bf43c290a1dce1d9231a201a46995aa2dcc60f1224f553c29730";
}
