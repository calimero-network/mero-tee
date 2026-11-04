//! Sealed key release: the key `/get-key` releases is encrypted to the node.
//!
//! Without this the key crossed the wire as plain hex inside TLS, and TLS ended
//! wherever the node's `kms-url` pointed. That URL comes from instance
//! metadata, which the node's operator writes, so an HTTPS proxy with any
//! public-CA certificate could sit in front of this service, forward every
//! request unchanged, and read every storage key it released. Every quote on
//! both sides was genuine; the transport was the hole.
//!
//! So the key is sealed end to end, TD to TD:
//!
//! * This service holds a long-lived X25519 **transport key**, derived from
//!   the cluster root ([`TRANSPORT_KEY_PATH`]) so every replica of one KMS
//!   cluster holds the same key. `/attest` returns its public half and commits to it in the quote
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

/// The root derivation path of the transport key. Never a peer key's path:
/// those are `{namespace}/{profile}/{peerId}` under a configured namespace.
pub(crate) const TRANSPORT_KEY_PATH: &str = "mero-kms/transport/x25519/v1";

const ATTEST_DOMAIN: &[u8] = b"mero-kms/attest-transport-key/v1";
const REQUEST_DOMAIN: &[u8] = b"mero-kms/sealed-get-key/v1";
const SEAL_DOMAIN: &[u8] = b"mero-kms/sealed-key/v1";

/// Version 2, for a release that carries the node's rollback counters
/// (`counters`): the quote names the node id, the answer is a JSON record.
const ATTEST_DOMAIN_V2: &[u8] = b"mero-kms/attest-transport-key/v2";
const REQUEST_DOMAIN_V2: &[u8] = b"mero-kms/sealed-get-key/v2";
const SEAL_DOMAIN_V2: &[u8] = b"mero-kms/sealed-key/v2";

/// What `/attest` reports it can do when asked (`capabilities: true`); the
/// v2 attest binding commits to the list, joined by commas.
pub(crate) const CAPABILITIES: &[&str] = &["rollback/v1"];

/// The transport keypair, from the 32 bytes the root derives at
/// [`TRANSPORT_KEY_PATH`].
pub(crate) struct TransportKey {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl TransportKey {
    pub(crate) fn from_secret(secret: &[u8; 32]) -> Self {
        let secret = Zeroizing::new(*secret);
        let public = MontgomeryPoint::mul_base_clamped(*secret).0;
        Self { secret, public }
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

/// [`attest_binding`] that also commits to [`CAPABILITIES`], so a relay cannot
/// strip them from the answer without the quote failing.
pub(crate) fn attest_binding_v2(binding: &[u8; 32], transport_public: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ATTEST_DOMAIN_V2);
    hasher.update(binding);
    hasher.update(transport_public);
    hasher.update(CAPABILITIES.join(",").as_bytes());
    hasher.finalize().into()
}

/// The 32 bytes a v2 request's quote carries after the challenge nonce: the
/// seal key, the peer id and the node id whose counters it asks for.
pub(crate) fn request_binding_v2(seal_to: &[u8; 32], peer_id: &str, node_id: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN_V2);
    hasher.update(seal_to);
    hasher.update(peer_id.as_bytes());
    hasher.update(node_id.to_be_bytes());
    hasher.finalize().into()
}

/// Seal a v2 release's record (`plaintext`, JSON) to `seal_to`.
pub(crate) fn seal_v2(
    transport: &TransportKey,
    seal_to: &[u8; 32],
    challenge_nonce: &[u8; 32],
    peer_id: &str,
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), ServiceError> {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let ciphertext = seal_bytes(
        SEAL_DOMAIN_V2,
        transport,
        seal_to,
        challenge_nonce,
        peer_id,
        nonce,
        plaintext,
    )?;
    Ok((nonce, ciphertext))
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
    seal_bytes(
        SEAL_DOMAIN,
        transport,
        seal_to,
        challenge_nonce,
        peer_id,
        nonce,
        key_hex.as_bytes(),
    )
}

/// X25519 to `seal_to`, HKDF-SHA256 (salt: the challenge nonce; info: `domain`,
/// the transport key, `seal_to`, the peer id), AES-256-GCM with the peer id as
/// associated data. v1 and v2 differ only in `domain` and in what they seal.
fn seal_bytes(
    domain: &[u8],
    transport: &TransportKey,
    seal_to: &[u8; 32],
    challenge_nonce: &[u8; 32],
    peer_id: &str,
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, ServiceError> {
    let shared = Zeroizing::new(MontgomeryPoint(*seal_to).mul_clamped(*transport.secret).0);
    // A low-order point gives an all-zero secret anybody can compute.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(ServiceError::InvalidAttestationRequest(
            "sealToB64 is a low-order point".to_owned(),
        ));
    }
    let info: [&[u8]; 4] = [domain, &transport.public, seal_to, peer_id.as_bytes()];
    let prk = Salt::new(HKDF_SHA256, challenge_nonce).extract(shared.as_ref());
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| ServiceError::KeyDerivationFailed("HKDF expansion failed".to_owned()))?;
    let key = LessSafeKey::new(UnboundKey::from(okm));
    // Zeroizing: if sealing fails, the buffer still holds the plaintext key.
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(peer_id.as_bytes()),
        &mut *buffer,
    )
    .map_err(|_| ServiceError::KeyDerivationFailed("sealing the key failed".to_owned()))?;
    Ok(std::mem::take(&mut *buffer))
}

/// What merod does with a v2 release: open the record sealed to `node_secret`.
#[cfg(test)]
pub(crate) fn open_v2(
    node_secret: &[u8; 32],
    transport_public: &[u8; 32],
    challenge_nonce: &[u8; 32],
    peer_id: &str,
    seal_nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ServiceError> {
    let node_public = MontgomeryPoint::mul_base_clamped(*node_secret).0;
    let shared = MontgomeryPoint(*transport_public)
        .mul_clamped(*node_secret)
        .0;
    let info: [&[u8]; 4] = [
        SEAL_DOMAIN_V2,
        transport_public,
        &node_public,
        peer_id.as_bytes(),
    ];
    let prk = Salt::new(HKDF_SHA256, challenge_nonce).extract(&shared);
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| ServiceError::KeyDerivationFailed("HKDF".to_owned()))?;
    let key = LessSafeKey::new(UnboundKey::from(okm));
    let mut buffer = ciphertext.to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(*seal_nonce),
            Aad::from(peer_id.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| ServiceError::KeyDerivationFailed("does not open".to_owned()))?;
    Ok(plain.to_vec())
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
        let transport = TransportKey::from_secret(&KMS_SECRET);
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

    /// The v2 wire format, repeated verbatim in merod's `kms::sealed` tests.
    #[test]
    fn the_v2_wire_format_matches_the_published_vectors() {
        let transport = TransportKey::from_secret(&KMS_SECRET);
        let node_public = MontgomeryPoint::mul_base_clamped(NODE_SECRET).0;
        assert_eq!(
            hex::encode(attest_binding_v2(&[0x77; 32], transport.public())),
            ATTEST_BINDING_V2_VECTOR
        );
        assert_eq!(
            hex::encode(request_binding_v2(&node_public, PEER, 3)),
            REQUEST_BINDING_V2_VECTOR
        );
        let sealed = seal_bytes(
            SEAL_DOMAIN_V2,
            &transport,
            &node_public,
            &NONCE,
            PEER,
            SEAL_NONCE,
            RECORD_V2.as_bytes(),
        )
        .unwrap();
        assert_eq!(hex::encode(&sealed), SEALED_RECORD_V2_VECTOR);
        let opened = open_v2(
            &NODE_SECRET,
            transport.public(),
            &NONCE,
            PEER,
            &SEAL_NONCE,
            &sealed,
        )
        .unwrap();
        assert_eq!(opened, RECORD_V2.as_bytes());
        assert_ne!(
            attest_binding_v2(&[0x77; 32], transport.public()),
            attest_binding(&[0x77; 32], transport.public())
        );
    }

    #[test]
    fn a_v2_record_does_not_open_as_v1() {
        let transport = TransportKey::from_secret(&KMS_SECRET);
        let node_public = MontgomeryPoint::mul_base_clamped(NODE_SECRET).0;
        let v1 =
            seal_with_nonce(&transport, &node_public, &NONCE, PEER, SEAL_NONCE, KEY_HEX).unwrap();
        assert!(open_v2(
            &NODE_SECRET,
            transport.public(),
            &NONCE,
            PEER,
            &SEAL_NONCE,
            &v1
        )
        .is_err());
    }

    #[test]
    fn a_low_order_seal_key_is_refused() {
        let transport = TransportKey::from_secret(&KMS_SECRET);
        assert!(seal(&transport, &[0; 32], &NONCE, PEER, KEY_HEX).is_err());
    }

    const RECORD_V2: &str = r#"{"keyHex":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","epoch":1,"generation":1,"mark":42,"sessionIdB64":"VVVVVVVVVVVVVVVVVVVVVQ==","sessionKeyHex":"6666666666666666666666666666666666666666666666666666666666666666"}"#;
    // Reproduced with Python's `cryptography` (X25519, HKDF, AESGCM).
    const ATTEST_BINDING_V2_VECTOR: &str =
        "e9f2764915d498666e849eda69ad2c777c72c96e159299a9c63af03f9e267927";
    const REQUEST_BINDING_V2_VECTOR: &str =
        "9bd31a7facb1d0bbba66d7ae2666da4c2ab890fec25f2a72f898210a6d9e817b";
    const SEALED_RECORD_V2_VECTOR: &str =
        "38acc754447ef35f7e3431a32e7ac8e7217ef54b502c439df6e30cae28b4dcf1\
        c230cdd1c6f0dea421897ed196bf420a17209551fadabc39fb3eb89a94d279ef\
        f1e039003090b29538fbe6aa12465bf53a0e72a3ae7e69b67bfd73b976e68959\
        d71cfbe14c2809e393d5571bd2231b2ad3e34ab9f1c5797b4108ddf7669f501a\
        a7bfe509131090684b55c3a7ce60577491957333cf4bf8e8811c501b4969137f\
        88d50f88c98c13fd8d72911e94f8aa5f82852e42069b61baf5429d8b3b4fc009\
        e207e8b45bc0be76919d5d5263800972249ef38779de66d5ab34ee413bcd04c8\
        e7a9ea2c4b47a48013ee19f1090317bf1502de8d9bc0e33d84aae53696";

    // Also reproduced independently with Python's `cryptography` (X25519, HKDF,
    // AESGCM), so the format is standard and not merely self-consistent.
    const ATTEST_BINDING_VECTOR: &str =
        "9554b7960a1e1e3493ba075885680dc2c8c17f3c0caf7c5fc97a80400703acf7";
    const REQUEST_BINDING_VECTOR: &str =
        "9ef1ee8c46f5fa7b8ed4bcec0255cd88ec847674a6c6aca13eb5076c85af9f17";
    const SEALED_KEY_VECTOR: &str = "ebb35e8aa078b188ac8118d8a5c57f63ebe9431c41d887a1df61425b18d8f6b1\
        7287f6c7e3d81ea1af1ce06ce3cdc9ccce726b637498bf43c290a1dce1d9231a201a46995aa2dcc60f1224f553c29730";
}
