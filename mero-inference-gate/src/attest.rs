//! What a quote commits to, and the `/attest` answer.
//!
//! `report_data = nonce ‖ SHA-256(ATTEST_DOMAIN ‖ spki_sha256 ‖ config_digest
//! ‖ SHA-256(gpu_json))`, where `gpu_json` is NVIDIA's evidence for the same
//! nonce, or empty on a TD with no GPU (which clients refuse). The answer
//! carries the exact bytes hashed, so a verifier hashes them as received and
//! never re-serializes.
//!
//! RTMR3 holds the image event every role extends (`calimero-rtmr3-v3`) and
//! then [`config_event`]: inference-init extends it with the configuration the
//! TD loaded, so the quote names the model as well as the image.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

/// Domain of the report-data binding.
pub const ATTEST_DOMAIN: &[u8] = b"mero-inference-gate/attest/v1";

/// What inference-init extends RTMR3 with: `SHA-384(prefix ‖ hex(config_digest))`.
pub const CONFIG_EVENT_PREFIX: &str = "calimero-inference-config-v1:";

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The binding in the second half of `report_data`.
pub fn binding(
    spki_sha256: &[u8; 32],
    config_digest: &[u8; 32],
    gpu_json: Option<&str>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ATTEST_DOMAIN);
    hasher.update(spki_sha256);
    hasher.update(config_digest);
    hasher.update(sha256(gpu_json.unwrap_or("").as_bytes()));
    hasher.finalize().into()
}

/// `nonce ‖ binding`, as the quote carries it.
pub fn report_data(nonce: &[u8; 32], binding: &[u8; 32]) -> [u8; 64] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(nonce);
    data[32..].copy_from_slice(binding);
    data
}

/// The RTMR3 extend for a configuration digest.
pub fn config_event(config_digest: &[u8; 32]) -> [u8; 48] {
    Sha384::digest(format!("{CONFIG_EVENT_PREFIX}{}", hex::encode(config_digest)).as_bytes()).into()
}

/// RTMR3 after `base` (the image event alone, as the release measures it) is
/// extended with [`config_event`]: what a client expects in the quote.
pub fn expected_rtmr3(base: &[u8; 48], config_digest: &[u8; 32]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(base);
    hasher.update(config_event(config_digest));
    hasher.finalize().into()
}

/// `POST /attest` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestRequest {
    /// The 32-byte nonce the client chose, hex.
    pub nonce_hex: String,
}

/// `POST /attest` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    pub quote_b64: String,
    pub report_data_hex: String,
    /// Hex SHA-256 of the gate's certificate's SubjectPublicKeyInfo (DER).
    pub tls_spki_sha256: String,
    /// The configuration the TD loaded, exactly the bytes hashed; empty on the
    /// release's measurement VM, which loads none.
    pub config_json: String,
    /// Hex SHA-256 of `config_json`.
    pub config_digest: String,
    /// NVIDIA's evidence for this nonce, exactly the bytes hashed; `None`
    /// only on a TD with no GPU.
    pub gpu_json: Option<String>,
}

/// A request's nonce: exactly 32 bytes of hex.
pub fn parse_nonce(nonce_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(nonce_hex.trim()).map_err(|_| "nonceHex is not hex".to_owned())?;
    <[u8; 32]>::try_from(bytes).map_err(|_| "nonceHex is not 32 bytes".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_is_nonce_then_binding() {
        let data = report_data(&[7; 32], &[9; 32]);
        assert_eq!(&data[..32], &[7; 32]);
        assert_eq!(&data[32..], &[9; 32]);
    }

    #[test]
    fn binding_covers_every_input() {
        let base = binding(&[1; 32], &[2; 32], Some("{}"));
        assert_ne!(base, binding(&[3; 32], &[2; 32], Some("{}")));
        assert_ne!(base, binding(&[1; 32], &[3; 32], Some("{}")));
        assert_ne!(base, binding(&[1; 32], &[2; 32], Some("{ }")));
        // No GPU hashes the empty string, as the doc says.
        assert_eq!(
            binding(&[1; 32], &[2; 32], None),
            binding(&[1; 32], &[2; 32], Some(""))
        );
    }

    // Fixed vectors, so the gate, inference-init (openssl) and mero-bot agree.
    #[test]
    fn binding_vector() {
        assert_eq!(
            hex::encode(binding(&[0x11; 32], &[0x22; 32], Some(r#"{"nonce":"00"}"#))),
            {
                let mut input = ATTEST_DOMAIN.to_vec();
                input.extend([0x11; 32]);
                input.extend([0x22; 32]);
                input.extend(sha256(br#"{"nonce":"00"}"#));
                hex::encode(sha256(&input))
            }
        );
    }

    #[test]
    fn rtmr3_replays_the_config_event() {
        let digest = sha256(b"{}");
        let event = config_event(&digest);
        let expected_event: [u8; 48] = Sha384::digest(format!(
            "calimero-inference-config-v1:{}",
            hex::encode(digest)
        ))
        .into();
        assert_eq!(event, expected_event);
        let mut input = vec![0u8; 48];
        input.extend(event);
        assert_eq!(
            expected_rtmr3(&[0; 48], &digest).to_vec(),
            Sha384::digest(&input).to_vec()
        );
    }

    // The vector mero-bot's tests pin too (src/mero.test.ts): a zero base and
    // the digest of "{}".
    #[test]
    fn rtmr3_vector_shared_with_mero_bot() {
        assert_eq!(
            hex::encode(expected_rtmr3(&[0; 48], &sha256(b"{}"))),
            "0d222b77db5c70344754231bc37632a41e90112da838264faf36a552ab308773414bb60ad44f8897fa9ddff1ca945212"
        );
    }

    #[test]
    fn nonce_must_be_32_bytes_of_hex() {
        assert!(parse_nonce(&"ab".repeat(32)).is_ok());
        assert!(parse_nonce(&"ab".repeat(31)).is_err());
        assert!(parse_nonce("zz").is_err());
    }
}
