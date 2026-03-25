//! Shared low-level helpers used across multiple modules.

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

pub const MEASUREMENT_BYTES: usize = 48;
pub const SHA256_HEX_LEN: usize = 64;
pub const CHALLENGE_ID_BYTES: usize = 16;
pub const CHALLENGE_ID_HEX_LEN: usize = CHALLENGE_ID_BYTES * 2;
pub const MAX_PEER_ID_LENGTH: usize = 128;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ClockError(String);

pub fn unix_now_secs() -> Result<u64, ClockError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ClockError(e.to_string()))
}

/// Normalize a hex string: trim, strip optional `0x` prefix, lowercase.
/// Validates length against `expected_bytes` and rejects non-hex characters.
pub fn normalize_hex(raw: &str, expected_bytes: usize) -> Result<String, HexNormalizeError> {
    let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    let expected_len = expected_bytes * 2;
    if normalized.len() != expected_len {
        return Err(HexNormalizeError::BadLength {
            expected_bytes,
            expected_hex: expected_len,
            actual_hex: normalized.len(),
        });
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(HexNormalizeError::NonHexCharacters);
    }
    Ok(normalized)
}

#[derive(Debug, Error)]
pub enum HexNormalizeError {
    #[error("expected {expected_bytes} bytes ({expected_hex} hex chars), got {actual_hex} chars")]
    BadLength {
        expected_bytes: usize,
        expected_hex: usize,
        actual_hex: usize,
    },
    #[error("value contains non-hex characters")]
    NonHexCharacters,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_secs_returns_reasonable_value() {
        let now = unix_now_secs().expect("clock should work");
        assert!(now > 1_700_000_000);
    }

    #[test]
    fn normalize_hex_strips_prefix_and_lowercases() {
        let result = normalize_hex("0xABCD", 2).unwrap();
        assert_eq!(result, "abcd");
    }

    #[test]
    fn normalize_hex_rejects_wrong_length() {
        let err = normalize_hex("abcd", 3).unwrap_err();
        assert!(matches!(err, HexNormalizeError::BadLength { .. }));
    }

    #[test]
    fn normalize_hex_rejects_non_hex() {
        let err = normalize_hex("zzzz", 2).unwrap_err();
        assert!(matches!(err, HexNormalizeError::NonHexCharacters));
    }
}
