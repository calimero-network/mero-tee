//! Environment variable parsing helpers.

use eyre::{bail, Result as EyreResult};

use crate::util::SHA256_HEX_LEN;

fn parse_bool_flag(raw: &str) -> EyreResult<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("Invalid boolean value '{}'", other),
    }
}

/// Read a boolean from the environment variable `name`, returning `default`
/// when the variable is not set. Accepts `1/true/yes/on` and `0/false/no/off`.
pub fn parse_bool_env(name: &str, default: bool) -> EyreResult<bool> {
    match std::env::var(name) {
        Ok(value) => parse_bool_flag(&value),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

/// Parse a comma-separated env var, optionally lowercasing entries.
pub fn parse_csv_env(name: &str, lowercase: bool) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|v| {
        v.split(',')
            .map(|s| {
                let trimmed = s.trim();
                if lowercase {
                    trimmed.to_ascii_lowercase()
                } else {
                    trimmed.to_string()
                }
            })
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Validate and normalize a SHA-256 hex pin (exactly 64 hex chars, lowercase, no `0x`).
pub fn normalize_hash_pin(raw: &str) -> EyreResult<String> {
    let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    if normalized.len() != SHA256_HEX_LEN {
        bail!(
            "MERO_KMS_POLICY_SHA256 must contain exactly {} hex chars (got {})",
            SHA256_HEX_LEN,
            normalized.len()
        );
    }
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("MERO_KMS_POLICY_SHA256 contains non-hex characters");
    }
    Ok(normalized)
}

/// Compute the SHA-256 hash of `bytes` and return it as a lowercase hex string.
pub fn hash_bytes_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Read an environment variable as a UTF-8 string, returning `None` when not
/// set and an error when the value is not valid UTF-8.
pub fn read_env_utf8(name: &str) -> EyreResult<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

/// Parse a comma-separated env var into validated hex measurement values.
/// Each entry must be a valid [`HexMeasurement`] (48-byte / 96-hex-char TDX register value).
pub fn parse_measurement_list_env(
    name: &str,
) -> EyreResult<Vec<crate::measurement::HexMeasurement>> {
    match std::env::var(name) {
        Ok(raw) => raw
            .split(',')
            .filter_map(|entry| {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .map(|value| {
                crate::measurement::HexMeasurement::parse(&value).map_err(|e| eyre::eyre!("{e}"))
            })
            .collect(),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}
