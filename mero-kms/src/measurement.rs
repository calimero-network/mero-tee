//! Validated hex measurement newtype for TDX register values.

use std::fmt;

use crate::util::{normalize_hex, HexNormalizeError, MEASUREMENT_BYTES};

/// A validated, normalized hex measurement value (lowercase, no `0x` prefix,
/// exactly [`MEASUREMENT_BYTES`] * 2 hex characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexMeasurement(String);

impl HexMeasurement {
    /// Parse and validate a raw hex string into a `HexMeasurement`.
    pub fn parse(raw: &str) -> Result<Self, HexNormalizeError> {
        normalize_hex(raw, MEASUREMENT_BYTES).map(Self)
    }

    /// Return the normalized hex string (lowercase, no `0x` prefix).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check whether the given raw measurement matches this value
    /// after normalization (case-insensitive, optional `0x` prefix).
    pub fn matches_raw(&self, raw: &str) -> bool {
        let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
        self.0 == normalized
    }
}

impl fmt::Display for HexMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for HexMeasurement {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for HexMeasurement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for HexMeasurement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_measurement() {
        let hex = "ab".repeat(MEASUREMENT_BYTES);
        let m = HexMeasurement::parse(&hex).unwrap();
        assert_eq!(m.as_str(), hex);
    }

    #[test]
    fn parse_strips_prefix_and_lowercases() {
        let upper = "AB".repeat(MEASUREMENT_BYTES);
        let with_prefix = format!("0x{upper}");
        let m = HexMeasurement::parse(&with_prefix).unwrap();
        assert_eq!(m.as_str(), "ab".repeat(MEASUREMENT_BYTES));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(HexMeasurement::parse("abcd").is_err());
    }

    #[test]
    fn matches_raw_is_case_insensitive() {
        let hex = "ab".repeat(MEASUREMENT_BYTES);
        let m = HexMeasurement::parse(&hex).unwrap();
        let upper = "AB".repeat(MEASUREMENT_BYTES);
        assert!(m.matches_raw(&upper));
        assert!(m.matches_raw(&format!("0x{upper}")));
    }
}
