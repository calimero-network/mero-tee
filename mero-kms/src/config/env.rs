//! Environment variable parsing helpers.

use eyre::{bail, Result as EyreResult};

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
/// Each entry must be a valid [`crate::measurement::HexMeasurement`] (48-byte / 96-hex-char TDX register value).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_flag_accepts_all_truthy_values() {
        for input in ["1", "true", "TRUE", "yes", "on", " True "] {
            assert!(
                parse_bool_flag(input).unwrap(),
                "expected true for {input:?}"
            );
        }
    }

    #[test]
    fn parse_bool_flag_accepts_all_falsy_values() {
        for input in ["0", "false", "FALSE", "no", "off", " False "] {
            assert!(
                !parse_bool_flag(input).unwrap(),
                "expected false for {input:?}"
            );
        }
    }

    #[test]
    fn parse_bool_flag_rejects_unknown() {
        assert!(parse_bool_flag("maybe").is_err());
    }
}
