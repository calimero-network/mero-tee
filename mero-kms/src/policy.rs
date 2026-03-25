//! Policy model, JSON parsing, and startup validation helpers.

use eyre::{bail, Result as EyreResult};

use crate::measurement::HexMeasurement;

/// Attestation verification policy for key release.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// Whether measurement checks are enforced.
    pub enforce_measurement_policy: bool,
    /// Allowed TCB statuses (normalized to lowercase).
    pub allowed_tcb_statuses: Vec<String>,
    /// Allowed MRTD values.
    pub allowed_mrtd: Vec<HexMeasurement>,
    /// Allowed RTMR0 values.
    pub allowed_rtmr0: Vec<HexMeasurement>,
    /// Allowed RTMR1 values.
    pub allowed_rtmr1: Vec<HexMeasurement>,
    /// Allowed RTMR2 values.
    pub allowed_rtmr2: Vec<HexMeasurement>,
    /// Allowed RTMR3 values.
    pub allowed_rtmr3: Vec<HexMeasurement>,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_owned()],
            allowed_mrtd: Vec::new(),
            allowed_rtmr0: Vec::new(),
            allowed_rtmr1: Vec::new(),
            allowed_rtmr2: Vec::new(),
            allowed_rtmr3: Vec::new(),
        }
    }
}

impl AttestationPolicy {
    /// Return the five TDX measurement register allowlists as `(label, allowlist)` pairs.
    ///
    /// This centralizes the MRTD + RTMR0–3 iteration order so callers don't
    /// repeat the same five-element array construction.
    pub fn register_fields(&self) -> [(&'static str, &[HexMeasurement]); 5] {
        [
            ("MRTD", &self.allowed_mrtd),
            ("RTMR0", &self.allowed_rtmr0),
            ("RTMR1", &self.allowed_rtmr1),
            ("RTMR2", &self.allowed_rtmr2),
            ("RTMR3", &self.allowed_rtmr3),
        ]
    }

    /// Check a raw measurement value against the allowlist for a named register.
    /// Returns `Ok(())` if it matches any entry, `Err(label, normalized)` otherwise.
    pub fn check_measurement(
        allowlist: &[HexMeasurement],
        label: &str,
        raw_value: &str,
    ) -> Result<(), (String, String)> {
        if allowlist.is_empty() {
            return Err((label.to_string(), format!("{} allowlist is empty", label)));
        }
        if allowlist.iter().any(|m| m.matches_raw(raw_value)) {
            return Ok(());
        }
        let normalized = raw_value
            .trim()
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        Err((
            label.to_string(),
            format!("{} '{}' is not in allowlist", label, normalized),
        ))
    }

    /// Parse a policy JSON document, validating the `tag`, `role`, and `profile`
    /// envelope fields before extracting measurement allowlists.
    ///
    /// `allow_legacy_missing_profile` supports older policy files that omit the
    /// `role` and `profile` fields — only accepted for `locked-read-only` to
    /// maintain backward compatibility with pre-profile releases.
    pub fn from_json(
        json_str: &str,
        expected_tag: &str,
        expected_profile: &str,
        allow_legacy_missing_profile: bool,
    ) -> EyreResult<Self> {
        let root: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| eyre::eyre!("Invalid policy JSON: {}", e))?;
        let tag = root
            .get("tag")
            .and_then(|value| value.as_str())
            .ok_or_else(|| eyre::eyre!("Policy JSON missing 'tag' string"))?;
        if tag != expected_tag {
            bail!(
                "Policy tag mismatch: expected '{}', got '{}'",
                expected_tag,
                tag
            );
        }
        match root.get("role").and_then(|value| value.as_str()) {
            Some("kms") => {}
            Some(role) => bail!("Policy role mismatch: expected 'kms', got '{}'", role),
            None if allow_legacy_missing_profile && expected_profile == "locked-read-only" => {}
            None => bail!("Policy JSON missing 'role' for KMS policy"),
        }
        match root.get("profile").and_then(|value| value.as_str()) {
            Some(profile) => {
                let normalized = super::config::parse_profile(profile)?;
                if normalized != expected_profile {
                    bail!(
                        "Policy profile mismatch: expected '{}', got '{}'",
                        expected_profile,
                        normalized
                    );
                }
            }
            None if allow_legacy_missing_profile && expected_profile == "locked-read-only" => {}
            None => bail!(
                "Policy JSON missing 'profile' for requested profile '{}'",
                expected_profile
            ),
        }

        let policy = root
            .get("policy")
            .and_then(|v| v.as_object())
            .ok_or_else(|| eyre::eyre!("Policy JSON missing 'policy' object"))?;

        let allowed_tcb_statuses = parse_json_string_array(policy, "node_allowed_tcb_statuses")
            .or_else(|| parse_json_string_array(policy, "allowed_tcb_statuses"))
            .unwrap_or_else(|| vec!["uptodate".to_owned()]);
        let allowed_mrtd = parse_policy_hex_allowlist(policy, "node_allowed_mrtd", "allowed_mrtd")?;
        let allowed_rtmr0 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr0", "allowed_rtmr0")?;
        let allowed_rtmr1 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr1", "allowed_rtmr1")?;
        let allowed_rtmr2 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr2", "allowed_rtmr2")?;
        let allowed_rtmr3 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr3", "allowed_rtmr3")?;

        Ok(AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses,
            allowed_mrtd,
            allowed_rtmr0,
            allowed_rtmr1,
            allowed_rtmr2,
            allowed_rtmr3,
        })
    }
}

/// Fail-fast check at startup: when enforcement is on, every measurement
/// register must have at least one allowed value. This catches misconfiguration
/// before the first key-release request arrives.
pub fn validate_policy_requirements(
    policy: &AttestationPolicy,
    accept_mock_attestation: bool,
) -> EyreResult<()> {
    if !policy.enforce_measurement_policy || accept_mock_attestation {
        return Ok(());
    }
    if policy.allowed_tcb_statuses.is_empty() {
        bail!(
            "Measurement policy is enforced, but allowed_tcb_statuses is empty. \
             Configure at least one allowed status (recommended: UpToDate)."
        );
    }

    for (label, allowlist) in policy.register_fields() {
        if allowlist.is_empty() {
            let guidance = if label == "MRTD" {
                "Provide policy via MERO_KMS_VERSION + MERO_KMS_PROFILE, or use USE_ENV_POLICY=true for explicit air-gapped mode."
            } else {
                "Configure at least one trusted value."
            };
            bail!(
                "Measurement policy is enforced, but allowed_{} is empty. {}",
                label.to_ascii_lowercase(),
                guidance
            );
        }
    }
    Ok(())
}

fn parse_json_string_array(
    policy: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    policy.get(key).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|value| value.as_str())
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    })
}

fn parse_json_hex_array(
    policy: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> EyreResult<Option<Vec<HexMeasurement>>> {
    let Some(values) = policy.get(key) else {
        return Ok(None);
    };
    let arr = values
        .as_array()
        .ok_or_else(|| eyre::eyre!("Policy field '{}' must be an array", key))?;
    let mut parsed = Vec::new();
    for value in arr {
        let raw = value
            .as_str()
            .ok_or_else(|| eyre::eyre!("Policy field '{}' entries must be strings", key))?;
        parsed
            .push(HexMeasurement::parse(raw).map_err(|e| {
                eyre::eyre!("Invalid measurement in policy field '{}': {}", key, e)
            })?);
    }
    Ok(Some(parsed))
}

/// Try `preferred_key` first (e.g. `node_allowed_mrtd`), fall back to
/// `fallback_key` (e.g. `allowed_mrtd`) for backward-compatible policy files.
fn parse_policy_hex_allowlist(
    policy: &serde_json::Map<String, serde_json::Value>,
    preferred_key: &str,
    fallback_key: &str,
) -> EyreResult<Vec<HexMeasurement>> {
    if let Some(values) = parse_json_hex_array(policy, preferred_key)? {
        return Ok(values);
    }
    Ok(parse_json_hex_array(policy, fallback_key)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MEASUREMENT_BYTES;

    fn strict_policy() -> AttestationPolicy {
        let measurement = HexMeasurement::parse(&"ab".repeat(MEASUREMENT_BYTES)).unwrap();
        AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_string()],
            allowed_mrtd: vec![measurement.clone()],
            allowed_rtmr0: vec![measurement.clone()],
            allowed_rtmr1: vec![measurement.clone()],
            allowed_rtmr2: vec![measurement.clone()],
            allowed_rtmr3: vec![measurement],
        }
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_rtmr3() {
        let mut policy = strict_policy();
        policy.allowed_rtmr3.clear();
        let err =
            validate_policy_requirements(&policy, false).expect_err("missing RTMR3 should fail");
        assert!(err.to_string().contains("allowed_rtmr3"));
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_tcb_statuses() {
        let mut policy = strict_policy();
        policy.allowed_tcb_statuses.clear();
        let err = validate_policy_requirements(&policy, false)
            .expect_err("missing TCB status allowlist should fail");
        assert!(err.to_string().contains("allowed_tcb_statuses"));
    }

    #[test]
    fn validate_policy_requirements_allows_when_mock_enabled() {
        let policy = AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: Vec::new(),
            allowed_mrtd: Vec::new(),
            allowed_rtmr0: Vec::new(),
            allowed_rtmr1: Vec::new(),
            allowed_rtmr2: Vec::new(),
            allowed_rtmr3: Vec::new(),
        };
        assert!(validate_policy_requirements(&policy, true).is_ok());
    }

    #[test]
    fn from_json_rejects_mismatched_profile() {
        let policy_json = serde_json::json!({
            "tag": "2.1.38",
            "role": "kms",
            "profile": "debug",
            "policy": {
                "node_allowed_tcb_statuses": ["uptodate"],
                "node_allowed_mrtd": ["ab".repeat(48)],
                "node_allowed_rtmr0": ["cd".repeat(48)],
                "node_allowed_rtmr1": ["ef".repeat(48)],
                "node_allowed_rtmr2": ["01".repeat(48)],
                "node_allowed_rtmr3": ["23".repeat(48)]
            }
        });
        let err = AttestationPolicy::from_json(
            &policy_json.to_string(),
            "2.1.38",
            "locked-read-only",
            false,
        )
        .expect_err("mismatched profile should fail");
        assert!(err.to_string().contains("Policy profile mismatch"));
    }

    #[test]
    fn from_json_rejects_non_kms_role() {
        let policy_json = serde_json::json!({
            "tag": "2.1.38",
            "role": "node",
            "profile": "locked-read-only",
            "policy": {
                "node_allowed_tcb_statuses": ["uptodate"],
                "node_allowed_mrtd": ["aa".repeat(48)],
                "node_allowed_rtmr0": ["bb".repeat(48)],
                "node_allowed_rtmr1": ["cc".repeat(48)],
                "node_allowed_rtmr2": ["dd".repeat(48)],
                "node_allowed_rtmr3": ["ee".repeat(48)]
            }
        });
        let err = AttestationPolicy::from_json(
            &policy_json.to_string(),
            "2.1.38",
            "locked-read-only",
            false,
        )
        .expect_err("non-kms role should fail");
        assert!(err.to_string().contains("Policy role mismatch"));
    }

    #[test]
    fn from_json_allows_locked_legacy_missing_profile() {
        let policy_json = serde_json::json!({
            "tag": "2.1.38",
            "policy": {
                "node_allowed_tcb_statuses": ["uptodate"],
                "node_allowed_mrtd": ["aa".repeat(48)],
                "node_allowed_rtmr0": ["bb".repeat(48)],
                "node_allowed_rtmr1": ["cc".repeat(48)],
                "node_allowed_rtmr2": ["dd".repeat(48)],
                "node_allowed_rtmr3": ["ee".repeat(48)]
            }
        });
        let parsed = AttestationPolicy::from_json(
            &policy_json.to_string(),
            "2.1.38",
            "locked-read-only",
            true,
        )
        .expect("legacy policy should parse for locked profile");
        assert_eq!(parsed.allowed_mrtd.len(), 1);
        assert_eq!(parsed.allowed_mrtd[0].as_str(), "aa".repeat(48));
    }
}
