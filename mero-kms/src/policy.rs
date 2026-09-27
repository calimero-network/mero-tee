//! Policy model and startup validation.

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
}

/// Fail-fast check at startup: when enforcement is on, every measurement
/// register must have at least one allowed value. This catches misconfiguration
/// before the first key-release request arrives.
///
/// The `accept_mock_attestation` short-circuit exists only under the default-off
/// `mock-attestation` feature; the production build cannot bypass this check.
pub fn validate_policy_requirements(
    policy: &AttestationPolicy,
    #[cfg(feature = "mock-attestation")] accept_mock_attestation: bool,
) -> EyreResult<()> {
    #[cfg(feature = "mock-attestation")]
    if accept_mock_attestation {
        return Ok(());
    }
    if !policy.enforce_measurement_policy {
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
            bail!(
                "Measurement policy is enforced, but allowed_{} is empty. Set ALLOWED_{} to \
                 at least one trusted value.",
                label.to_ascii_lowercase(),
                label
            );
        }
    }
    Ok(())
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
        let err = validate_policy_requirements(
            &policy,
            #[cfg(feature = "mock-attestation")]
            false,
        )
        .expect_err("missing RTMR3 should fail");
        assert!(err.to_string().contains("allowed_rtmr3"));
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_tcb_statuses() {
        let mut policy = strict_policy();
        policy.allowed_tcb_statuses.clear();
        let err = validate_policy_requirements(
            &policy,
            #[cfg(feature = "mock-attestation")]
            false,
        )
        .expect_err("missing TCB status allowlist should fail");
        assert!(err.to_string().contains("allowed_tcb_statuses"));
    }

    #[cfg(feature = "mock-attestation")]
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
}
