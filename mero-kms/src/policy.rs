//! Policy model and startup validation helpers.

use eyre::{bail, Result as EyreResult};

/// Attestation verification policy for key release.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// Whether measurement checks are enforced.
    pub enforce_measurement_policy: bool,
    /// Allowed TCB statuses (normalized to lowercase).
    pub allowed_tcb_statuses: Vec<String>,
    /// Allowed MRTD values (hex, lowercase, no 0x prefix).
    pub allowed_mrtd: Vec<String>,
    /// Allowed RTMR0 values (hex, lowercase, no 0x prefix).
    pub allowed_rtmr0: Vec<String>,
    /// Allowed RTMR1 values (hex, lowercase, no 0x prefix).
    pub allowed_rtmr1: Vec<String>,
    /// Allowed RTMR2 values (hex, lowercase, no 0x prefix).
    pub allowed_rtmr2: Vec<String>,
    /// Allowed RTMR3 values (hex, lowercase, no 0x prefix).
    pub allowed_rtmr3: Vec<String>,
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

    let checks: [(&str, &[String], &str); 5] = [
        (
            "allowed_mrtd",
            &policy.allowed_mrtd,
            "Provide policy via MERO_KMS_VERSION + MERO_KMS_PROFILE, or use USE_ENV_POLICY=true for explicit air-gapped mode.",
        ),
        (
            "allowed_rtmr0",
            &policy.allowed_rtmr0,
            "Configure at least one trusted RTMR0 value.",
        ),
        (
            "allowed_rtmr1",
            &policy.allowed_rtmr1,
            "Configure at least one trusted RTMR1 value.",
        ),
        (
            "allowed_rtmr2",
            &policy.allowed_rtmr2,
            "Configure at least one trusted RTMR2 value.",
        ),
        (
            "allowed_rtmr3",
            &policy.allowed_rtmr3,
            "Configure at least one trusted RTMR3 value.",
        ),
    ];
    for (name, values, guidance) in checks {
        if values.is_empty() {
            bail!(
                "Measurement policy is enforced, but {} is empty. {}",
                name,
                guidance
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_policy() -> AttestationPolicy {
        let measurement = "ab".repeat(48);
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
}
