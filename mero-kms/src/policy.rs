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
            "Measurement policy is enforced, but ALLOWED_TCB_STATUSES is empty. \
             Configure at least one allowed status (recommended: UpToDate)."
        );
    }

    let checks: [(&str, &[String], &str); 5] = [
        (
            "ALLOWED_MRTD",
            &policy.allowed_mrtd,
            "Set MERO_KMS_VERSION to fetch from release, or USE_ENV_POLICY=true with ALLOWED_MRTD for air-gapped.",
        ),
        (
            "ALLOWED_RTMR0",
            &policy.allowed_rtmr0,
            "Configure at least one trusted RTMR0 value.",
        ),
        (
            "ALLOWED_RTMR1",
            &policy.allowed_rtmr1,
            "Configure at least one trusted RTMR1 value.",
        ),
        (
            "ALLOWED_RTMR2",
            &policy.allowed_rtmr2,
            "Configure at least one trusted RTMR2 value.",
        ),
        (
            "ALLOWED_RTMR3",
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
