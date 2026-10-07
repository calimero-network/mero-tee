//! Policy model and startup validation.

use eyre::{bail, Result as EyreResult};

use crate::measurement::HexMeasurement;

/// The kind of TD a policy entry admits. The KMS infers it from the entry a
/// quote matches; a requester never states it. It picks the key namespace, so
/// an agent can never be released a node's key whatever peer ID it presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A merod node image.
    Node,
    /// A private agent image.
    Agent,
}

impl Role {
    /// The role's name as it appears in RTMR3 and in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Agent => "agent",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The measurements of one released image role.
///
/// A quote matches an entry only when all five registers are in that entry's
/// lists. Matching each register against a list pooled across roles would
/// accept combinations no released image produces, such as a node's MRTD to
/// RTMR2 with an agent's RTMR3.
#[derive(Debug, Clone)]
pub struct PolicyEntry {
    /// The role a quote matching this entry is released keys as.
    pub role: Role,
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

impl PolicyEntry {
    /// An entry for `role` with every allowlist empty.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            allowed_mrtd: Vec::new(),
            allowed_rtmr0: Vec::new(),
            allowed_rtmr1: Vec::new(),
            allowed_rtmr2: Vec::new(),
            allowed_rtmr3: Vec::new(),
        }
    }

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
}

/// Attestation verification policy for key release.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// Whether measurement checks are enforced.
    pub enforce_measurement_policy: bool,
    /// Allowed TCB statuses (normalized to lowercase), shared by every role:
    /// they describe the platform, not the image.
    pub allowed_tcb_statuses: Vec<String>,
    /// One entry per image role this KMS serves.
    pub entries: Vec<PolicyEntry>,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_owned()],
            entries: Vec::new(),
        }
    }
}

impl AttestationPolicy {
    /// The entry for `role`, if this KMS serves it.
    pub fn entry(&self, role: Role) -> Option<&PolicyEntry> {
        self.entries.iter().find(|entry| entry.role == role)
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

/// Whether some quote could match both entries: every register's lists share
/// a value.
fn entries_overlap(a: &PolicyEntry, b: &PolicyEntry) -> bool {
    a.register_fields()
        .iter()
        .zip(b.register_fields())
        .all(|((_, ours), (_, theirs))| ours.iter().any(|value| theirs.contains(value)))
}

/// Fail-fast check at startup: when enforcement is on, there must be at least
/// one entry, at most one per role, no two entries a single quote could match,
/// and every measurement register of every
/// entry must have at least one allowed value. This catches misconfiguration
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
    if policy.entries.is_empty() {
        bail!("Measurement policy is enforced, but it has no entries. Set ALLOWED_MRTD..RTMR3.");
    }

    for (index, entry) in policy.entries.iter().enumerate() {
        // Two entries for one role would be two allowlists the operator has
        // to read together to know what that role admits; one is enough.
        if policy.entries[..index]
            .iter()
            .any(|earlier| earlier.role == entry.role)
        {
            bail!("Measurement policy has more than one {} entry", entry.role);
        }
        // A quote that could match two entries would get the first one's role,
        // so which key it is released would depend on entry order.
        if let Some(earlier) = policy.entries[..index]
            .iter()
            .find(|earlier| entries_overlap(earlier, entry))
        {
            bail!(
                "Measurement policy entries {} and {} share a value in every register, \
                 so one quote could match both",
                earlier.role,
                entry.role
            );
        }
        let env_prefix = match entry.role {
            Role::Node => "",
            Role::Agent => "AGENT_",
        };
        for (label, allowlist) in entry.register_fields() {
            if allowlist.is_empty() {
                bail!(
                    "Measurement policy is enforced, but the {} entry's allowed_{} is empty. \
                     Set {}ALLOWED_{} to at least one trusted value.",
                    entry.role,
                    label.to_ascii_lowercase(),
                    env_prefix,
                    label
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MEASUREMENT_BYTES;

    fn strict_entry(role: Role) -> PolicyEntry {
        let measurement = HexMeasurement::parse(&"ab".repeat(MEASUREMENT_BYTES)).unwrap();
        PolicyEntry {
            role,
            allowed_mrtd: vec![measurement.clone()],
            allowed_rtmr0: vec![measurement.clone()],
            allowed_rtmr1: vec![measurement.clone()],
            allowed_rtmr2: vec![measurement.clone()],
            allowed_rtmr3: vec![measurement],
        }
    }

    fn strict_policy() -> AttestationPolicy {
        AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_string()],
            entries: vec![strict_entry(Role::Node)],
        }
    }

    fn validate(policy: &AttestationPolicy) -> EyreResult<()> {
        validate_policy_requirements(
            policy,
            #[cfg(feature = "mock-attestation")]
            false,
        )
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_rtmr3() {
        let mut policy = strict_policy();
        policy.entries[0].allowed_rtmr3.clear();
        let err = validate(&policy).expect_err("missing RTMR3 should fail");
        assert!(err.to_string().contains("allowed_rtmr3"));
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_tcb_statuses() {
        let mut policy = strict_policy();
        policy.allowed_tcb_statuses.clear();
        let err = validate(&policy).expect_err("missing TCB status allowlist should fail");
        assert!(err.to_string().contains("allowed_tcb_statuses"));
    }

    #[test]
    fn validate_policy_requirements_rejects_no_entries() {
        let mut policy = strict_policy();
        policy.entries.clear();
        let err = validate(&policy).expect_err("a policy with no entries should fail");
        assert!(err.to_string().contains("no entries"), "{err}");
    }

    #[test]
    fn validate_policy_requirements_rejects_two_entries_with_one_role() {
        let mut policy = strict_policy();
        policy.entries.push(strict_entry(Role::Node));
        let err = validate(&policy).expect_err("two node entries should fail");
        assert!(
            err.to_string().contains("more than one node entry"),
            "{err}"
        );
    }

    #[test]
    fn validate_policy_requirements_names_the_agent_env_var() {
        let mut policy = strict_policy();
        let mut agent = strict_entry(Role::Agent);
        agent.allowed_mrtd.clear();
        policy.entries.push(agent);
        let err = validate(&policy).expect_err("an incomplete agent entry should fail");
        assert!(err.to_string().contains("AGENT_ALLOWED_MRTD"), "{err}");
    }

    #[test]
    fn validate_policy_requirements_rejects_entries_one_quote_could_match() {
        let mut policy = strict_policy();
        policy.entries.push(strict_entry(Role::Agent));
        let err = validate(&policy).expect_err("identical node and agent entries should fail");
        assert!(err.to_string().contains("could match both"), "{err}");
    }

    #[test]
    fn validate_policy_requirements_accepts_a_node_and_an_agent_entry() {
        let mut policy = strict_policy();
        let mut agent = strict_entry(Role::Agent);
        agent.allowed_rtmr3 = vec![HexMeasurement::parse(&"cd".repeat(MEASUREMENT_BYTES)).unwrap()];
        policy.entries.push(agent);
        validate(&policy).expect("one entry per role, differing in RTMR3, is valid");
    }

    #[cfg(feature = "mock-attestation")]
    #[test]
    fn validate_policy_requirements_allows_when_mock_enabled() {
        let policy = AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: Vec::new(),
            entries: vec![PolicyEntry::new(Role::Node)],
        };
        assert!(validate_policy_requirements(&policy, true).is_ok());
    }
}
