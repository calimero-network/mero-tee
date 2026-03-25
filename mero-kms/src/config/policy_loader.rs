//! Release-based policy fetching and URL resolution.

use eyre::{bail, Result as EyreResult};

use crate::policy::AttestationPolicy;

use super::env::hash_bytes_hex;

const POLICY_RELEASE_BASE: &str = "https://github.com/calimero-network/mero-tee/releases/download";

/// HTTP client timeout for policy fetches.
const POLICY_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// User-Agent header sent when fetching policies from GitHub releases.
const POLICY_FETCH_USER_AGENT: &str = "mero-kms-phala/1.0";

/// A candidate URL for fetching an attestation policy, with metadata
/// about whether it is a legacy (profile-less) fallback.
#[derive(Debug, Clone)]
pub struct PolicyCandidate {
    /// Full URL to the policy JSON asset on GitHub releases.
    pub url: String,
    /// `true` when this candidate is the legacy profile-less fallback URL.
    pub is_legacy_fallback: bool,
}

/// Build the ordered list of policy candidate URLs to try for a given
/// release version and profile.
pub fn policy_candidate_urls(version: &str, profile: &str) -> Vec<PolicyCandidate> {
    let tag = format!("mero-kms-v{}", version.trim());
    vec![
        PolicyCandidate {
            url: format!(
                "{}/{}/kms-phala-attestation-policy.{}.json",
                POLICY_RELEASE_BASE, tag, profile
            ),
            is_legacy_fallback: false,
        },
        PolicyCandidate {
            url: format!(
                "{}/{}/kms-phala-attestation-policy.json",
                POLICY_RELEASE_BASE, tag
            ),
            is_legacy_fallback: true,
        },
    ]
}

/// Fetch an attestation policy from GitHub releases, trying profile-specific
/// then generic fallback URLs.
pub async fn fetch_policy_from_release(
    version: &str,
    profile: &str,
    expected_policy_sha256: Option<&str>,
) -> EyreResult<AttestationPolicy> {
    let candidates = policy_candidate_urls(version, profile);
    let client = reqwest::Client::builder()
        .timeout(POLICY_FETCH_TIMEOUT)
        .user_agent(POLICY_FETCH_USER_AGENT)
        .build()
        .map_err(|e| eyre::eyre!("Failed to create HTTP client: {}", e))?;
    let mut last_error: Option<String> = None;
    for candidate in &candidates {
        let resp = match client.get(&candidate.url).send().await {
            Ok(resp) => resp,
            Err(err) => {
                last_error = Some(format!("request error for {}: {}", candidate.url, err));
                continue;
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            last_error = Some(format!("not found: {}", candidate.url));
            continue;
        }
        if !resp.status().is_success() {
            bail!("Policy fetch failed: {} {}", resp.status(), candidate.url);
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| eyre::eyre!("Failed to read policy response: {}", e))?;
        if let Some(expected) = expected_policy_sha256 {
            let actual = hash_bytes_hex(&bytes);
            if actual != expected {
                bail!(
                    "Policy hash mismatch for {}: expected {}, got {}",
                    candidate.url,
                    expected,
                    actual
                );
            }
        }
        let body = std::str::from_utf8(&bytes)
            .map_err(|e| eyre::eyre!("Policy body is not valid UTF-8: {}", e))?;
        return AttestationPolicy::from_json(
            body,
            version.trim(),
            profile,
            candidate.is_legacy_fallback,
        );
    }

    bail!(
        "Policy fetch failed for profile '{}': {}",
        profile,
        last_error.unwrap_or_else(|| "no policy candidates resolved".to_string())
    );
}
