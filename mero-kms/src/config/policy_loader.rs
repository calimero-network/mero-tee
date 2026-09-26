//! Release-based policy fetching and URL resolution.
//!
//! A fetched policy is only used once its Sigstore signature verifies against
//! the `Release mero-kms` workflow identity (see [`super::policy_signature`]).
//! `MERO_KMS_POLICY_SHA256`, when set, is an additional pin on top of that.

use eyre::{bail, Result as EyreResult};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::policy::AttestationPolicy;

use super::env::hash_bytes_hex;
use super::policy_signature::{
    load_trust_root, verify_policy_signature, BUNDLE_ASSET_SUFFIX, SIGNATURE_ASSET_SUFFIX,
};

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
///
/// The first candidate that exists must also have its `.sig` and
/// `.bundle.json` assets, and they must verify; a candidate whose signature is
/// missing or wrong is an error, not a reason to try the next one.
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
        let signature = fetch_text_asset(
            &client,
            &format!("{}{}", candidate.url, SIGNATURE_ASSET_SUFFIX),
        )
        .await?;
        let bundle = fetch_text_asset(
            &client,
            &format!("{}{}", candidate.url, BUNDLE_ASSET_SUFFIX),
        )
        .await?;
        let trust_root = load_trust_root().await?;
        return verified_policy_from_assets(
            trust_root,
            candidate,
            &bytes,
            &signature,
            &bundle,
            expected_policy_sha256,
            version,
            profile,
        )
        .await;
    }

    bail!(
        "Policy fetch failed for profile '{}': {}",
        profile,
        last_error.unwrap_or_else(|| "no policy candidates resolved".to_string())
    );
}

async fn fetch_text_asset(client: &reqwest::Client, url: &str) -> EyreResult<String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to fetch {}: {}", url, e))?;
    if !resp.status().is_success() {
        bail!("Failed to fetch {}: {}", url, resp.status());
    }
    resp.text()
        .await
        .map_err(|e| eyre::eyre!("Failed to read {}: {}", url, e))
}

/// Verify a fetched policy's signature (and hash pin, if any), then parse it.
#[allow(clippy::too_many_arguments)]
async fn verified_policy_from_assets(
    trust_root: SigstoreTrustRoot,
    candidate: &PolicyCandidate,
    policy_bytes: &[u8],
    signature: &str,
    bundle: &str,
    expected_policy_sha256: Option<&str>,
    version: &str,
    profile: &str,
) -> EyreResult<AttestationPolicy> {
    verify_policy_signature(trust_root, policy_bytes, signature, bundle)
        .await
        .map_err(|e| {
            eyre::eyre!(
                "Policy signature verification failed for {}: {}",
                candidate.url,
                e
            )
        })?;
    if let Some(expected) = expected_policy_sha256 {
        let actual = hash_bytes_hex(policy_bytes);
        if actual != expected {
            bail!(
                "Policy hash mismatch for {}: expected {}, got {}",
                candidate.url,
                expected,
                actual
            );
        }
    }
    let body = std::str::from_utf8(policy_bytes)
        .map_err(|e| eyre::eyre!("Policy body is not valid UTF-8: {}", e))?;
    AttestationPolicy::from_json(body, version.trim(), profile, candidate.is_legacy_fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &[u8] =
        include_bytes!("../../testdata/kms-phala-attestation-policy.locked-read-only.json");
    const SIGNATURE: &str =
        include_str!("../../testdata/kms-phala-attestation-policy.locked-read-only.json.sig");
    const BUNDLE: &str = include_str!(
        "../../testdata/kms-phala-attestation-policy.locked-read-only.json.bundle.json"
    );
    const TRUSTED_ROOT: &[u8] = include_bytes!("../../testdata/sigstore-trusted-root.json");
    const VERSION: &str = "2.3.71";
    const PROFILE: &str = "locked-read-only";

    fn trust_root() -> SigstoreTrustRoot {
        SigstoreTrustRoot::from_trusted_root_json_unchecked(TRUSTED_ROOT)
            .expect("fixture trusted root parses")
    }

    fn candidate() -> PolicyCandidate {
        policy_candidate_urls(VERSION, PROFILE)
            .into_iter()
            .next()
            .expect("a profile candidate")
    }

    async fn load(policy: &[u8], pin: Option<&str>) -> EyreResult<AttestationPolicy> {
        verified_policy_from_assets(
            trust_root(),
            &candidate(),
            policy,
            SIGNATURE,
            BUNDLE,
            pin,
            VERSION,
            PROFILE,
        )
        .await
    }

    #[tokio::test]
    async fn a_signed_release_policy_loads() {
        let policy = load(POLICY, None).await.expect("signed policy loads");
        assert!(!policy.allowed_mrtd.is_empty());
    }

    #[tokio::test]
    async fn a_signed_release_policy_loads_under_its_hash_pin() {
        let pin = hash_bytes_hex(POLICY);
        let _ = load(POLICY, Some(&pin)).await.expect("pinned policy loads");
    }

    /// mero-tee#337: a release asset swapped for one that admits an extra
    /// node MRTD must not load, even with no `MERO_KMS_POLICY_SHA256` pin.
    #[tokio::test]
    async fn a_tampered_release_policy_is_refused_without_a_pin() {
        let mut policy: serde_json::Value =
            serde_json::from_slice(POLICY).expect("fixture is JSON");
        policy["policy"]["node_allowed_mrtd"]
            .as_array_mut()
            .expect("fixture has node_allowed_mrtd")
            .push(serde_json::Value::String("cd".repeat(48)));
        let tampered = serde_json::to_vec_pretty(&policy).expect("serializes");

        let err = load(&tampered, None)
            .await
            .expect_err("a tampered policy must be refused");
        assert!(
            err.to_string()
                .contains("Policy signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn a_signed_policy_under_the_wrong_pin_is_refused() {
        let err = load(POLICY, Some(&"00".repeat(32)))
            .await
            .expect_err("a pin mismatch must be refused");
        assert!(
            err.to_string().contains("Policy hash mismatch"),
            "unexpected error: {err}"
        );
    }
}
