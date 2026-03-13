//! mero-kms-phala: Key management service for merod nodes running in Phala Cloud TEE.
//!
//! This service validates TDX attestations from merod nodes and releases deterministic
//! storage encryption keys based on peer ID using Phala's dstack key derivation.

mod challenge_store;
mod handlers;

use std::net::SocketAddr;

use axum::http::{HeaderValue, Method};
use eyre::{bail, Result as EyreResult};
use sha2::Digest;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::handlers::create_router;

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

/// Configuration for the key releaser service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Socket address to listen on.
    pub listen_addr: SocketAddr,
    /// Path to the dstack Unix socket.
    pub dstack_socket_path: String,
    /// Challenge token TTL in seconds.
    pub challenge_ttl_secs: u64,
    /// Maximum number of unconsumed challenges allowed at once.
    pub max_pending_challenges: usize,
    /// Whether to accept mock attestations (for development only).
    pub accept_mock_attestation: bool,
    /// Optional Redis URL for shared challenge storage.
    pub redis_url: Option<String>,
    /// Policy/profile cohort name used for policy fetch and key namespace separation.
    pub kms_profile: String,
    /// Key path prefix used for key derivation namespace separation.
    pub key_namespace_prefix: String,
    /// Optional SHA-256 pin for fetched policy asset.
    pub policy_sha256: Option<String>,
    /// Explicit CORS allowlist; empty means CORS disabled.
    pub cors_allowed_origins: Vec<String>,
    /// Attestation policy used for key release decisions.
    pub attestation_policy: AttestationPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            dstack_socket_path: "/var/run/dstack.sock".to_string(),
            challenge_ttl_secs: 60,
            max_pending_challenges: 10_000,
            accept_mock_attestation: false,
            redis_url: None,
            kms_profile: "locked-read-only".to_string(),
            key_namespace_prefix: "merod/storage".to_string(),
            policy_sha256: None,
            cors_allowed_origins: Vec::new(),
            attestation_policy: AttestationPolicy::default(),
        }
    }
}

const POLICY_RELEASE_BASE: &str = "https://github.com/calimero-network/mero-tee/releases/download";
const KNOWN_PROFILES: [&str; 3] = ["debug", "debug-read-only", "locked-read-only"];

impl Config {
    /// Load configuration from environment variables.
    /// When MERO_KMS_VERSION is set, fetches attestation policy from the official release
    /// instead of trusting env vars. Use USE_ENV_POLICY=true for air-gapped deployments.
    pub async fn from_env() -> EyreResult<Self> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));

        let dstack_socket_path = std::env::var("DSTACK_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/run/dstack.sock".to_string());

        let challenge_ttl_secs = std::env::var("CHALLENGE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let max_pending_challenges = std::env::var("MAX_PENDING_CHALLENGES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10_000);
        if max_pending_challenges == 0 {
            bail!("MAX_PENDING_CHALLENGES must be greater than 0");
        }

        let accept_mock_attestation = parse_bool_env("ACCEPT_MOCK_ATTESTATION", false)?;

        let redis_url = std::env::var("REDIS_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let kms_profile = parse_profile(
            std::env::var("KMS_POLICY_PROFILE")
                .ok()
                .as_deref()
                .unwrap_or("locked-read-only"),
        )?;

        let key_namespace_prefix = std::env::var("KEY_NAMESPACE_PREFIX")
            .ok()
            .map(|v| v.trim_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "merod/storage".to_string());

        let policy_sha256 = std::env::var("MERO_KMS_POLICY_SHA256")
            .ok()
            .map(|v| normalize_hash_pin(&v))
            .transpose()?;

        let cors_allowed_origins = parse_csv_env_raw("CORS_ALLOWED_ORIGINS").unwrap_or_default();

        let enforce_measurement_policy = parse_bool_env("ENFORCE_MEASUREMENT_POLICY", true)?;

        let use_env_policy = parse_bool_env("USE_ENV_POLICY", false)?;

        let release_version = if use_env_policy {
            None
        } else {
            Self::release_version_from_env()
        };
        if release_version.is_some() && policy_sha256.is_none() {
            bail!(
                "MERO_KMS_POLICY_SHA256 is required when loading policy from release. \
                 Set MERO_KMS_POLICY_SHA256 to the reviewed policy hash, or set USE_ENV_POLICY=true \
                 for air-gapped env-policy mode."
            );
        }

        let mut attestation_policy = if use_env_policy {
            Self::load_policy_from_env()?
        } else if let Some(version) = release_version {
            let policy = Self::fetch_policy_from_release_async(
                &version,
                &kms_profile,
                policy_sha256.as_deref(),
            )
            .await?;
            tracing::info!(
                "Loaded attestation policy from release mero-kms-v{} profile {}",
                version,
                kms_profile
            );
            policy
        } else {
            Self::load_policy_from_env()?
        };
        attestation_policy.enforce_measurement_policy = enforce_measurement_policy;

        validate_policy_requirements(&attestation_policy, accept_mock_attestation)?;

        Ok(Self {
            listen_addr,
            dstack_socket_path,
            challenge_ttl_secs,
            max_pending_challenges,
            accept_mock_attestation,
            redis_url,
            kms_profile,
            key_namespace_prefix,
            policy_sha256,
            cors_allowed_origins,
            attestation_policy,
        })
    }

    fn release_version_from_env() -> Option<String> {
        let tag = std::env::var("MERO_KMS_RELEASE_TAG").ok();
        let version = std::env::var("MERO_KMS_VERSION").ok();
        tag.or(version).map(|s| {
            let s = s.trim();
            if s.starts_with("mero-kms-v") {
                s.strip_prefix("mero-kms-v").unwrap_or(s).to_string()
            } else {
                s.to_string()
            }
        })
    }

    async fn fetch_policy_from_release_async(
        version: &str,
        profile: &str,
        expected_policy_sha256: Option<&str>,
    ) -> EyreResult<AttestationPolicy> {
        let tag = format!("mero-kms-v{}", version.trim());
        let mut urls = vec![(
            format!(
                "{}/{}/kms-phala-attestation-policy.{}.json",
                POLICY_RELEASE_BASE, tag, profile
            ),
            false,
        )];
        if profile == "locked-read-only" {
            urls.push((
                format!(
                    "{}/{}/kms-phala-attestation-policy.json",
                    POLICY_RELEASE_BASE, tag
                ),
                true,
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("mero-kms-phala/1.0")
            .build()
            .map_err(|e| eyre::eyre!("Failed to create HTTP client: {}", e))?;
        let mut last_error: Option<String> = None;
        for (url, legacy_fallback) in urls {
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| eyre::eyre!("Policy fetch failed: {}", e))?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                last_error = Some(format!("not found: {}", url));
                continue;
            }
            if !resp.status().is_success() {
                bail!("Policy fetch failed: {} {}", resp.status(), url);
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
                        url,
                        expected,
                        actual
                    );
                }
            }
            let body = std::str::from_utf8(&bytes)
                .map_err(|e| eyre::eyre!("Policy body is not valid UTF-8: {}", e))?;
            return Self::parse_policy_json(body, version.trim(), profile, legacy_fallback);
        }

        bail!(
            "Policy fetch failed for profile '{}': {}",
            profile,
            last_error.unwrap_or_else(|| "no policy candidates resolved".to_string())
        );
    }

    fn parse_policy_json(
        json_str: &str,
        expected_tag: &str,
        expected_profile: &str,
        allow_legacy_missing_profile: bool,
    ) -> EyreResult<AttestationPolicy> {
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
            Some(role) => {
                bail!("Policy role mismatch: expected 'kms', got '{}'", role);
            }
            None if allow_legacy_missing_profile && expected_profile == "locked-read-only" => {}
            None => {
                bail!("Policy JSON missing 'role' for KMS policy");
            }
        }
        match root.get("profile").and_then(|value| value.as_str()) {
            Some(profile) => {
                let normalized = parse_profile(profile)?;
                if normalized != expected_profile {
                    bail!(
                        "Policy profile mismatch: expected '{}', got '{}'",
                        expected_profile,
                        normalized
                    );
                }
            }
            None if allow_legacy_missing_profile && expected_profile == "locked-read-only" => {}
            None => {
                bail!(
                    "Policy JSON missing 'profile' for requested profile '{}'",
                    expected_profile
                );
            }
        }
        let policy = root
            .get("policy")
            .and_then(|v| v.as_object())
            .ok_or_else(|| eyre::eyre!("Policy JSON missing 'policy' object"))?;

        // KMS verifies nodes; use node_allowed_* (fallback to allowed_* for legacy)
        let allowed_tcb_statuses = parse_json_string_array(policy, "node_allowed_tcb_statuses")
            .or_else(|| parse_json_string_array(policy, "allowed_tcb_statuses"))
            .unwrap_or_else(|| vec!["uptodate".to_owned()]);
        let allowed_mrtd =
            parse_policy_hex_allowlist(policy, "node_allowed_mrtd", "allowed_mrtd", 48)?;
        let allowed_rtmr0 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr0", "allowed_rtmr0", 48)?;
        let allowed_rtmr1 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr1", "allowed_rtmr1", 48)?;
        let allowed_rtmr2 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr2", "allowed_rtmr2", 48)?;
        let allowed_rtmr3 =
            parse_policy_hex_allowlist(policy, "node_allowed_rtmr3", "allowed_rtmr3", 48)?;

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

    fn load_policy_from_env() -> EyreResult<AttestationPolicy> {
        let allowed_tcb_statuses =
            parse_csv_env("ALLOWED_TCB_STATUSES").unwrap_or_else(|| vec!["uptodate".to_owned()]);
        let allowed_mrtd = parse_measurement_list_env("ALLOWED_MRTD", "MRTD", 48)?;
        let allowed_rtmr0 = parse_measurement_list_env("ALLOWED_RTMR0", "RTMR0", 48)?;
        let allowed_rtmr1 = parse_measurement_list_env("ALLOWED_RTMR1", "RTMR1", 48)?;
        let allowed_rtmr2 = parse_measurement_list_env("ALLOWED_RTMR2", "RTMR2", 48)?;
        let allowed_rtmr3 = parse_measurement_list_env("ALLOWED_RTMR3", "RTMR3", 48)?;

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

fn parse_bool_flag(value: &str) -> EyreResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => bail!(
            "Invalid boolean value '{}'. Allowed: true/false/1/0/yes/no",
            value
        ),
    }
}

fn parse_bool_env(name: &str, default: bool) -> EyreResult<bool> {
    match std::env::var(name) {
        Ok(value) => parse_bool_flag(&value).map_err(|e| eyre::eyre!("{} is invalid: {}", name, e)),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{} must be valid UTF-8", name)
        }
    }
}

fn parse_profile(value: &str) -> EyreResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if KNOWN_PROFILES.iter().any(|profile| *profile == normalized) {
        Ok(normalized)
    } else {
        bail!(
            "Unsupported KMS_POLICY_PROFILE '{}'. Allowed values: {}",
            value,
            KNOWN_PROFILES.join(", ")
        )
    }
}

fn normalize_hash_pin(value: &str) -> EyreResult<String> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    let normalized = without_prefix
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "MERO_KMS_POLICY_SHA256 must be a 64-hex sha256 (optionally prefixed by sha256:). Got '{}'",
            value
        );
    }
    Ok(normalized)
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn parse_json_string_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    let arr = obj.get(key)?.as_array()?;
    let out: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_json_hex_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_bytes: usize,
) -> EyreResult<Vec<String>> {
    let arr = match obj.get(key).and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let mut parsed = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| eyre::eyre!("Policy {}[{}] must be a string", key, i))?;
        let normalized = normalize_hex(s);
        let bytes = hex::decode(&normalized)
            .map_err(|e| eyre::eyre!("Policy {}[{}] invalid hex: {}", key, i, e))?;
        if bytes.len() != expected_bytes {
            bail!(
                "Policy {}[{}] invalid length: expected {} bytes, got {}",
                key,
                i,
                expected_bytes,
                bytes.len()
            );
        }
        parsed.push(normalized);
    }
    Ok(parsed)
}

fn parse_policy_hex_allowlist(
    policy: &serde_json::Map<String, serde_json::Value>,
    primary_key: &str,
    legacy_key: &str,
    expected_bytes: usize,
) -> EyreResult<Vec<String>> {
    let primary = parse_json_hex_array(policy, primary_key, expected_bytes)?;
    if primary.is_empty() {
        parse_json_hex_array(policy, legacy_key, expected_bytes)
    } else {
        Ok(primary)
    }
}

fn parse_csv_env(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect()
    })
}

fn parse_csv_env_raw(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn parse_measurement_list_env(
    name: &str,
    label: &str,
    expected_bytes: usize,
) -> EyreResult<Vec<String>> {
    let Some(values) = parse_csv_env(name) else {
        return Ok(Vec::new());
    };

    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let normalized = normalize_hex(&value);
        let bytes = hex::decode(&normalized).map_err(|e| {
            eyre::eyre!(
                "{} value '{}' from {} is not valid hex: {}",
                label,
                value,
                name,
                e
            )
        })?;
        if bytes.len() != expected_bytes {
            bail!(
                "{} value '{}' from {} has invalid length: expected {} bytes, got {}",
                label,
                value,
                name,
                expected_bytes,
                bytes.len()
            );
        }
        parsed.push(normalized);
    }

    Ok(parsed)
}

fn normalize_hex(value: &str) -> String {
    value.trim().trim_start_matches("0x").to_ascii_lowercase()
}

fn validate_policy_requirements(
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_level(true)
        .init();

    // Load configuration
    let config = Config::from_env().await?;

    info!("Starting mero-kms-phala");
    info!("Listen address: {}", config.listen_addr);
    info!("Dstack socket: {}", config.dstack_socket_path);
    info!("Challenge TTL (seconds): {}", config.challenge_ttl_secs);
    info!("Max pending challenges: {}", config.max_pending_challenges);
    info!(
        "Accept mock attestation: {}",
        config.accept_mock_attestation
    );
    info!("KMS profile cohort: {}", config.kms_profile);
    info!("Key namespace prefix: {}", config.key_namespace_prefix);
    if let Some(redis_url) = config.redis_url.as_deref() {
        info!("Challenge store backend: redis ({})", redis_url);
    } else {
        info!("Challenge store backend: in-memory");
    }
    if let Some(policy_sha256) = config.policy_sha256.as_deref() {
        info!("Policy SHA-256 pin enabled: {}", policy_sha256);
    }
    info!(
        "Measurement policy enforced: {}",
        config.attestation_policy.enforce_measurement_policy
    );
    if !config.attestation_policy.enforce_measurement_policy {
        tracing::warn!(
            "Measurement policy enforcement is disabled; this is not safe for production"
        );
    }
    info!(
        "Policy entries: tcb_statuses={}, mrtd={}, rtmr0={}, rtmr1={}, rtmr2={}, rtmr3={}",
        config.attestation_policy.allowed_tcb_statuses.len(),
        config.attestation_policy.allowed_mrtd.len(),
        config.attestation_policy.allowed_rtmr0.len(),
        config.attestation_policy.allowed_rtmr1.len(),
        config.attestation_policy.allowed_rtmr2.len(),
        config.attestation_policy.allowed_rtmr3.len()
    );

    if config.accept_mock_attestation {
        tracing::warn!(
            "WARNING: Mock attestation acceptance is enabled. This should NEVER be used in production!"
        );
    }

    // Create router with handlers
    let base_app = create_router(config.clone())?.layer(TraceLayer::new_for_http());
    let app = if config.cors_allowed_origins.is_empty() {
        tracing::info!("CORS disabled (CORS_ALLOWED_ORIGINS not set)");
        base_app
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .map(|origin| {
                HeaderValue::from_str(origin)
                    .map_err(|e| eyre::eyre!("Invalid CORS origin '{}': {}", origin, e))
            })
            .collect::<EyreResult<_>>()?;
        base_app.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        )
    };

    // Start server
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_policy() -> AttestationPolicy {
        let v = "ab".repeat(48);
        AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_string()],
            allowed_mrtd: vec![v.clone()],
            allowed_rtmr0: vec![v.clone()],
            allowed_rtmr1: vec![v.clone()],
            allowed_rtmr2: vec![v.clone()],
            allowed_rtmr3: vec![v],
        }
    }

    #[test]
    fn validate_policy_requirements_rejects_missing_rtmr3() {
        let mut policy = strict_policy();
        policy.allowed_rtmr3.clear();
        let err = validate_policy_requirements(&policy, false).unwrap_err();
        assert!(err.to_string().contains("ALLOWED_RTMR3"));
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
    fn parse_policy_hex_allowlist_prefers_primary_key() {
        let primary = "cd".repeat(48);
        let legacy = "ef".repeat(48);
        let value = serde_json::json!({
            "node_allowed_mrtd": [primary],
            "allowed_mrtd": [legacy],
        });
        let policy = value.as_object().expect("policy object");
        let parsed =
            parse_policy_hex_allowlist(policy, "node_allowed_mrtd", "allowed_mrtd", 48).unwrap();
        assert_eq!(parsed, vec!["cd".repeat(48)]);
    }

    #[test]
    fn parse_bool_flag_accepts_false_values() {
        assert!(!parse_bool_flag("false").unwrap());
        assert!(!parse_bool_flag("0").unwrap());
        assert!(!parse_bool_flag("no").unwrap());
    }

    #[test]
    fn parse_bool_flag_rejects_invalid_value() {
        let err = parse_bool_flag("truthy").unwrap_err();
        assert!(err.to_string().contains("Invalid boolean value"));
    }

    #[test]
    fn parse_policy_json_rejects_mismatched_profile() {
        let measurement = "ab".repeat(48);
        let policy_json = serde_json::json!({
            "tag": "2.1.38",
            "role": "kms",
            "profile": "debug",
            "policy": {
                "node_allowed_tcb_statuses": ["uptodate"],
                "node_allowed_mrtd": [measurement],
                "node_allowed_rtmr0": ["cd".repeat(48)],
                "node_allowed_rtmr1": ["ef".repeat(48)],
                "node_allowed_rtmr2": ["01".repeat(48)],
                "node_allowed_rtmr3": ["23".repeat(48)]
            }
        });
        let err = Config::parse_policy_json(
            &policy_json.to_string(),
            "2.1.38",
            "locked-read-only",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Policy profile mismatch"));
    }

    #[test]
    fn parse_policy_json_allows_locked_legacy_missing_profile() {
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
        let parsed =
            Config::parse_policy_json(&policy_json.to_string(), "2.1.38", "locked-read-only", true)
                .expect("legacy locked-read-only policy should parse");
        assert_eq!(parsed.allowed_mrtd, vec!["aa".repeat(48)]);
    }

    #[test]
    fn parse_policy_json_rejects_non_kms_role() {
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
        let err = Config::parse_policy_json(
            &policy_json.to_string(),
            "2.1.38",
            "locked-read-only",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Policy role mismatch"));
    }
}
