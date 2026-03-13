//! mero-kms-phala: Key management service for merod nodes running in Phala Cloud TEE.
//!
//! This service validates TDX attestations from merod nodes and releases deterministic
//! storage encryption keys based on peer ID using Phala's dstack key derivation.

mod handlers;

use std::net::SocketAddr;

use eyre::{bail, Result as EyreResult};
use tower_http::cors::{Any, CorsLayer};
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
    /// Whether to accept mock attestations (for development only).
    pub accept_mock_attestation: bool,
    /// Attestation policy used for key release decisions.
    pub attestation_policy: AttestationPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            dstack_socket_path: "/var/run/dstack.sock".to_string(),
            challenge_ttl_secs: 60,
            accept_mock_attestation: false,
            attestation_policy: AttestationPolicy::default(),
        }
    }
}

const POLICY_RELEASE_BASE: &str = "https://github.com/calimero-network/mero-tee/releases/download";

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

        let accept_mock_attestation = std::env::var("ACCEPT_MOCK_ATTESTATION")
            .map(|v| parse_bool_flag(&v))
            .unwrap_or(false);

        let enforce_measurement_policy = std::env::var("ENFORCE_MEASUREMENT_POLICY")
            .map(|v| parse_bool_flag(&v))
            .unwrap_or(true);

        let use_env_policy = std::env::var("USE_ENV_POLICY")
            .map(|v| parse_bool_flag(&v))
            .unwrap_or(false);

        let mut attestation_policy = if use_env_policy {
            Self::load_policy_from_env()?
        } else if let Some(version) = Self::release_version_from_env() {
            match Self::fetch_policy_from_release_async(&version).await {
                Ok(policy) => {
                    tracing::info!(
                        "Loaded attestation policy from release mero-kms-v{}",
                        version
                    );
                    policy
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch policy from release ({}): {}. Falling back to env vars.",
                        version,
                        e
                    );
                    Self::load_policy_from_env()?
                }
            }
        } else {
            Self::load_policy_from_env()?
        };
        attestation_policy.enforce_measurement_policy = enforce_measurement_policy;

        if enforce_measurement_policy
            && !accept_mock_attestation
            && attestation_policy.allowed_tcb_statuses.is_empty()
        {
            bail!(
                "Measurement policy is enforced, but ALLOWED_TCB_STATUSES is empty. \
                 Configure at least one allowed status (recommended: UpToDate)."
            );
        }

        if enforce_measurement_policy
            && !accept_mock_attestation
            && attestation_policy.allowed_mrtd.is_empty()
        {
            bail!(
                "Measurement policy is enforced, but ALLOWED_MRTD is empty. \
                 Set MERO_KMS_VERSION to fetch from release, or USE_ENV_POLICY=true with ALLOWED_MRTD for air-gapped."
            );
        }

        Ok(Self {
            listen_addr,
            dstack_socket_path,
            challenge_ttl_secs,
            accept_mock_attestation,
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

    async fn fetch_policy_from_release_async(version: &str) -> EyreResult<AttestationPolicy> {
        let tag = format!("mero-kms-v{}", version.trim());
        let url = format!(
            "{}/{}/kms-phala-attestation-policy.json",
            POLICY_RELEASE_BASE, tag
        );
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("mero-kms-phala/1.0")
            .build()
            .map_err(|e| eyre::eyre!("Failed to create HTTP client: {}", e))?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| eyre::eyre!("Policy fetch failed: {}", e))?;
        if !resp.status().is_success() {
            bail!("Policy fetch failed: {} {}", resp.status(), url);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| eyre::eyre!("Failed to read policy response: {}", e))?;
        Self::parse_policy_json(&body)
    }

    fn parse_policy_json(json_str: &str) -> EyreResult<AttestationPolicy> {
        let root: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| eyre::eyre!("Invalid policy JSON: {}", e))?;
        let policy = root
            .get("policy")
            .and_then(|v| v.as_object())
            .ok_or_else(|| eyre::eyre!("Policy JSON missing 'policy' object"))?;

        // KMS verifies nodes; use node_allowed_* (fallback to allowed_* for legacy)
        let allowed_tcb_statuses = parse_json_string_array(policy, "node_allowed_tcb_statuses")
            .or_else(|| parse_json_string_array(policy, "allowed_tcb_statuses"))
            .unwrap_or_else(|| vec!["uptodate".to_owned()]);
        let node_mrtd = parse_json_hex_array(policy, "node_allowed_mrtd", 48)?;
        let allowed_mrtd = if node_mrtd.is_empty() {
            parse_json_hex_array(policy, "allowed_mrtd", 48)?
        } else {
            node_mrtd
        };
        let node_rtmr0 = parse_json_hex_array(policy, "node_allowed_rtmr0", 48)?;
        let allowed_rtmr0 = if node_rtmr0.is_empty() {
            parse_json_hex_array(policy, "allowed_rtmr0", 48)?
        } else {
            node_rtmr0
        };
        let node_rtmr1 = parse_json_hex_array(policy, "node_allowed_rtmr1", 48)?;
        let allowed_rtmr1 = if node_rtmr1.is_empty() {
            parse_json_hex_array(policy, "allowed_rtmr1", 48)?
        } else {
            node_rtmr1
        };
        let node_rtmr2 = parse_json_hex_array(policy, "node_allowed_rtmr2", 48)?;
        let allowed_rtmr2 = if node_rtmr2.is_empty() {
            parse_json_hex_array(policy, "allowed_rtmr2", 48)?
        } else {
            node_rtmr2
        };
        let node_rtmr3 = parse_json_hex_array(policy, "node_allowed_rtmr3", 48)?;
        let allowed_rtmr3 = if node_rtmr3.is_empty() {
            parse_json_hex_array(policy, "allowed_rtmr3", 48)?
        } else {
            node_rtmr3
        };

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

fn parse_bool_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
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
    info!(
        "Accept mock attestation: {}",
        config.accept_mock_attestation
    );
    info!(
        "Measurement policy enforced: {}",
        config.attestation_policy.enforce_measurement_policy
    );
    if !config.attestation_policy.enforce_measurement_policy {
        tracing::warn!("Measurement policy enforcement is disabled; this is not safe for production");
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
    let app = create_router(config.clone())
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Start server
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
