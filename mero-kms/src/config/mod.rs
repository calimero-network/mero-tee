//! Service configuration and release-policy loading.
//!
//! # Environment Variables
//!
//! | Variable | Type | Default | Description |
//! |---|---|---|---|
//! | `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:8080` | HTTP listen address |
//! | `DSTACK_SOCKET_PATH` | `String` | `/var/run/dstack.sock` | Path to dstack Unix socket |
//! | `CHALLENGE_TTL_SECS` | `u64` | `60` | Challenge nonce time-to-live in seconds |
//! | `MAX_PENDING_CHALLENGES` | `usize` | `10000` | Maximum concurrent pending challenges |
//! | `ACCEPT_MOCK_ATTESTATION` | `bool` | `false` | Accept mock quotes (dev only, **never** in production) |
//! | `REDIS_URL` | `String` | *(none — in-memory)* | Redis URL for shared challenge store |
//! | `MERO_KMS_VERSION` | `String` | *(none)* | Release version for policy fetch (e.g. `2.3.4` or `mero-kms-v2.3.4`) |
//! | `MERO_KMS_PROFILE` | `String` | `locked-read-only` | KMS profile cohort (overrides `KMS_POLICY_PROFILE`) |
//! | `KMS_POLICY_PROFILE` | `String` | *(deprecated)* | Legacy alias for `MERO_KMS_PROFILE` |
//! | `KEY_NAMESPACE_PREFIX` | `String` | `merod/storage` | dstack key derivation namespace prefix |
//! | `MERO_KMS_POLICY_SHA256` | `String` | *(none)* | Optional SHA-256 pin for fetched policy file |
//! | `CORS_ALLOWED_ORIGINS` | `CSV` | *(none — CORS disabled)* | Comma-separated allowed CORS origins |
//! | `ENFORCE_MEASUREMENT_POLICY` | `bool` | `true` | Whether TDX measurement checks are enforced |
//! | `USE_ENV_POLICY` | `bool` | `false` | Load policy from `ALLOWED_*` env vars instead of release |
//! | `ALLOWED_TCB_STATUSES` | `CSV` | `uptodate` | Allowed TCB status values (when `USE_ENV_POLICY=true`) |
//! | `ALLOWED_MRTD` | `CSV` | *(empty)* | Allowed MRTD hex values (when `USE_ENV_POLICY=true`) |
//! | `ALLOWED_RTMR0` | `CSV` | *(empty)* | Allowed RTMR0 hex values (when `USE_ENV_POLICY=true`) |
//! | `ALLOWED_RTMR1` | `CSV` | *(empty)* | Allowed RTMR1 hex values (when `USE_ENV_POLICY=true`) |
//! | `ALLOWED_RTMR2` | `CSV` | *(empty)* | Allowed RTMR2 hex values (when `USE_ENV_POLICY=true`) |
//! | `ALLOWED_RTMR3` | `CSV` | *(empty)* | Allowed RTMR3 hex values (when `USE_ENV_POLICY=true`) |

pub mod env;
pub mod policy_loader;

use std::net::SocketAddr;

use eyre::{bail, Result as EyreResult};

use crate::policy::{validate_policy_requirements, AttestationPolicy};

use self::env::{
    normalize_hash_pin, parse_bool_env, parse_csv_env, parse_measurement_list_env, read_env_utf8,
};
use self::policy_loader::fetch_policy_from_release;

const KNOWN_PROFILES: [&str; 3] = ["debug", "debug-read-only", "locked-read-only"];
const IMAGE_PROFILE_PATH: &str = "/etc/mero-kms/image-profile";

/// Configuration for the key releaser service.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen address (default `0.0.0.0:8080`).
    pub listen_addr: SocketAddr,
    /// Path to the dstack Unix socket for key derivation and quote generation.
    pub dstack_socket_path: String,
    /// How long a challenge nonce remains valid (seconds).
    pub challenge_ttl_secs: u64,
    /// Maximum number of concurrent pending challenges before rate-limiting.
    pub max_pending_challenges: usize,
    /// Accept mock TDX quotes (development only, **never** in production).
    pub accept_mock_attestation: bool,
    /// Optional Redis URL for shared challenge storage across instances.
    pub redis_url: Option<String>,
    /// KMS profile cohort (e.g. `locked-read-only`, `debug`).
    pub kms_profile: String,
    /// Namespace prefix for dstack key derivation paths.
    pub key_namespace_prefix: String,
    /// Optional SHA-256 hex pin for the fetched policy file.
    pub policy_sha256: Option<String>,
    /// Comma-separated allowed CORS origins; empty means CORS is disabled.
    pub cors_allowed_origins: Vec<String>,
    /// Loaded attestation policy with measurement allowlists and TCB status rules.
    pub attestation_policy: AttestationPolicy,
    /// Whether the attestation policy is loaded and ready for key release.
    pub policy_ready: bool,
    /// Human-readable reason when `policy_ready` is `false`.
    pub policy_unavailable_reason: Option<String>,
    /// Release version used for policy fetch (e.g. `"2.3.4"`).
    pub kms_version: Option<String>,
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
            policy_ready: true,
            policy_unavailable_reason: None,
            kms_version: None,
        }
    }
}

impl Config {
    /// Load runtime configuration from process environment.
    pub async fn from_env() -> EyreResult<Self> {
        Self::from_env_with_image_profile_path(IMAGE_PROFILE_PATH).await
    }

    /// Internal loader that allows overriding image-profile path for tests.
    async fn from_env_with_image_profile_path(image_profile_path: &str) -> EyreResult<Self> {
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

        let pinned_image_profile = read_image_profile_from_file(image_profile_path)?;
        let env_profile_override = profile_override_from_env()?;
        let kms_profile = resolve_kms_profile(
            pinned_image_profile.as_deref(),
            env_profile_override.as_deref(),
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

        let cors_allowed_origins = parse_csv_env("CORS_ALLOWED_ORIGINS", false).unwrap_or_default();

        let enforce_measurement_policy = parse_bool_env("ENFORCE_MEASUREMENT_POLICY", true)?;
        let use_env_policy = parse_bool_env("USE_ENV_POLICY", false)?;

        let release_version = if use_env_policy {
            None
        } else {
            Self::release_version_from_env()?
        };

        let (mut attestation_policy, policy_ready, policy_unavailable_reason) =
            resolve_attestation_policy(
                use_env_policy,
                release_version.as_deref(),
                &kms_profile,
                policy_sha256.as_deref(),
            )
            .await?;
        attestation_policy.enforce_measurement_policy = enforce_measurement_policy;
        if policy_ready {
            validate_policy_requirements(&attestation_policy, accept_mock_attestation)?;
        }

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
            policy_ready,
            policy_unavailable_reason,
            kms_version: release_version,
        })
    }

    fn release_version_from_env() -> EyreResult<Option<String>> {
        match std::env::var("MERO_KMS_VERSION") {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    bail!("MERO_KMS_VERSION cannot be empty");
                }
                Ok(Some(
                    trimmed
                        .strip_prefix("mero-kms-v")
                        .unwrap_or(trimmed)
                        .to_string(),
                ))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => bail!("MERO_KMS_VERSION must be valid UTF-8"),
        }
    }
}

/// Determine the attestation policy source (env vars vs. GitHub release) and load it.
/// Returns a default empty policy with `policy_ready=false` when the version is not
/// yet set, allowing the service to start in degraded mode (/attest works, /get-key is blocked).
async fn resolve_attestation_policy(
    use_env_policy: bool,
    release_version: Option<&str>,
    kms_profile: &str,
    policy_sha256: Option<&str>,
) -> EyreResult<(AttestationPolicy, bool, Option<String>)> {
    if use_env_policy {
        return Ok((load_policy_from_env()?, true, None));
    }
    if let Some(version) = release_version {
        match fetch_policy_from_release(version, kms_profile, policy_sha256).await {
            Ok(policy) => {
                tracing::info!(
                    "Loaded attestation policy from release mero-kms-v{} profile {}",
                    version,
                    kms_profile
                );
                Ok((policy, true, None))
            }
            Err(err) => {
                let reason = format!(
                    "Failed to load release policy for version '{}' profile '{}': {}",
                    version, kms_profile, err
                );
                tracing::warn!("{reason}");
                Ok((AttestationPolicy::default(), false, Some(reason)))
            }
        }
    } else {
        let reason = "MERO_KMS_VERSION is not set; release policy is not available yet".to_string();
        tracing::warn!("{reason}");
        Ok((AttestationPolicy::default(), false, Some(reason)))
    }
}

fn load_policy_from_env() -> EyreResult<AttestationPolicy> {
    Ok(AttestationPolicy {
        enforce_measurement_policy: true,
        allowed_tcb_statuses: parse_csv_env("ALLOWED_TCB_STATUSES", true)
            .unwrap_or_else(|| vec!["uptodate".to_string()]),
        allowed_mrtd: parse_measurement_list_env("ALLOWED_MRTD")?,
        allowed_rtmr0: parse_measurement_list_env("ALLOWED_RTMR0")?,
        allowed_rtmr1: parse_measurement_list_env("ALLOWED_RTMR1")?,
        allowed_rtmr2: parse_measurement_list_env("ALLOWED_RTMR2")?,
        allowed_rtmr3: parse_measurement_list_env("ALLOWED_RTMR3")?,
    })
}

/// Read the KMS profile from env, handling the deprecated `KMS_POLICY_PROFILE`
/// alias. If both are set they must agree; if only the legacy name is set a
/// deprecation warning is emitted.
fn profile_override_from_env() -> EyreResult<Option<String>> {
    let modern = read_env_utf8("MERO_KMS_PROFILE")?;
    let legacy = read_env_utf8("KMS_POLICY_PROFILE")?;

    if let Some(modern_profile) = modern {
        if let Some(legacy_profile) = legacy.as_deref() {
            if !modern_profile
                .trim()
                .eq_ignore_ascii_case(legacy_profile.trim())
            {
                bail!(
                    "MERO_KMS_PROFILE and legacy KMS_POLICY_PROFILE disagree; set only MERO_KMS_PROFILE"
                );
            }
        }
        return Ok(Some(modern_profile));
    }

    if legacy.is_some() {
        tracing::warn!(
            "KMS_POLICY_PROFILE is deprecated; use MERO_KMS_PROFILE for new deployments"
        );
    }
    Ok(legacy)
}

/// Read and validate the image-pinned policy profile, if present.
fn read_image_profile_from_file(image_profile_path: &str) -> EyreResult<Option<String>> {
    match std::fs::read_to_string(image_profile_path) {
        Ok(raw) => {
            let value = raw.trim();
            if value.is_empty() {
                bail!(
                    "Pinned KMS image profile file {} is empty; refusing startup",
                    image_profile_path
                );
            }
            parse_profile(value).map(Some)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => bail!(
            "Failed to read pinned KMS image profile from {}: {}",
            image_profile_path,
            err
        ),
    }
}

/// Resolve effective KMS policy profile:
/// if image profile is pinned, env override must match the pinned profile.
fn resolve_kms_profile(
    pinned_profile: Option<&str>,
    env_override: Option<&str>,
) -> EyreResult<String> {
    if let Some(pinned) = pinned_profile {
        let pinned_profile = parse_profile(pinned)?;
        if let Some(override_raw) = env_override {
            let override_profile = parse_profile(override_raw)?;
            if override_profile != pinned_profile {
                bail!(
                    "MERO_KMS_PROFILE '{}' does not match profile-pinned image value '{}'. \
                     Build/deploy the matching KMS image profile instead.",
                    override_profile,
                    pinned_profile
                );
            }
        }
        return Ok(pinned_profile);
    }

    parse_profile(
        env_override
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("locked-read-only"),
    )
}

/// Normalize and validate a KMS profile name against the known set.
/// Used both at config load time and when parsing policy JSON.
pub fn parse_profile(raw: &str) -> EyreResult<String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        bail!("KMS policy profile cannot be empty");
    }
    if KNOWN_PROFILES.contains(&value.as_str()) {
        Ok(value)
    } else {
        bail!(
            "Unsupported KMS policy profile '{}'. Expected one of: {}",
            value,
            KNOWN_PROFILES.join(", ")
        )
    }
}

/// Log all resolved configuration values at startup.
pub fn log_startup_config(config: &Config) {
    use tracing::{info, warn};

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
    if let Some(kms_version) = config.kms_version.as_deref() {
        info!("Policy release version: {}", kms_version);
    }
    info!("Policy ready for key issuance: {}", config.policy_ready);
    if !config.policy_ready {
        warn!(
            "Policy unavailable; /attest remains available but /get-key is fail-closed: {}",
            config
                .policy_unavailable_reason
                .as_deref()
                .unwrap_or("unknown policy readiness error")
        );
    }
    info!(
        "Measurement policy enforced: {}",
        config.attestation_policy.enforce_measurement_policy
    );
    if !config.attestation_policy.enforce_measurement_policy {
        warn!("Measurement policy enforcement is disabled; this is not safe for production");
    }
    if config.policy_ready {
        info!(
            "Policy entries: tcb_statuses={}, mrtd={}, rtmr0={}, rtmr1={}, rtmr2={}, rtmr3={}",
            config.attestation_policy.allowed_tcb_statuses.len(),
            config.attestation_policy.allowed_mrtd.len(),
            config.attestation_policy.allowed_rtmr0.len(),
            config.attestation_policy.allowed_rtmr1.len(),
            config.attestation_policy.allowed_rtmr2.len(),
            config.attestation_policy.allowed_rtmr3.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config::policy_loader::policy_candidate_urls;
    use crate::test_util::{valid_measurement_hex, ENV_KEYS};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        previous: HashMap<String, Option<String>>,
    }

    impl EnvGuard {
        fn apply(overrides: &[(&str, &str)]) -> Self {
            let mut previous = HashMap::new();
            for key in ENV_KEYS {
                previous.insert((*key).to_string(), std::env::var(key).ok());
                std::env::remove_var(key);
            }
            for (key, value) in overrides {
                std::env::set_var(key, value);
            }
            Self { previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    struct TempProfileFile {
        path: PathBuf,
    }

    impl TempProfileFile {
        fn new(contents: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos();
            path.push(format!("mero-kms-profile-{}.txt", unique));
            std::fs::write(&path, contents).expect("should write temp profile file");
            Self { path }
        }

        fn as_str(&self) -> &str {
            self.path
                .to_str()
                .expect("temp profile path should be valid utf-8")
        }
    }

    impl Drop for TempProfileFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn valid_env_policy_overrides() -> Vec<(&'static str, String)> {
        let measurement = valid_measurement_hex();
        vec![
            ("USE_ENV_POLICY", "true".to_string()),
            ("ALLOWED_TCB_STATUSES", "uptodate".to_string()),
            ("ALLOWED_MRTD", measurement.clone()),
            ("ALLOWED_RTMR0", measurement.clone()),
            ("ALLOWED_RTMR1", measurement.clone()),
            ("ALLOWED_RTMR2", measurement.clone()),
            ("ALLOWED_RTMR3", measurement),
        ]
    }

    fn apply_string_overrides(overrides: Vec<(&'static str, String)>) -> EnvGuard {
        let owned: Vec<(&str, &str)> = overrides.iter().map(|(k, v)| (*k, v.as_str())).collect();
        EnvGuard::apply(&owned)
    }

    #[test]
    fn resolve_kms_profile_uses_pinned_profile() {
        let selected =
            resolve_kms_profile(Some("debug-read-only"), None).expect("profile resolves");
        assert_eq!(selected, "debug-read-only");
    }

    #[test]
    fn release_version_reads_mero_kms_version_env() {
        let _lock = env_lock().lock().expect("env lock");
        let _guard =
            apply_string_overrides(vec![("MERO_KMS_VERSION", "mero-kms-v2.3.4".to_string())]);
        let version = Config::release_version_from_env()
            .expect("release version")
            .expect("version should be present");
        assert_eq!(version, "2.3.4");
    }

    #[test]
    fn policy_candidate_urls_include_profile_and_generic_fallback() {
        let urls = policy_candidate_urls("2.3.4", "debug-read-only");
        assert_eq!(urls.len(), 2);
        assert!(urls[0]
            .url
            .ends_with("/mero-kms-v2.3.4/kms-phala-attestation-policy.debug-read-only.json"));
        assert!(!urls[0].is_legacy_fallback);
        assert!(urls[1]
            .url
            .ends_with("/mero-kms-v2.3.4/kms-phala-attestation-policy.json"));
        assert!(urls[1].is_legacy_fallback);
    }

    #[test]
    fn resolve_kms_profile_allows_matching_override_for_pinned_image() {
        let selected = resolve_kms_profile(Some("locked-read-only"), Some("locked-read-only"))
            .expect("matching override should be accepted for pinned profile");
        assert_eq!(selected, "locked-read-only");
    }

    #[test]
    fn resolve_kms_profile_rejects_mismatched_override_for_pinned_image() {
        let err = resolve_kms_profile(Some("locked-read-only"), Some("debug"))
            .expect_err("mismatched override should be rejected for pinned profile");
        assert!(err
            .to_string()
            .contains("does not match profile-pinned image value"));
    }

    #[test]
    fn resolve_kms_profile_allows_env_profile_without_pinned_image() {
        let selected = resolve_kms_profile(None, Some("debug")).expect("profile resolves");
        assert_eq!(selected, "debug");
    }

    #[test]
    fn read_image_profile_from_file_rejects_empty_file() {
        let temp = TempProfileFile::new("\n");
        let err = read_image_profile_from_file(temp.as_str())
            .expect_err("empty pinned profile file should fail");
        assert!(err.to_string().contains("is empty; refusing startup"));
    }

    #[test]
    fn from_env_accepts_env_policy_mode_with_valid_allowlists() {
        let _lock = env_lock().lock().expect("env lock");
        let _guard = apply_string_overrides(valid_env_policy_overrides());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let config = runtime
            .block_on(Config::from_env_with_image_profile_path(
                "/tmp/nonexistent-kms-profile",
            ))
            .expect("env-policy mode should load");
        assert_eq!(config.kms_profile, "locked-read-only");
        assert_eq!(config.attestation_policy.allowed_mrtd.len(), 1);
        assert_eq!(config.attestation_policy.allowed_rtmr3.len(), 1);
        assert!(config.policy_ready);
    }

    #[test]
    fn from_env_use_env_policy_ignores_release_version_without_hash_pin() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("MERO_KMS_VERSION", "2.9.9".to_string()));
        let _guard = apply_string_overrides(overrides);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let config = runtime
            .block_on(Config::from_env_with_image_profile_path(
                "/tmp/nonexistent-kms-profile",
            ))
            .expect("env-policy mode should not require MERO_KMS_POLICY_SHA256");
        assert_eq!(config.kms_profile, "locked-read-only");
        assert!(config.policy_ready);
    }

    #[test]
    fn from_env_without_release_version_marks_policy_unavailable() {
        let _lock = env_lock().lock().expect("env lock");
        let _guard = apply_string_overrides(vec![]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let config = runtime
            .block_on(Config::from_env_with_image_profile_path(
                "/tmp/nonexistent-kms-profile",
            ))
            .expect("missing version should not prevent startup");
        assert!(!config.policy_ready);
        assert_eq!(config.kms_version, None);
        assert!(config
            .policy_unavailable_reason
            .as_deref()
            .unwrap_or_default()
            .contains("MERO_KMS_VERSION"));
    }

    #[test]
    fn from_env_rejects_malformed_measurement_list() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        for (key, value) in &mut overrides {
            if *key == "ALLOWED_MRTD" {
                *value = "zzzz".to_string();
            }
        }
        let _guard = apply_string_overrides(overrides);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = runtime
            .block_on(Config::from_env_with_image_profile_path(
                "/tmp/nonexistent-kms-profile",
            ))
            .expect_err("malformed ALLOWED_MRTD should fail");
        assert!(err.to_string().contains("expected 48 bytes"));
    }

    #[test]
    fn from_env_rejects_override_when_profile_is_pinned() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("MERO_KMS_PROFILE", "debug".to_string()));
        let _guard = apply_string_overrides(overrides);
        let profile_file = TempProfileFile::new("locked-read-only\n");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = runtime
            .block_on(Config::from_env_with_image_profile_path(
                profile_file.as_str(),
            ))
            .expect_err("pinned image should reject MERO_KMS_PROFILE override");
        assert!(err
            .to_string()
            .contains("does not match profile-pinned image value"));
    }

    #[test]
    fn profile_override_prefers_modern_env_name() {
        let _lock = env_lock().lock().expect("env lock");
        let _guard = apply_string_overrides(vec![
            ("MERO_KMS_PROFILE", "debug-read-only".to_string()),
            ("KMS_POLICY_PROFILE", "debug-read-only".to_string()),
        ]);
        let selected = profile_override_from_env()
            .expect("profile override should parse")
            .expect("override should exist");
        assert_eq!(selected, "debug-read-only");
    }
}
