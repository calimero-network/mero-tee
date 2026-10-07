//! Service configuration, read once from the environment at startup.
//!
//! Everything here is baked into the image (`kms.env`) and so is part of its
//! measurements; nothing comes from instance metadata. The node allowlist in
//! particular is the image's own: there is no other source to fall back to, and
//! startup fails when it is incomplete.
//!
//! # Environment Variables
//!
//! | Variable | Type | Default | Description |
//! |---|---|---|---|
//! | `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:8080` | HTTP listen address |
//! | `CHALLENGE_TTL_SECS` | `u64` | `60` | How long a `/challenge` token stays valid, in seconds |
//! | `MAX_CONSUMED_CHALLENGES` | `usize` | `10000` | How many used, unexpired challenges one replica remembers to refuse their replay. When full, `/get-key` answers 429 |
//! | `ACCEPT_MOCK_ATTESTATION` | `bool` | `false` | Accept mock quotes (dev only, **never** in production). Only read when built with the default-off `mock-attestation` feature; ignored otherwise. |
//! | `MERO_KMS_PROFILE` | `String` | `locked-read-only` | KMS profile cohort (overrides `KMS_POLICY_PROFILE`); must match `/etc/mero-kms/image-profile` when that exists |
//! | `KMS_POLICY_PROFILE` | `String` | *(deprecated)* | Legacy alias for `MERO_KMS_PROFILE` |
//! | `KEY_NAMESPACE_PREFIX` | `String` | `merod/storage` | Namespace prefix of node key derivation paths |
//! | `AGENT_KEY_NAMESPACE_PREFIX` | `String` | `mero-agent/storage` | Namespace prefix of agent key derivation paths; must differ from `KEY_NAMESPACE_PREFIX` |
//! | `CORS_ALLOWED_ORIGINS` | `CSV` | *(none — CORS disabled)* | Comma-separated allowed CORS origins |
//! | `ENFORCE_MEASUREMENT_POLICY` | `bool` | `true` | Whether node TDX measurement checks are enforced |
//! | `MERO_KMS_REQUIRE_SEALED_KEY_RELEASE` | `bool` | `true` | Refuse `/get-key` requests that do not ask for a sealed key |
//! | `ALLOWED_TCB_STATUSES` | `CSV` | `uptodate` | Allowed TCB statuses, for nodes and for peer replicas |
//! | `ALLOWED_MRTD` | `CSV` | *(empty)* | Allowed node MRTD hex values; required when enforcing |
//! | `ALLOWED_RTMR0` | `CSV` | *(empty)* | Allowed node RTMR0 hex values; required when enforcing |
//! | `ALLOWED_RTMR1` | `CSV` | *(empty)* | Allowed node RTMR1 hex values; required when enforcing |
//! | `ALLOWED_RTMR2` | `CSV` | *(empty)* | Allowed node RTMR2 hex values; required when enforcing |
//! | `ALLOWED_RTMR3` | `CSV` | *(empty)* | Allowed node RTMR3 hex values; required when enforcing |
//! | `AGENT_ALLOWED_MRTD` | `CSV` | *(empty)* | Allowed agent MRTD hex values. The five `AGENT_ALLOWED_*` are set together or not at all; unset, no agent is served |
//! | `AGENT_ALLOWED_RTMR0` | `CSV` | *(empty)* | Allowed agent RTMR0 hex values |
//! | `AGENT_ALLOWED_RTMR1` | `CSV` | *(empty)* | Allowed agent RTMR1 hex values |
//! | `AGENT_ALLOWED_RTMR2` | `CSV` | *(empty)* | Allowed agent RTMR2 hex values |
//! | `AGENT_ALLOWED_RTMR3` | `CSV` | *(empty)* | Allowed agent RTMR3 hex values |
//! | `MERO_KMS_BOOTSTRAP` | `bool` | `false` | Generate the cluster's root instead of joining. Set on exactly one replica, once |
//! | `MERO_KMS_PEERS` | `CSV` | *(empty)* | Base URLs of replicas to join from. Untrusted: a wrong one only fails a join. Required unless `MERO_KMS_BOOTSTRAP=true` |
//! | `MERO_KMS_JOIN_RETRY_SECS` | `u64` | `10` | Pause between rounds of join attempts |

pub mod env;

use std::net::SocketAddr;

use eyre::{bail, Result as EyreResult};

use crate::policy::{validate_policy_requirements, AttestationPolicy, PolicyEntry, Role};

use self::env::{parse_bool_env, parse_csv_env, parse_measurement_list_env, read_env_utf8};

const KNOWN_PROFILES: [&str; 3] = ["debug", "debug-read-only", "locked-read-only"];
const IMAGE_PROFILE_PATH: &str = "/etc/mero-kms/image-profile";

/// Configuration for the key releaser service.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen address (default `0.0.0.0:8080`).
    pub listen_addr: SocketAddr,
    /// How long a challenge token remains valid (seconds).
    pub challenge_ttl_secs: u64,
    /// How many used, unexpired challenges one replica remembers.
    pub max_consumed_challenges: usize,
    /// Accept mock TDX quotes (development only, **never** in production).
    ///
    /// Only present under the default-off `mock-attestation` feature; the
    /// production build has no such knob.
    #[cfg(feature = "mock-attestation")]
    pub accept_mock_attestation: bool,
    /// KMS profile cohort (e.g. `locked-read-only`, `debug`).
    pub kms_profile: String,
    /// Namespace prefix of node key derivation paths.
    pub key_namespace_prefix: String,
    /// Namespace prefix of agent key derivation paths. Distinct from
    /// `key_namespace_prefix`, so no agent can be released a node's key.
    pub agent_key_namespace_prefix: String,
    /// Comma-separated allowed CORS origins; empty means CORS is disabled.
    pub cors_allowed_origins: Vec<String>,
    /// The node and agent allowlists baked into the image, with TCB status rules.
    pub attestation_policy: AttestationPolicy,
    /// Refuse `/get-key` requests that do not ask for a sealed key
    /// (`MERO_KMS_REQUIRE_SEALED_KEY_RELEASE`, default `true`). An unsealed key
    /// is readable by whatever terminates TLS in front of this service. Setting
    /// it `false` serves merods older than 0.11.0-rc.47, which cannot unseal,
    /// and reopens that hole for them.
    pub require_sealed_key_release: bool,
    /// Generate the cluster's root instead of joining.
    pub kms_bootstrap: bool,
    /// Base URLs of replicas to join from.
    pub cluster_peers: Vec<String>,
    /// Pause between rounds of join attempts, in seconds.
    pub join_retry_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            challenge_ttl_secs: 60,
            max_consumed_challenges: 10_000,
            #[cfg(feature = "mock-attestation")]
            accept_mock_attestation: false,
            kms_profile: "locked-read-only".to_string(),
            key_namespace_prefix: "merod/storage".to_string(),
            agent_key_namespace_prefix: "mero-agent/storage".to_string(),
            cors_allowed_origins: Vec::new(),
            attestation_policy: AttestationPolicy::default(),
            require_sealed_key_release: true,
            kms_bootstrap: false,
            cluster_peers: Vec::new(),
            join_retry_secs: 10,
        }
    }
}

impl Config {
    /// Load runtime configuration from process environment.
    pub fn from_env() -> EyreResult<Self> {
        Self::from_env_with_image_profile_path(IMAGE_PROFILE_PATH)
    }

    /// Internal loader that allows overriding image-profile path for tests.
    fn from_env_with_image_profile_path(image_profile_path: &str) -> EyreResult<Self> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));

        let challenge_ttl_secs = std::env::var("CHALLENGE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let max_consumed_challenges = std::env::var("MAX_CONSUMED_CHALLENGES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10_000);
        if max_consumed_challenges == 0 {
            bail!("MAX_CONSUMED_CHALLENGES must be greater than 0");
        }

        #[cfg(feature = "mock-attestation")]
        let accept_mock_attestation = parse_bool_env("ACCEPT_MOCK_ATTESTATION", false)?;

        let pinned_image_profile = read_image_profile_from_file(image_profile_path)?;
        let env_profile_override = profile_override_from_env()?;
        let kms_profile = resolve_kms_profile(
            pinned_image_profile.as_deref(),
            env_profile_override.as_deref(),
        )?;

        let key_namespace_prefix = key_prefix_from_env("KEY_NAMESPACE_PREFIX", "merod/storage");
        let agent_key_namespace_prefix =
            key_prefix_from_env("AGENT_KEY_NAMESPACE_PREFIX", "mero-agent/storage");
        // Key paths are `{prefix}/{profile}/{peerId}` with a slash-free peer ID,
        // so only an equal prefix could give an agent and a node the same path.
        if agent_key_namespace_prefix == key_namespace_prefix {
            bail!(
                "AGENT_KEY_NAMESPACE_PREFIX must differ from KEY_NAMESPACE_PREFIX \
                 ('{key_namespace_prefix}'), or an agent could be released a node's key"
            );
        }

        let cors_allowed_origins = parse_csv_env("CORS_ALLOWED_ORIGINS", false).unwrap_or_default();

        let require_sealed_key_release =
            parse_bool_env("MERO_KMS_REQUIRE_SEALED_KEY_RELEASE", true)?;
        let (kms_bootstrap, cluster_peers, join_retry_secs) = cluster_from_env()?;

        let mut attestation_policy = load_policy_from_env()?;
        attestation_policy.enforce_measurement_policy =
            parse_bool_env("ENFORCE_MEASUREMENT_POLICY", true)?;
        validate_policy_requirements(
            &attestation_policy,
            #[cfg(feature = "mock-attestation")]
            accept_mock_attestation,
        )?;

        Ok(Self {
            listen_addr,
            challenge_ttl_secs,
            max_consumed_challenges,
            #[cfg(feature = "mock-attestation")]
            accept_mock_attestation,
            kms_profile,
            key_namespace_prefix,
            agent_key_namespace_prefix,
            cors_allowed_origins,
            attestation_policy,
            require_sealed_key_release,
            kms_bootstrap,
            cluster_peers,
            join_retry_secs,
        })
    }
}

/// Read the cluster settings. A replica with neither bootstrap nor peers could
/// never get a root, so it refuses to start.
fn cluster_from_env() -> EyreResult<(bool, Vec<String>, u64)> {
    let kms_bootstrap = parse_bool_env("MERO_KMS_BOOTSTRAP", false)?;
    let cluster_peers = parse_csv_env("MERO_KMS_PEERS", false).unwrap_or_default();
    let join_retry_secs = std::env::var("MERO_KMS_JOIN_RETRY_SECS")
        .ok()
        .map(|v| v.trim().parse::<u64>())
        .transpose()
        .map_err(|e| eyre::eyre!("MERO_KMS_JOIN_RETRY_SECS: {e}"))?
        .unwrap_or(10)
        .max(1);
    if !kms_bootstrap && cluster_peers.is_empty() {
        bail!("set MERO_KMS_BOOTSTRAP=true or MERO_KMS_PEERS");
    }
    Ok((kms_bootstrap, cluster_peers, join_retry_secs))
}

/// A key namespace prefix without surrounding slashes, or `default`.
fn key_prefix_from_env(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|v| v.trim_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// The allowlists baked into the image: always the node entry from
/// `ALLOWED_*`, and an agent entry from `AGENT_ALLOWED_*` when those are set.
fn load_policy_from_env() -> EyreResult<AttestationPolicy> {
    let mut entries = vec![entry_from_env(Role::Node, "")?];
    if let Some(agent) = optional_entry_from_env(Role::Agent, "AGENT_")? {
        entries.push(agent);
    }
    Ok(AttestationPolicy {
        enforce_measurement_policy: true,
        allowed_tcb_statuses: parse_csv_env("ALLOWED_TCB_STATUSES", true)
            .unwrap_or_else(|| vec!["uptodate".to_string()]),
        entries,
    })
}

fn entry_from_env(role: Role, env_prefix: &str) -> EyreResult<PolicyEntry> {
    let list =
        |register: &str| parse_measurement_list_env(&format!("{env_prefix}ALLOWED_{register}"));
    Ok(PolicyEntry {
        role,
        allowed_mrtd: list("MRTD")?,
        allowed_rtmr0: list("RTMR0")?,
        allowed_rtmr1: list("RTMR1")?,
        allowed_rtmr2: list("RTMR2")?,
        allowed_rtmr3: list("RTMR3")?,
    })
}

/// An entry the image may leave out. All five lists or none: a partial entry
/// is a broken build, not a role to serve with some registers unchecked, and
/// it is refused even with enforcement off so a debug image cannot hide it.
fn optional_entry_from_env(role: Role, env_prefix: &str) -> EyreResult<Option<PolicyEntry>> {
    let entry = entry_from_env(role, env_prefix)?;
    let fields = entry.register_fields();
    let set = fields.iter().filter(|(_, list)| !list.is_empty()).count();
    if set == 0 {
        return Ok(None);
    }
    if set < fields.len() {
        let missing: Vec<String> = fields
            .iter()
            .filter(|(_, list)| list.is_empty())
            .map(|(label, _)| format!("{env_prefix}ALLOWED_{label}"))
            .collect();
        bail!(
            "The {role} allowlist is incomplete: {} unset. Set all five {env_prefix}ALLOWED_* or none.",
            missing.join(", ")
        );
    }
    Ok(Some(entry))
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

    info!("Starting mero-kms");
    info!("Listen address: {}", config.listen_addr);
    info!(
        "Cluster: bootstrap={} peers={:?}",
        config.kms_bootstrap, config.cluster_peers
    );
    info!("Challenge TTL (seconds): {}", config.challenge_ttl_secs);
    info!(
        "Max consumed challenges remembered: {}",
        config.max_consumed_challenges
    );
    #[cfg(feature = "mock-attestation")]
    info!(
        "Accept mock attestation: {}",
        config.accept_mock_attestation
    );
    info!("KMS profile cohort: {}", config.kms_profile);
    info!("Key namespace prefix: {}", config.key_namespace_prefix);
    info!(
        "Agent key namespace prefix: {}",
        config.agent_key_namespace_prefix
    );
    info!(
        "Measurement policy enforced: {}",
        config.attestation_policy.enforce_measurement_policy
    );
    if !config.attestation_policy.enforce_measurement_policy {
        warn!("Measurement policy enforcement is disabled; this is not safe for production");
    }
    info!(
        "Policy TCB statuses: {}",
        config.attestation_policy.allowed_tcb_statuses.len()
    );
    for entry in &config.attestation_policy.entries {
        info!(
            "Policy entry {}: mrtd={}, rtmr0={}, rtmr1={}, rtmr2={}, rtmr3={}",
            entry.role,
            entry.allowed_mrtd.len(),
            entry.allowed_rtmr0.len(),
            entry.allowed_rtmr1.len(),
            entry.allowed_rtmr2.len(),
            entry.allowed_rtmr3.len()
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
            ("MERO_KMS_BOOTSTRAP", "true".to_string()),
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
        let config = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect("env-policy mode should load");
        assert_eq!(config.kms_profile, "locked-read-only");
        let node = config
            .attestation_policy
            .entry(Role::Node)
            .expect("node entry");
        assert_eq!(node.allowed_mrtd.len(), 1);
        assert_eq!(node.allowed_rtmr3.len(), 1);
        assert!(
            config.attestation_policy.entry(Role::Agent).is_none(),
            "no AGENT_ALLOWED_* means no agent entry"
        );
        assert_eq!(config.agent_key_namespace_prefix, "mero-agent/storage");
    }

    fn agent_env_policy_overrides() -> Vec<(&'static str, String)> {
        let measurement = "cd".repeat(crate::util::MEASUREMENT_BYTES);
        vec![
            ("AGENT_ALLOWED_MRTD", measurement.clone()),
            ("AGENT_ALLOWED_RTMR0", measurement.clone()),
            ("AGENT_ALLOWED_RTMR1", measurement.clone()),
            ("AGENT_ALLOWED_RTMR2", measurement.clone()),
            ("AGENT_ALLOWED_RTMR3", measurement),
        ]
    }

    #[test]
    fn from_env_builds_an_agent_entry_from_agent_allowlists() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.extend(agent_env_policy_overrides());
        let _guard = apply_string_overrides(overrides);
        let config = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect("node and agent allowlists should load");
        assert_eq!(config.attestation_policy.entries.len(), 2);
        let agent = config
            .attestation_policy
            .entry(Role::Agent)
            .expect("agent entry");
        assert_eq!(agent.allowed_rtmr3.len(), 1);
    }

    #[test]
    fn from_env_rejects_a_partial_agent_allowlist() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.extend(
            agent_env_policy_overrides()
                .into_iter()
                .filter(|(key, _)| *key != "AGENT_ALLOWED_RTMR2"),
        );
        let _guard = apply_string_overrides(overrides);
        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect_err("a partial agent allowlist should refuse startup");
        assert!(err.to_string().contains("AGENT_ALLOWED_RTMR2"), "{err}");
    }

    #[test]
    fn from_env_rejects_a_partial_agent_allowlist_without_enforcement() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("ENFORCE_MEASUREMENT_POLICY", "false".to_string()));
        overrides.push((
            "AGENT_ALLOWED_MRTD",
            "cd".repeat(crate::util::MEASUREMENT_BYTES),
        ));
        let _guard = apply_string_overrides(overrides);
        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect_err("a partial agent allowlist is a broken build in any profile");
        assert!(err.to_string().contains("AGENT_ALLOWED_RTMR0"), "{err}");
    }

    #[test]
    fn from_env_rejects_an_agent_prefix_equal_to_the_node_prefix() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("AGENT_KEY_NAMESPACE_PREFIX", "/merod/storage/".to_string()));
        let _guard = apply_string_overrides(overrides);
        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect_err("a shared prefix would let an agent derive a node key");
        assert!(err.to_string().contains("must differ"), "{err}");
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
        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
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
        let err = Config::from_env_with_image_profile_path(profile_file.as_str())
            .expect_err("pinned image should reject MERO_KMS_PROFILE override");
        assert!(err
            .to_string()
            .contains("does not match profile-pinned image value"));
    }

    #[test]
    fn from_env_rejects_an_incomplete_node_allowlist() {
        let _lock = env_lock().lock().expect("env lock");
        let overrides = valid_env_policy_overrides()
            .into_iter()
            .filter(|(key, _)| *key != "ALLOWED_RTMR3")
            .collect();
        let _guard = apply_string_overrides(overrides);

        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect_err("a missing ALLOWED_RTMR3 should refuse startup");
        assert!(err.to_string().contains("allowed_rtmr3"), "{err}");
    }

    #[test]
    fn from_env_rejects_a_replica_with_neither_bootstrap_nor_peers() {
        let _lock = env_lock().lock().expect("env lock");
        let overrides = valid_env_policy_overrides()
            .into_iter()
            .filter(|(key, _)| *key != "MERO_KMS_BOOTSTRAP")
            .collect();
        let _guard = apply_string_overrides(overrides);

        let err = Config::from_env_with_image_profile_path("/tmp/nonexistent-kms-profile")
            .expect_err("a replica that can never get a root should refuse startup");
        assert!(err.to_string().contains("MERO_KMS_PEERS"), "{err}");
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
