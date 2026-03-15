//! Service configuration and release-policy loading.

use std::net::SocketAddr;

use eyre::{bail, Result as EyreResult};
use sha2::Digest;

use crate::policy::{validate_policy_requirements, AttestationPolicy};

const POLICY_RELEASE_BASE: &str = "https://github.com/calimero-network/mero-tee/releases/download";
const KNOWN_PROFILES: [&str; 3] = ["debug", "debug-read-only", "locked-read-only"];
const IMAGE_PROFILE_PATH: &str = "/etc/mero-kms/image-profile";

/// Configuration for the key releaser service.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub dstack_socket_path: String,
    pub challenge_ttl_secs: u64,
    pub max_pending_challenges: usize,
    pub accept_mock_attestation: bool,
    pub redis_url: Option<String>,
    pub kms_profile: String,
    pub key_namespace_prefix: String,
    pub policy_sha256: Option<String>,
    pub cors_allowed_origins: Vec<String>,
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

impl Config {
    pub async fn from_env() -> EyreResult<Self> {
        Self::from_env_with_image_profile_path(IMAGE_PROFILE_PATH).await
    }

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
        let env_profile_override = match std::env::var("KMS_POLICY_PROFILE") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                bail!("KMS_POLICY_PROFILE must be valid UTF-8")
            }
        };
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

    pub(crate) fn parse_policy_json(
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
            Some(role) => bail!("Policy role mismatch: expected 'kms', got '{}'", role),
            None if allow_legacy_missing_profile && expected_profile == "locked-read-only" => {}
            None => bail!("Policy JSON missing 'role' for KMS policy"),
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
            None => bail!(
                "Policy JSON missing 'profile' for requested profile '{}'",
                expected_profile
            ),
        }

        let policy = root
            .get("policy")
            .and_then(|v| v.as_object())
            .ok_or_else(|| eyre::eyre!("Policy JSON missing 'policy' object"))?;

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
        Ok(AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: parse_csv_env("ALLOWED_TCB_STATUSES")
                .unwrap_or_else(|| vec!["uptodate".to_string()]),
            allowed_mrtd: parse_measurement_list_env("ALLOWED_MRTD", 48)?,
            allowed_rtmr0: parse_measurement_list_env("ALLOWED_RTMR0", 48)?,
            allowed_rtmr1: parse_measurement_list_env("ALLOWED_RTMR1", 48)?,
            allowed_rtmr2: parse_measurement_list_env("ALLOWED_RTMR2", 48)?,
            allowed_rtmr3: parse_measurement_list_env("ALLOWED_RTMR3", 48)?,
        })
    }
}

fn parse_bool_flag(raw: &str) -> EyreResult<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("Invalid boolean value '{}'", other),
    }
}

fn parse_bool_env(name: &str, default: bool) -> EyreResult<bool> {
    match std::env::var(name) {
        Ok(value) => parse_bool_flag(&value),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

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

fn resolve_kms_profile(
    pinned_profile: Option<&str>,
    env_override: Option<&str>,
) -> EyreResult<String> {
    if let Some(pinned) = pinned_profile {
        if env_override.is_some() {
            bail!(
                "KMS_POLICY_PROFILE override is not allowed for profile-pinned images. \
                 Build/deploy the matching KMS image profile instead."
            );
        }
        return parse_profile(pinned);
    }

    parse_profile(
        env_override
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("locked-read-only"),
    )
}

fn parse_profile(raw: &str) -> EyreResult<String> {
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

fn normalize_hash_pin(raw: &str) -> EyreResult<String> {
    let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    if normalized.len() != 64 {
        bail!(
            "MERO_KMS_POLICY_SHA256 must contain exactly 64 hex chars (got {})",
            normalized.len()
        );
    }
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("MERO_KMS_POLICY_SHA256 contains non-hex characters");
    }
    Ok(normalized)
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(digest)
}

fn parse_json_string_array(
    policy: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    policy.get(key).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|value| value.as_str())
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    })
}

fn parse_json_hex_array(
    policy: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_bytes: usize,
) -> EyreResult<Option<Vec<String>>> {
    let Some(values) = policy.get(key) else {
        return Ok(None);
    };
    let arr = values
        .as_array()
        .ok_or_else(|| eyre::eyre!("Policy field '{}' must be an array", key))?;
    let mut parsed = Vec::new();
    for value in arr {
        let raw = value
            .as_str()
            .ok_or_else(|| eyre::eyre!("Policy field '{}' entries must be strings", key))?;
        parsed.push(normalize_hex(raw, expected_bytes)?);
    }
    Ok(Some(parsed))
}

fn parse_policy_hex_allowlist(
    policy: &serde_json::Map<String, serde_json::Value>,
    preferred_key: &str,
    fallback_key: &str,
    expected_bytes: usize,
) -> EyreResult<Vec<String>> {
    if let Some(values) = parse_json_hex_array(policy, preferred_key, expected_bytes)? {
        return Ok(values);
    }
    Ok(parse_json_hex_array(policy, fallback_key, expected_bytes)?.unwrap_or_default())
}

fn parse_csv_env(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn parse_csv_env_raw(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn parse_measurement_list_env(name: &str, expected_bytes: usize) -> EyreResult<Vec<String>> {
    match std::env::var(name) {
        Ok(raw) => raw
            .split(',')
            .filter_map(|entry| {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .map(|value| normalize_hex(value, expected_bytes))
            .collect(),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

fn normalize_hex(raw: &str, expected_bytes: usize) -> EyreResult<String> {
    let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    let expected_len = expected_bytes * 2;
    if normalized.len() != expected_len {
        bail!(
            "Expected {} bytes ({} hex chars), got {} chars",
            expected_bytes,
            expected_len,
            normalized.len()
        );
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("Value contains non-hex characters");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const ENV_KEYS: &[&str] = &[
        "LISTEN_ADDR",
        "DSTACK_SOCKET_PATH",
        "CHALLENGE_TTL_SECS",
        "MAX_PENDING_CHALLENGES",
        "ACCEPT_MOCK_ATTESTATION",
        "REDIS_URL",
        "KMS_POLICY_PROFILE",
        "KEY_NAMESPACE_PREFIX",
        "MERO_KMS_POLICY_SHA256",
        "CORS_ALLOWED_ORIGINS",
        "ENFORCE_MEASUREMENT_POLICY",
        "USE_ENV_POLICY",
        "MERO_KMS_RELEASE_TAG",
        "MERO_KMS_VERSION",
        "ALLOWED_TCB_STATUSES",
        "ALLOWED_MRTD",
        "ALLOWED_RTMR0",
        "ALLOWED_RTMR1",
        "ALLOWED_RTMR2",
        "ALLOWED_RTMR3",
    ];

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

    fn valid_measurement_hex() -> String {
        "ab".repeat(48)
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
    fn resolve_kms_profile_rejects_override_for_pinned_image() {
        let err = resolve_kms_profile(Some("locked-read-only"), Some("locked-read-only"))
            .expect_err("override should be rejected for pinned profile");
        assert!(err
            .to_string()
            .contains("KMS_POLICY_PROFILE override is not allowed"));
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
    fn parse_policy_json_rejects_mismatched_profile() {
        let policy_json = serde_json::json!({
            "tag": "2.1.38",
            "role": "kms",
            "profile": "debug",
            "policy": {
                "node_allowed_tcb_statuses": ["uptodate"],
                "node_allowed_mrtd": ["ab".repeat(48)],
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
        .expect_err("mismatched profile should fail");
        assert!(err.to_string().contains("Policy profile mismatch"));
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
        .expect_err("non-kms role should fail");
        assert!(err.to_string().contains("Policy role mismatch"));
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
                .expect("legacy policy should parse for locked profile");
        assert_eq!(parsed.allowed_mrtd, vec!["aa".repeat(48)]);
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
    }

    #[test]
    fn from_env_use_env_policy_ignores_release_version_without_hash_pin() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("MERO_KMS_VERSION", "2.1.49".to_string()));
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
    }

    #[test]
    fn from_env_rejects_release_version_without_policy_hash_pin() {
        let _lock = env_lock().lock().expect("env lock");
        let _guard = EnvGuard::apply(&[("MERO_KMS_VERSION", "2.1.49")]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = runtime
            .block_on(Config::from_env_with_image_profile_path(
                "/tmp/nonexistent-kms-profile",
            ))
            .expect_err("missing policy hash pin should fail");
        assert!(err
            .to_string()
            .contains("MERO_KMS_POLICY_SHA256 is required"));
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
        assert!(err.to_string().contains("Expected 48 bytes"));
    }

    #[test]
    fn from_env_rejects_override_when_profile_is_pinned() {
        let _lock = env_lock().lock().expect("env lock");
        let mut overrides = valid_env_policy_overrides();
        overrides.push(("KMS_POLICY_PROFILE", "debug".to_string()));
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
            .expect_err("pinned image should reject KMS_POLICY_PROFILE override");
        assert!(err
            .to_string()
            .contains("KMS_POLICY_PROFILE override is not allowed"));
    }
}
