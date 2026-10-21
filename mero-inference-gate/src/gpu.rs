//! NVIDIA evidence for a nonce, in the shape NRAS takes:
//! `{"nonce", "arch", "evidence_list": [{"certificate", "evidence"}]}`.
//!
//! The gate asks a helper for it (`gpu-evidence`, which reads it from the
//! driver through NVML) on every `/attest`, so its nonce is the client's own.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// How long the helper may take: NVML signs a report per GPU.
const HELPER_TIMEOUT: Duration = Duration::from_secs(60);

/// At most this much evidence (an H100's report and certificate chain are a
/// few KiB each).
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;

pub enum GpuEvidence {
    /// A TD with no GPU: `/attest` answers `gpuJson: null`, which clients refuse.
    None,
    /// The helper, run as `<path> <nonce hex>`; its stdout is the evidence.
    Helper(PathBuf),
    /// Fixed evidence with `{nonce}` standing for the nonce. Tests only.
    #[doc(hidden)]
    Template(String),
}

impl GpuEvidence {
    /// The evidence for `nonce_hex`, exactly as it will be hashed and sent.
    /// It must be a JSON object whose `nonce` is `nonce_hex`: evidence for
    /// another nonce could be a replay.
    pub async fn collect(&self, nonce_hex: &str) -> Result<Option<String>, String> {
        let text = match self {
            Self::None => return Ok(None),
            Self::Template(template) => template.replace("{nonce}", nonce_hex),
            Self::Helper(path) => {
                let child = Command::new(path)
                    .arg(nonce_hex)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| format!("cannot run {}: {e}", path.display()))?;
                let output = tokio::time::timeout(HELPER_TIMEOUT, child.wait_with_output())
                    .await
                    .map_err(|_| format!("{} took over {HELPER_TIMEOUT:?}", path.display()))?
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                if !output.status.success() {
                    return Err(format!(
                        "{} failed ({}): {}",
                        path.display(),
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                String::from_utf8(output.stdout)
                    .map_err(|_| "GPU evidence is not UTF-8".to_owned())?
            }
        };
        let text = text.trim().to_owned();
        if text.len() > MAX_EVIDENCE_BYTES {
            return Err("GPU evidence is too large".to_owned());
        }
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| "GPU evidence is not JSON".to_owned())?;
        if value.get("nonce").and_then(|n| n.as_str()) != Some(nonce_hex) {
            return Err("GPU evidence is not for this nonce".to_owned());
        }
        let evidence = value.get("evidence_list").and_then(|l| l.as_array());
        if evidence.is_none_or(|list| list.is_empty()) {
            return Err("GPU evidence lists no GPU".to_owned());
        }
        Ok(Some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "ab";

    #[tokio::test]
    async fn evidence_must_be_for_the_nonce() {
        let good = GpuEvidence::Template(
            r#"{"nonce":"{nonce}","evidence_list":[{"evidence":"e"}]}"#.into(),
        );
        assert!(good
            .collect(NONCE)
            .await
            .unwrap()
            .unwrap()
            .contains(r#""nonce":"ab""#));
        let stale =
            GpuEvidence::Template(r#"{"nonce":"cd","evidence_list":[{"evidence":"e"}]}"#.into());
        assert!(stale.collect(NONCE).await.is_err());
        let empty = GpuEvidence::Template(r#"{"nonce":"{nonce}","evidence_list":[]}"#.into());
        assert!(empty.collect(NONCE).await.is_err());
        assert_eq!(GpuEvidence::None.collect(NONCE).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_failing_helper_is_an_error() {
        assert!(GpuEvidence::Helper("/bin/false".into())
            .collect(NONCE)
            .await
            .is_err());
        assert!(GpuEvidence::Helper("/nonexistent".into())
            .collect(NONCE)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_helper_gets_the_nonce() {
        let dir = std::env::temp_dir().join(format!("gpu-evidence-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let helper = dir.join("helper");
        std::fs::write(
            &helper,
            "#!/bin/sh\nprintf '{\"nonce\":\"%s\",\"evidence_list\":[{\"evidence\":\"e\"}]}' \"$1\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let text = GpuEvidence::Helper(helper)
            .collect(NONCE)
            .await
            .unwrap()
            .unwrap();
        assert!(text.contains(r#""nonce":"ab""#));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
