//! mero-agent-gate: serves `/attest` and `/provision` inside an agent TD.
//!
//! # Environment
//!
//! Baked into the image (`/etc/mero-agent/gate.env`) and measured; nothing
//! comes from instance metadata.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `GATE_LISTEN_ADDR` | `0.0.0.0:8090` | HTTP listen address |
//! | `GATE_STATE_DIR` | `/mnt/agent` | The encrypted data disk. Secrets go to `secrets/`, the signing key to `keys/` |
//! | `GATE_REQUIRE_MOUNT` | `true` | Refuse to start unless `GATE_STATE_DIR` is a mount point, so nothing lands on the boot disk |
//! | `GATE_PROVISIONERS_FILE` | `/etc/mero-agent/provisioners` | Base64 X25519 keys of the provisioners allowed to set secrets, one per line |
//! | `GATE_ALLOW_UNAUTHENTICATED_PROVISIONING` | `false` | Accept bundles from anyone who verified the quote. Refused on `locked-read-only` |
//! | `GATE_IMAGE_PROFILE_FILE` | `/etc/mero-agent/image-profile` | The image's profile |
//! | `GATE_MOCK_ATTESTATION` | `false` | Serve mock quotes. `mock-attestation` builds only |

use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use eyre::{bail, Result as EyreResult, WrapErr};
use mero_agent_gate::keys::{load_or_create_signing_key, ProvisioningKey};
use mero_agent_gate::server::{router, Gate, Quoter, TdxQuoter};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn env_bool(name: &str, default: bool) -> EyreResult<bool> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => bail!("{name}: invalid boolean '{other}'"),
        },
        Err(_) => Ok(default),
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

/// A mount point sits on a different device from its parent. `/mnt/agent` is
/// where agent-init mounts the encrypted disk; if it is not mounted, the
/// signing key and secrets would land on the boot disk, which the host reads.
fn is_mount_point(path: &Path) -> EyreResult<bool> {
    let own = std::fs::metadata(path).wrap_err_with(|| format!("{}", path.display()))?;
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent = std::fs::metadata(parent).wrap_err_with(|| format!("{}", parent.display()))?;
    Ok(own.dev() != parent.dev())
}

/// One base64 X25519 key per line; blank lines and `#` comments ignored.
fn read_provisioners(path: &Path) -> EyreResult<Vec<[u8; 32]>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).wrap_err_with(|| format!("{}", path.display())),
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            BASE64
                .decode(line)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    eyre::eyre!("{}: '{line}' is not a base64 X25519 key", path.display())
                })
        })
        .collect()
}

fn private_dir(path: &Path) -> EyreResult<()> {
    std::fs::create_dir_all(path).wrap_err_with(|| format!("{}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .wrap_err_with(|| format!("{}", path.display()))
}

#[tokio::main]
async fn main() -> EyreResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let listen: SocketAddr = std::env::var("GATE_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8090".to_owned())
        .parse()
        .wrap_err("GATE_LISTEN_ADDR")?;
    let state_dir = env_path("GATE_STATE_DIR", "/mnt/agent");
    let profile = std::fs::read_to_string(env_path(
        "GATE_IMAGE_PROFILE_FILE",
        "/etc/mero-agent/image-profile",
    ))
    .map(|p| p.trim().to_owned())
    .unwrap_or_default();
    let provisioners = read_provisioners(&env_path(
        "GATE_PROVISIONERS_FILE",
        "/etc/mero-agent/provisioners",
    ))?;
    let allow_unauthenticated = env_bool("GATE_ALLOW_UNAUTHENTICATED_PROVISIONING", false)?;

    let require_mount = env_bool("GATE_REQUIRE_MOUNT", true)?;
    if !require_mount && profile == "locked-read-only" {
        bail!("GATE_REQUIRE_MOUNT=false is refused on locked-read-only");
    }
    if require_mount && !is_mount_point(&state_dir)? {
        bail!(
            "{} is not a mount point; refusing to keep the signing key and secrets on the boot disk",
            state_dir.display()
        );
    }
    if allow_unauthenticated && profile == "locked-read-only" {
        bail!("unauthenticated provisioning is refused on locked-read-only");
    }
    if provisioners.is_empty() && !allow_unauthenticated {
        warn!("No provisioners are listed: /provision will refuse every bundle");
    }
    if allow_unauthenticated {
        warn!("Unauthenticated provisioning is ON: anyone who verifies the quote can set secrets");
    }

    #[cfg(feature = "mock-attestation")]
    let quoter: Arc<dyn Quoter> = if env_bool("GATE_MOCK_ATTESTATION", false)? {
        warn!("Serving MOCK quotes; never in production");
        Arc::new(mero_agent_gate::server::MockQuoter)
    } else {
        Arc::new(TdxQuoter)
    };
    #[cfg(not(feature = "mock-attestation"))]
    let quoter: Arc<dyn Quoter> = Arc::new(TdxQuoter);

    let keys_dir = state_dir.join("keys");
    let secrets_dir = state_dir.join("secrets");
    private_dir(&keys_dir)?;
    private_dir(&secrets_dir)?;
    let signing = load_or_create_signing_key(&keys_dir.join("signing.ed25519"))?;
    let signing_public = signing.verifying_key().to_bytes();
    drop(signing);

    let gate = Arc::new(Gate {
        quoter,
        provisioning: ProvisioningKey::generate(),
        signing_public,
        secrets_dir,
        provisioners,
        allow_unauthenticated,
        provisioned: AtomicBool::new(false),
    });
    info!(
        profile = %profile,
        provisioners = gate.provisioners.len(),
        provisioning_key = %BASE64.encode(gate.provisioning.public),
        signing_key = %BASE64.encode(gate.signing_public),
        "mero-agent-gate ready"
    );

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Listening on {listen}");
    axum::serve(listener, router(gate))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
