//! mero-agent-gate: serves `/attest`, `/provision` and `/release` inside an
//! agent TD that hosts several agents, one per slot.
//!
//! # Environment
//!
//! Baked into the image (`/etc/mero-agent/gate.env`) and measured. The one
//! input from instance metadata is the operator key, and it can only write the
//! operator's own secrets (see `GATE_OPERATOR_KEY_FILE`).
//!
//! Nobody is baked in as allowed to provision: the first HPKE Auth-mode bundle
//! for an agent id claims a free slot for that id and its sender key, which is
//! kept on the encrypted disk (`agents/<n>/keys/owner.x25519`) and bound into
//! every later quote for that agent. Only that key can provision or release it.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `GATE_LISTEN_ADDR` | `0.0.0.0:8090` | HTTP listen address |
//! | `GATE_STATE_DIR` | `/mnt/agent` | The encrypted data disk. Slot `n` lives in `agents/<n>/` ([`slots`](mero_agent_gate::slots)) |
//! | `GATE_REQUIRE_MOUNT` | `true` | Refuse to start unless `GATE_STATE_DIR` is a mount point, so nothing lands on the boot disk |
//! | `GATE_SLOTS` | `1` | How many agents the TD hosts |
//! | `GATE_SLOT_GROUP_PREFIX` | *(none)* | Slot `n`'s keys and secrets are made readable by the group `<prefix><n>` (0640, directories 0750), and by nobody else. Empty: owner-only. The gate runs as root, which configfs-tsm quotes need |
//! | `GATE_SLOT_UNIT` | *(none)* | Slot `n`'s agent as a systemd unit, `{slot}` standing for `n` (`mero-agent@{slot}.service`): stopped before a release erases the slot, started after. Empty: none |
//! | `GATE_IMAGE_PROFILE_FILE` | `/etc/mero-agent/image-profile` | The image's profile |
//! | `GATE_OPERATOR_KEY_FILE` | `/run/mero-agent/operator.x25519` | The operator's X25519 public key, base64. agent-init copies it from the `operator-key` metadata whoever runs the VM sets. Its holder may write only the [`OPERATOR_SECRETS`](mero_agent_gate::protocol::OPERATOR_SECRETS) into a claimed agent (`/operator`). Missing: `/operator` refuses everything |
//! | `GATE_MOCK_ATTESTATION` | `false` | Serve mock quotes. `mock-attestation` builds only |

use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use eyre::{bail, Result as EyreResult, WrapErr};
use mero_agent_gate::keys::ProvisioningKey;
use mero_agent_gate::server::{router, Gate, NoUnits, Quoter, SystemdUnits, TdxQuoter, Units};
use mero_agent_gate::slots::open_slots;
use tracing::info;
#[cfg(feature = "mock-attestation")]
use tracing::warn;
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

/// The operator key agent-init wrote, or None when there is none. A file that
/// is there but holds no 32-byte key stops the gate: half a configuration
/// should not read as "no operator".
fn read_operator_key(path: &Path) -> EyreResult<Option<[u8; 32]>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let bytes = BASE64
                .decode(text.trim())
                .wrap_err_with(|| format!("{}: not base64", path.display()))?;
            let key = <[u8; 32]>::try_from(bytes)
                .map_err(|_| eyre::eyre!("{}: an operator key is 32 bytes", path.display()))?;
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).wrap_err_with(|| format!("{}", path.display())),
    }
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
    let slot_count: u32 = match std::env::var("GATE_SLOTS") {
        Ok(value) => value.trim().parse().wrap_err("GATE_SLOTS")?,
        Err(_) => 1,
    };
    let group_prefix = std::env::var("GATE_SLOT_GROUP_PREFIX").unwrap_or_default();
    let units: Arc<dyn Units> = match std::env::var("GATE_SLOT_UNIT") {
        Ok(template) if !template.trim().is_empty() => {
            if !template.contains("{slot}") {
                bail!("GATE_SLOT_UNIT must name the slot with {{slot}}");
            }
            Arc::new(SystemdUnits {
                template: template.trim().to_owned(),
            })
        }
        _ => Arc::new(NoUnits),
    };

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

    #[cfg(feature = "mock-attestation")]
    let quoter: Arc<dyn Quoter> = if env_bool("GATE_MOCK_ATTESTATION", false)? {
        warn!("Serving MOCK quotes; never in production");
        Arc::new(mero_agent_gate::server::MockQuoter)
    } else {
        Arc::new(TdxQuoter)
    };
    #[cfg(not(feature = "mock-attestation"))]
    let quoter: Arc<dyn Quoter> = Arc::new(TdxQuoter);

    let operator = read_operator_key(&env_path(
        "GATE_OPERATOR_KEY_FILE",
        "/run/mero-agent/operator.x25519",
    ))?;

    let slots = open_slots(&state_dir.join("agents"), slot_count, group_prefix.trim())?;
    let claimed = slots.iter().filter(|s| s.claim.is_some()).count();
    let gate = Arc::new(
        Gate::new(quoter, ProvisioningKey::generate(), slots, units).with_operator(operator),
    );
    info!(
        profile = %profile,
        slots = slot_count,
        claimed,
        operator = %operator.map_or_else(|| "none".to_owned(), |key| BASE64.encode(key)),
        provisioning_key = %BASE64.encode(gate.provisioning.public),
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
