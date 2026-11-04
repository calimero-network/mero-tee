//! mero-inference-gate: serves `/attest` and passes `/v1/*` to vLLM inside a
//! private inference TD, over TLS that ends here.
//!
//! # Environment
//!
//! Baked into the image (`/etc/mero-inference/gate.env`) and measured. The
//! files it names are inference-init's: the configuration it loaded and
//! measured into RTMR3, and the access-token hashes from metadata.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `GATE_LISTEN_ADDR` | `0.0.0.0:8443` | HTTPS listen address |
//! | `GATE_UPSTREAM` | `http://127.0.0.1:8000` | vLLM |
//! | `GATE_CONFIG_FILE` | `/run/mero-inference/config.json` | The configuration, exactly as measured. Missing: the measurement VM, which serves `/attest` only |
//! | `GATE_TOKENS_FILE` | `/run/mero-inference/access-tokens` | Hex SHA-256 of the accepted bearer tokens. Missing or empty: `/v1` refuses everyone |
//! | `GATE_GPU_EVIDENCE` | `/usr/local/lib/mero-inference/gpu-evidence` | The helper that prints NVIDIA evidence for a nonce. `none`: a TD with no GPU, whose quotes clients refuse |
//! | `GATE_MOCK_ATTESTATION` | `false` | Serve mock quotes. `mock-attestation` builds only |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use eyre::{bail, eyre, Result as EyreResult, WrapErr};
use mero_inference_gate::gpu::GpuEvidence;
use mero_inference_gate::server::{router, Gate, Quoter, TdxQuoter};
use mero_inference_gate::tls::TlsIdentity;
use mero_inference_gate::tokens::Tokens;
use tracing::info;
#[cfg(feature = "mock-attestation")]
use tracing::warn;
use tracing_subscriber::EnvFilter;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[allow(dead_code, reason = "read only by the mock-attestation build")]
fn env_bool(name: &str) -> EyreResult<bool> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => bail!("{name}: invalid boolean '{other}'"),
        },
        Err(_) => Ok(false),
    }
}

/// A file's contents, or `None` if it does not exist.
fn read_optional(path: &str) -> EyreResult<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).wrap_err_with(|| format!("reading {path}")),
    }
}

fn quoter() -> EyreResult<Box<dyn Quoter>> {
    #[cfg(feature = "mock-attestation")]
    if env_bool("GATE_MOCK_ATTESTATION")? {
        warn!("serving MOCK quotes: development only");
        return Ok(Box::new(mero_inference_gate::server::MockQuoter));
    }
    Ok(Box::new(TdxQuoter))
}

#[tokio::main]
async fn main() -> EyreResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen: SocketAddr = env_or("GATE_LISTEN_ADDR", "0.0.0.0:8443")
        .parse()
        .wrap_err("GATE_LISTEN_ADDR")?;
    // The exact bytes inference-init measured: never trimmed or re-serialized.
    let config_json = read_optional(&env_or(
        "GATE_CONFIG_FILE",
        "/run/mero-inference/config.json",
    ))?
    .unwrap_or_default();
    let tokens = Tokens::parse(
        &read_optional(&env_or(
            "GATE_TOKENS_FILE",
            "/run/mero-inference/access-tokens",
        ))?
        .unwrap_or_default(),
    )
    .map_err(|e| eyre!(e))?;
    let gpu = match env_or(
        "GATE_GPU_EVIDENCE",
        "/usr/local/lib/mero-inference/gpu-evidence",
    )
    .as_str()
    {
        "none" => GpuEvidence::None,
        path => GpuEvidence::Helper(PathBuf::from(path)),
    };
    let tls = TlsIdentity::generate().map_err(|e| eyre!("TLS key: {e}"))?;
    let gate = Gate::new(
        quoter()?,
        gpu,
        tls.spki_sha256,
        config_json,
        tokens,
        env_or("GATE_UPSTREAM", "http://127.0.0.1:8000"),
    )
    .map_err(|e| eyre!(e))?;
    info!(
        %listen,
        tls_spki_sha256 = %hex::encode(tls.spki_sha256),
        config_digest = %hex::encode(gate.config_digest()),
        model = gate.served_model.as_deref().unwrap_or("none (measurement VM)"),
        access_tokens = gate.tokens.len(),
        "mero-inference-gate starting"
    );
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });
    axum_server::bind_rustls(
        listen,
        axum_server::tls_rustls::RustlsConfig::from_config(tls.config),
    )
    .handle(handle)
    .serve(router(Arc::new(gate)).into_make_service())
    .await
    .wrap_err("serving")
}
