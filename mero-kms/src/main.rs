//! mero-kms-phala: Key management service for merod nodes running in Phala Cloud TEE.
//!
//! This service validates TDX attestations from merod nodes and releases deterministic
//! storage encryption keys based on peer ID using Phala's dstack key derivation.

mod challenge_store;
mod config;
mod handlers;
mod policy;
mod runtime_event;

use axum::http::{HeaderValue, Method};
use eyre::Result as EyreResult;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::handlers::create_router;
use crate::runtime_event::ensure_kms_profile_runtime_event;

pub use crate::config::Config;
pub use crate::policy::AttestationPolicy;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_level(true)
        .init();

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
        warn!("Measurement policy enforcement is disabled; this is not safe for production");
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
        warn!(
            "WARNING: Mock attestation acceptance is enabled. This should NEVER be used in production!"
        );
        warn!("Skipping KMS profile RTMR3 runtime marker because mock attestation mode is enabled");
    } else if let Err(err) = ensure_kms_profile_runtime_event(&config.kms_profile) {
        warn!("Failed to emit KMS profile RTMR3 runtime marker; continuing startup: {err:#}");
        warn!(
            "Profile pinning is still enforced, but runtime profile-measurement separation may be reduced"
        );
    }

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

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
