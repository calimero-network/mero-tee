//! mero-kms-phala: Key management service for merod nodes running in Phala Cloud TEE.
//!
//! This service validates TDX attestations from merod nodes and releases deterministic
//! storage encryption keys based on peer ID using Phala's dstack key derivation.

mod challenge_store;
mod config;
mod handlers;
mod measurement;
mod policy;
mod runtime_event;
mod util;

#[cfg(test)]
mod test_util;

use axum::http::{HeaderValue, Method};
use eyre::Result as EyreResult;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::warn;
use tracing_subscriber::EnvFilter;

use crate::config::log_startup_config;
use crate::handlers::create_router;
use crate::runtime_event::ensure_kms_profile_runtime_event;

pub use crate::config::Config;
pub use crate::measurement::HexMeasurement;
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

    log_startup_config(&config);

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
    let app = build_cors_layer(&config.cors_allowed_origins, base_app)?;

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!("Server listening on {}", config.listen_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn build_cors_layer<S>(origins: &[String], app: axum::Router<S>) -> EyreResult<axum::Router<S>>
where
    S: Clone + Send + Sync + 'static,
{
    if origins.is_empty() {
        tracing::info!("CORS disabled (CORS_ALLOWED_ORIGINS not set)");
        return Ok(app);
    }
    let header_values: Vec<HeaderValue> = origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|e| eyre::eyre!("Invalid CORS origin '{}': {}", origin, e))
        })
        .collect::<EyreResult<_>>()?;
    Ok(app.layer(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(header_values))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(Any),
    ))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("Received Ctrl+C, shutting down gracefully"),
        () = terminate => tracing::info!("Received SIGTERM, shutting down gracefully"),
    }
}
