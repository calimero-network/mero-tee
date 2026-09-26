//! HTTP request handlers for the key release service.

mod attest;
mod challenge;
pub mod errors;
mod get_key;

use axum::extract::{DefaultBodyLimit, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use std::sync::Arc;

use crate::backend::Backend;
use crate::challenge_store::ChallengeStore;
use crate::cluster::{self, JoinNonces};
use crate::Config;

pub(crate) use attest::decode_fixed_b64_32;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Shared application state injected into all handlers via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// Service configuration and attestation policy.
    pub config: Config,
    /// Backend for storing and consuming single-use challenges.
    pub challenge_store: ChallengeStore,
    /// Where keys and quotes come from.
    pub(crate) backend: Backend,
    /// Nonces this replica issued to replicas joining its cluster.
    pub(crate) join_nonces: Arc<JoinNonces>,
}

/// Create the router with all endpoints.
pub(crate) fn create_router(config: Config, backend: Backend) -> eyre::Result<Router> {
    let challenge_store = ChallengeStore::from_redis_url(config.redis_url.as_deref())
        .map_err(|e| eyre::eyre!("failed to initialize challenge store: {}", e))?;
    let state = AppState {
        config,
        challenge_store,
        backend,
        join_nonces: Arc::new(JoinNonces::default()),
    };

    Ok(Router::new()
        .route("/health", get(health_handler))
        .route("/challenge", post(challenge::challenge_handler))
        .route("/get-key", post(get_key::get_key_handler))
        .route("/attest", post(attest::attest_kms_handler))
        .route("/cluster/nonce", post(cluster::join_nonce_handler))
        .route("/cluster/join", post(cluster::join_handler))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state))
}

/// Health check endpoint. A TDX replica also reports whether it holds its
/// cluster's root yet, so a deployer can tell when a new replica has joined.
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = serde_json::json!({
        "status": "alive",
        "service": "mero-kms-phala"
    });
    if let Backend::Tdx(tdx) = &state.backend {
        body["clusterRootReady"] = serde_json::Value::Bool(tdx.has_root());
    }
    Json(body)
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
