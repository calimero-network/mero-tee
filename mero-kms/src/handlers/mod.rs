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

use crate::backend::TdxBackend;
use crate::cluster::{self, JoinNonces};
use crate::stateless_challenge::SpentChallenges;
use crate::Config;

pub(crate) use attest::decode_fixed_b64_32;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Shared application state injected into all handlers via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// Service configuration and attestation policy.
    pub config: Config,
    /// Where keys and quotes come from.
    pub(crate) backend: Arc<TdxBackend>,
    /// Nonces this replica issued to replicas joining its cluster.
    pub(crate) join_nonces: Arc<JoinNonces>,
    /// The stateless challenges this replica has already accepted.
    pub(crate) spent_challenges: Arc<SpentChallenges>,
}

/// Create the router with all endpoints.
pub(crate) fn create_router(config: Config, backend: Arc<TdxBackend>) -> Router {
    let state = AppState {
        config,
        backend,
        join_nonces: Arc::new(JoinNonces::default()),
        spent_challenges: Arc::new(SpentChallenges::default()),
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/challenge", post(challenge::challenge_handler))
        .route("/get-key", post(get_key::get_key_handler))
        .route("/attest", post(attest::attest_kms_handler))
        .route("/cluster/nonce", post(cluster::join_nonce_handler))
        .route("/cluster/join", post(cluster::join_handler))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// Health check endpoint. Also reports whether this replica holds its
/// cluster's root yet, so a deployer can tell when a new replica has joined.
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut health = serde_json::json!({
        "status": "alive",
        "service": "mero-kms",
        "clusterRootReady": state.backend.has_root(),
    });
    if let Some(error) = state.backend.last_join_error() {
        health["lastJoinError"] = serde_json::Value::String(error);
    }
    Json(health)
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
