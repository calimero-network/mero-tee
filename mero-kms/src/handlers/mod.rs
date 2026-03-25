//! HTTP request handlers for the key release service.

mod attest;
mod challenge;
pub mod errors;
mod get_key;

use axum::extract::DefaultBodyLimit;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::challenge_store::ChallengeStore;
use crate::Config;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Shared application state injected into all handlers via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// Service configuration and attestation policy.
    pub config: Config,
    /// Backend for storing and consuming single-use challenges.
    pub challenge_store: ChallengeStore,
}

/// Create the router with all endpoints.
pub fn create_router(config: Config) -> eyre::Result<Router> {
    let challenge_store = ChallengeStore::from_redis_url(config.redis_url.as_deref())
        .map_err(|e| eyre::eyre!("failed to initialize challenge store: {}", e))?;
    let state = AppState {
        config,
        challenge_store,
    };

    Ok(Router::new()
        .route("/health", get(health_handler))
        .route("/challenge", post(challenge::challenge_handler))
        .route("/get-key", post(get_key::get_key_handler))
        .route("/attest", post(attest::attest_kms_handler))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state))
}

/// Health check endpoint.
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "alive",
        "service": "mero-kms-phala"
    }))
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
