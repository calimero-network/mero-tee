//! HTTP request handlers for the key release service.

mod attest;
mod challenge;
pub mod errors;
mod get_key;
mod rollback;

use axum::extract::{DefaultBodyLimit, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use std::sync::Arc;

use crate::backend::TdxBackend;
use crate::cluster::{self, JoinNonces};
use crate::counters::{Counters, Signed};
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
    /// The nodes' rollback counters (`counters`).
    pub(crate) counters: Arc<Counters>,
}

/// The router of a replica that already holds its root and, with it, every
/// counter there is (a bootstrapping replica, or a test's).
#[cfg(test)]
pub(crate) fn create_router(config: Config, backend: Arc<TdxBackend>) -> Router {
    let counters = Arc::new(Counters::new(config.replicas, config.cluster_peers.clone()));
    if backend.has_root() {
        counters.bootstrap();
    }
    create_router_with(config, backend, counters)
}

/// Create the router with all endpoints, over `counters`.
pub(crate) fn create_router_with(
    config: Config,
    backend: Arc<TdxBackend>,
    counters: Arc<Counters>,
) -> Router {
    let state = AppState {
        config,
        backend,
        join_nonces: Arc::new(JoinNonces::default()),
        spent_challenges: Arc::new(SpentChallenges::default()),
        counters,
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/challenge", post(challenge::challenge_handler))
        .route("/get-key", post(get_key::get_key_handler))
        .route("/attest", post(attest::attest_kms_handler))
        .route("/cluster/nonce", post(cluster::join_nonce_handler))
        .route("/cluster/join", post(cluster::join_handler))
        .route("/cluster/counters/read", post(counters_read_handler))
        .route("/cluster/counters/merge", post(counters_merge_handler))
        .route("/rollback/raise", post(rollback::raise_handler))
        .route("/rollback/reset", post(rollback::reset_handler))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// Another replica reads counters (`counters`); MACed both ways.
async fn counters_read_handler(
    State(state): State<AppState>,
    Json(request): Json<Signed>,
) -> Result<Json<Signed>, errors::ServiceError> {
    state
        .counters
        .answer_read(&state.backend, &request)
        .map(Json)
}

/// Another replica writes counters (`counters`); MACed both ways.
async fn counters_merge_handler(
    State(state): State<AppState>,
    Json(request): Json<Signed>,
) -> Result<Json<Signed>, errors::ServiceError> {
    state
        .counters
        .answer_merge(&state.backend, &request)
        .map(Json)
}

/// Health check endpoint. Also reports whether this replica holds its
/// cluster's root yet, so a deployer can tell when a new replica has joined,
/// and, once a join has failed, why: `lastJoinError` on the joiner,
/// `lastJoinRefusal` on the replica that refused it.
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut health = serde_json::json!({
        "status": "alive",
        "service": "mero-kms",
        "clusterRootReady": state.backend.has_root(),
        "countersReady": state.counters.is_ready(),
    });
    if let Some(error) = state.backend.last_join_error() {
        health["lastJoinError"] = serde_json::Value::String(error);
    }
    if let Some(refusal) = state.backend.last_join_refusal() {
        health["lastJoinRefusal"] = serde_json::Value::String(refusal);
    }
    Json(health)
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
