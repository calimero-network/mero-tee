//! `/challenge` endpoint: issues short-lived nonce challenges.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::random;
use serde::{Deserialize, Serialize};

use crate::challenge_store::{ChallengeStoreError, PendingChallenge};
use crate::util::{unix_now_secs, CHALLENGE_ID_BYTES, MAX_PEER_ID_LENGTH};

use super::errors::ServiceError;
use super::AppState;

/// Request body for the challenge endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    /// Peer ID of the requesting merod node (base58 encoded).
    pub peer_id: String,
}

/// Response body for the challenge endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    /// Unique challenge ID.
    pub challenge_id: String,
    /// Base64-encoded 32-byte nonce.
    pub nonce_b64: String,
    /// Expiration timestamp (unix seconds).
    pub expires_at: u64,
}

/// Handler for challenge issuance.
pub(crate) async fn challenge_handler(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ServiceError> {
    validate_peer_id_shape(&request.peer_id)?;
    let nonce: [u8; 32] = random();

    let challenge_id = create_challenge_id();
    let now = unix_now_secs().map_err(|e| ServiceError::InvalidChallenge(e.to_string()))?;
    let expires_at = now.saturating_add(state.config.challenge_ttl_secs);
    state
        .challenge_store
        .insert(
            challenge_id.clone(),
            PendingChallenge {
                nonce,
                peer_id: request.peer_id,
                expires_at,
            },
            state.config.challenge_ttl_secs,
            state.config.max_pending_challenges,
        )
        .await
        .map_err(|err| match err {
            ChallengeStoreError::CapacityExceeded => {
                ServiceError::RateLimited("Too many pending challenges. Retry shortly.".to_string())
            }
            _ => ServiceError::InvalidChallenge(format!("Challenge storage failed: {}", err)),
        })?;

    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce_b64: BASE64.encode(nonce),
        expires_at,
    }))
}

fn create_challenge_id() -> String {
    let raw: [u8; CHALLENGE_ID_BYTES] = random();
    hex::encode(raw)
}

pub(crate) fn validate_peer_id_shape(peer_id: &str) -> Result<(), ServiceError> {
    let trimmed = peer_id.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InvalidPeerId(
            "peer ID must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_PEER_ID_LENGTH {
        return Err(ServiceError::InvalidPeerId(format!(
            "peer ID exceeds max length {}",
            MAX_PEER_ID_LENGTH
        )));
    }
    if !trimmed
        .chars()
        .all(|c| matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'))
    {
        return Err(ServiceError::InvalidPeerId(
            "peer ID contains non-base58btc characters".to_string(),
        ));
    }
    Ok(())
}
