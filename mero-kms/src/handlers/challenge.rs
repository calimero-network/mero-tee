//! `/challenge` endpoint: issues short-lived, stateless challenge tokens (see
//! `stateless_challenge`).

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::stateless_challenge;
use crate::util::{unix_now_secs, MAX_PEER_ID_LENGTH};

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
    /// The challenge token, echoed back to `/get-key`.
    pub challenge_id: String,
    /// Base64-encoded 32-byte nonce.
    pub nonce_b64: String,
    /// Expiration timestamp (unix seconds).
    pub expires_at: u64,
}

/// Handler for challenge issuance. 503 until this replica holds its cluster's
/// root, which keys the token.
pub(crate) async fn challenge_handler(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ServiceError> {
    validate_peer_id_shape(&request.peer_id)?;
    let key = state.backend.challenge_key()?;
    let now = unix_now_secs().map_err(|e| ServiceError::InvalidChallenge(e.to_string()))?;
    let expires_at = now.saturating_add(state.config.challenge_ttl_secs);
    // Any replica of the cluster can check this challenge; see
    // `stateless_challenge`. Nothing is stored.
    let (challenge_id, nonce) = stateless_challenge::issue(&key, &request.peer_id, expires_at);

    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce_b64: BASE64.encode(nonce),
        expires_at,
    }))
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
