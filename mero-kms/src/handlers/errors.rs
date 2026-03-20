//! Shared API error types and HTTP mapping for handler modules.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

/// Error response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Service-level errors.
#[derive(Debug)]
pub enum ServiceError {
    InvalidBase64(String),
    InvalidPeerId(String),
    InvalidAttestationRequest(String),
    RateLimited(String),
    InvalidChallenge(String),
    InvalidPeerPublicKey(String),
    InvalidSignature(String),
    AttestationVerificationFailed(String),
    MockAttestationRejected,
    PeerIdentityMismatch,
    PeerIdMismatch,
    TcbStatusRejected(String),
    MeasurementPolicyRejected(String),
    PolicyNotReady(String),
    KeyDerivationFailed(String),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_response) = match &self {
            ServiceError::InvalidBase64(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "invalid_request".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::InvalidPeerId(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "invalid_peer_id".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::InvalidAttestationRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "invalid_attestation_request".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::RateLimited(msg) => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorResponse {
                    error: "rate_limited".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::InvalidChallenge(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "invalid_challenge".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::InvalidPeerPublicKey(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "invalid_peer_public_key".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::InvalidSignature(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "invalid_signature".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::AttestationVerificationFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "attestation_verification_failed".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::MockAttestationRejected => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "mock_attestation_rejected".to_string(),
                    details: Some(
                        "Mock attestations are not accepted in production mode".to_string(),
                    ),
                },
            ),
            ServiceError::PeerIdentityMismatch => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "peer_identity_mismatch".to_string(),
                    details: Some(
                        "The provided peer public key does not correspond to the claimed peer ID"
                            .to_string(),
                    ),
                },
            ),
            ServiceError::PeerIdMismatch => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse {
                    error: "peer_id_mismatch".to_string(),
                    details: Some(
                        "The peer ID in the attestation does not match the claimed peer ID"
                            .to_string(),
                    ),
                },
            ),
            ServiceError::TcbStatusRejected(msg) => (
                StatusCode::FORBIDDEN,
                ErrorResponse {
                    error: "tcb_status_rejected".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::MeasurementPolicyRejected(msg) => (
                StatusCode::FORBIDDEN,
                ErrorResponse {
                    error: "measurement_policy_rejected".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::PolicyNotReady(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse {
                    error: "policy_not_ready".to_string(),
                    details: Some(msg.clone()),
                },
            ),
            ServiceError::KeyDerivationFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: "key_derivation_failed".to_string(),
                    details: Some(msg.clone()),
                },
            ),
        };

        (status, Json(error_response)).into_response()
    }
}
