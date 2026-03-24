//! Shared API error types and HTTP mapping for handler modules.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Error response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Service-level errors with automatic `Display` and `std::error::Error` via thiserror.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid peer ID: {0}")]
    InvalidPeerId(String),
    #[error("invalid attestation request: {0}")]
    InvalidAttestationRequest(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("invalid challenge: {0}")]
    InvalidChallenge(String),
    #[error("invalid peer public key: {0}")]
    InvalidPeerPublicKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("attestation verification failed: {0}")]
    AttestationVerificationFailed(String),
    #[error("mock attestation rejected: mock attestations are not accepted in production mode")]
    MockAttestationRejected,
    #[error("peer identity mismatch: the provided peer public key does not correspond to the claimed peer ID")]
    PeerIdentityMismatch,
    #[error("peer ID mismatch: the peer ID in the attestation does not match the claimed peer ID")]
    PeerIdMismatch,
    #[error("TCB status rejected: {0}")]
    TcbStatusRejected(String),
    #[error("measurement policy rejected: {0}")]
    MeasurementPolicyRejected(String),
    #[error("policy not ready: {0}")]
    PolicyNotReady(String),
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

impl ServiceError {
    /// Map each variant to its HTTP status code and machine-readable error tag.
    fn status_and_tag(&self) -> (StatusCode, &'static str) {
        match self {
            Self::InvalidBase64(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidPeerId(_) => (StatusCode::BAD_REQUEST, "invalid_peer_id"),
            Self::InvalidAttestationRequest(_) => {
                (StatusCode::BAD_REQUEST, "invalid_attestation_request")
            }
            Self::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::InvalidChallenge(_) => (StatusCode::UNAUTHORIZED, "invalid_challenge"),
            Self::InvalidPeerPublicKey(_) => (StatusCode::BAD_REQUEST, "invalid_peer_public_key"),
            Self::InvalidSignature(_) => (StatusCode::UNAUTHORIZED, "invalid_signature"),
            Self::AttestationVerificationFailed(_) => {
                (StatusCode::UNAUTHORIZED, "attestation_verification_failed")
            }
            Self::MockAttestationRejected => {
                (StatusCode::UNAUTHORIZED, "mock_attestation_rejected")
            }
            Self::PeerIdentityMismatch => (StatusCode::UNAUTHORIZED, "peer_identity_mismatch"),
            Self::PeerIdMismatch => (StatusCode::UNAUTHORIZED, "peer_id_mismatch"),
            Self::TcbStatusRejected(_) => (StatusCode::FORBIDDEN, "tcb_status_rejected"),
            Self::MeasurementPolicyRejected(_) => {
                (StatusCode::FORBIDDEN, "measurement_policy_rejected")
            }
            Self::PolicyNotReady(_) => (StatusCode::SERVICE_UNAVAILABLE, "policy_not_ready"),
            Self::KeyDerivationFailed(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "key_derivation_failed")
            }
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        let (status, tag) = self.status_and_tag();
        let details = self.to_string();
        let error_response = ErrorResponse {
            error: tag.to_string(),
            details: Some(details),
        };
        (status, Json(error_response)).into_response()
    }
}
