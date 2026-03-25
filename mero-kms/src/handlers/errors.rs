//! Shared API error types and HTTP mapping for handler modules.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// JSON error response body returned by all handler error paths.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    /// Machine-readable error tag (e.g. `"invalid_request"`, `"rate_limited"`).
    pub error: String,
    /// Optional human-readable details about the error, omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(details) = &self.details {
            write!(f, ": {}", details)?;
        }
        Ok(())
    }
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
    /// Map each variant to its HTTP status code, machine-readable error tag,
    /// and human-readable details string. Consumes `self` to avoid cloning
    /// the inner `String` payloads.
    fn into_parts(self) -> (StatusCode, &'static str, Option<String>) {
        match self {
            Self::InvalidBase64(msg) => (StatusCode::BAD_REQUEST, "invalid_request", Some(msg)),
            Self::InvalidPeerId(msg) => (StatusCode::BAD_REQUEST, "invalid_peer_id", Some(msg)),
            Self::InvalidAttestationRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_attestation_request",
                Some(msg),
            ),
            Self::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", Some(msg)),
            Self::InvalidChallenge(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_challenge", Some(msg))
            }
            Self::InvalidPeerPublicKey(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_peer_public_key",
                Some(msg),
            ),
            Self::InvalidSignature(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_signature", Some(msg))
            }
            Self::AttestationVerificationFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                "attestation_verification_failed",
                Some(msg),
            ),
            Self::MockAttestationRejected => (
                StatusCode::UNAUTHORIZED,
                "mock_attestation_rejected",
                Some("Mock attestations are not accepted in production mode".to_string()),
            ),
            Self::PeerIdentityMismatch => (
                StatusCode::UNAUTHORIZED,
                "peer_identity_mismatch",
                Some(
                    "The provided peer public key does not correspond to the claimed peer ID"
                        .to_string(),
                ),
            ),
            Self::PeerIdMismatch => (
                StatusCode::UNAUTHORIZED,
                "peer_id_mismatch",
                Some(
                    "The peer ID in the attestation does not match the claimed peer ID".to_string(),
                ),
            ),
            Self::TcbStatusRejected(msg) => {
                (StatusCode::FORBIDDEN, "tcb_status_rejected", Some(msg))
            }
            Self::MeasurementPolicyRejected(msg) => (
                StatusCode::FORBIDDEN,
                "measurement_policy_rejected",
                Some(msg),
            ),
            Self::PolicyNotReady(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_not_ready",
                Some(msg),
            ),
            Self::KeyDerivationFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_derivation_failed",
                Some(msg),
            ),
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        let (status, tag, details) = self.into_parts();
        let error_response = ErrorResponse {
            error: tag.to_string(),
            details,
        };
        (status, Json(error_response)).into_response()
    }
}
