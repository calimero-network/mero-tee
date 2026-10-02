//! `/attest` endpoint: returns a KMS quote for client verification.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::errors::ServiceError;
use super::AppState;
use crate::sealed;

/// Request body for the KMS attestation endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsAttestRequest {
    /// Base64-encoded 32-byte client nonce for freshness.
    pub nonce_b64: String,
    /// Optional base64-encoded 32-byte binding value for channel/session binding.
    #[serde(default)]
    pub binding_b64: Option<String>,
    /// Report this service's transport key and commit to it in the quote, so
    /// the caller can have `/get-key` seal the key it releases (see `sealed`).
    #[serde(default)]
    pub transport_key: bool,
    /// Also return this TD's event log, so a verifier can see which measured
    /// event makes two TDs' registers differ.
    #[serde(default)]
    pub event_log: bool,
}

/// Response body for the KMS attestation endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsAttestResponse {
    /// Base64-encoded raw TDX quote bytes.
    pub quote_b64: String,
    /// Hex-encoded 64-byte report_data used for quote generation.
    pub report_data_hex: String,
    /// Base64 X25519 transport key, present when the request asked for it. The
    /// quote's report data then commits to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_public_key_b64: Option<String>,
    /// Base64 CCEL event log, present when the request asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_log_b64: Option<String>,
}

/// Handler for KMS self-attestation.
///
/// This endpoint allows callers (for example, merod) to verify the KMS instance
/// measurement with a fresh nonce before requesting key material.
pub(crate) async fn attest_kms_handler(
    State(state): State<AppState>,
    Json(request): Json<KmsAttestRequest>,
) -> Result<Json<KmsAttestResponse>, ServiceError> {
    let nonce = decode_fixed_b64_32("nonceB64", &request.nonce_b64)?;
    let binding = resolve_attestation_binding(request.binding_b64.as_deref())?;
    let (binding, transport_public) = if request.transport_key {
        let transport = state.backend.transport_key()?;
        let public = *transport.public();
        (sealed::attest_binding(&binding, &public), Some(public))
    } else {
        (plain_attest_binding(&binding), None)
    };
    let report_data = build_attestation_report_data(&nonce, &binding);
    let quote = state.backend.quote(report_data).await?.quote_bytes;
    let event_log = if request.event_log {
        Some(BASE64.encode(state.backend.event_log().await?))
    } else {
        None
    };

    Ok(Json(KmsAttestResponse {
        quote_b64: BASE64.encode(quote),
        report_data_hex: hex::encode(report_data),
        transport_public_key_b64: transport_public.map(|public| BASE64.encode(public)),
        event_log_b64: event_log,
    }))
}

pub(crate) fn decode_fixed_b64_32(field_name: &str, value: &str) -> Result<[u8; 32], ServiceError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|e| ServiceError::InvalidAttestationRequest(format!("{}: {}", field_name, e)))?;
    decoded.try_into().map_err(|_| {
        ServiceError::InvalidAttestationRequest(format!("{} must be exactly 32 bytes", field_name))
    })
}

/// Domain separation label used to derive the default attestation binding.
const ATTEST_DOMAIN_SEPARATOR: &[u8] = b"mero-kms-attest-v1";

/// Domain-separated default binding when the caller doesn't supply one.
/// Ensures the second half of report_data is never all-zeros.
fn default_attestation_binding() -> [u8; 32] {
    Sha256::digest(ATTEST_DOMAIN_SEPARATOR).into()
}

/// Domain of the 32 bytes `/attest` puts after the nonce when it reports no
/// transport key.
const PLAIN_ATTEST_DOMAIN: &[u8] = b"mero-kms/attest-plain/v1";

/// The 32 bytes `/attest` puts after the nonce when it reports no transport key.
///
/// Never the caller's bytes as given. This TD signs `/cluster/join` quotes
/// (`nonce ‖ join_binding`), `/cluster/join` responses (`nonce ‖ give_binding`)
/// and transport-key commitments (`nonce ‖ sealed::attest_binding`), and all of
/// those bindings are hashes anyone can compute. If this unauthenticated
/// endpoint signed a caller's 32 bytes verbatim, a caller could ask for exactly
/// one of those quotes, with the measurements of this replica, without holding
/// a TD: join the cluster and be handed its root, or vouch for a transport key
/// of its own. Hashed under a domain of its own, the output collides with none
/// of them.
fn plain_attest_binding(binding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAIN_ATTEST_DOMAIN);
    hasher.update(binding);
    hasher.finalize().into()
}

pub(crate) fn resolve_attestation_binding(
    binding_b64: Option<&str>,
) -> Result<[u8; 32], ServiceError> {
    match binding_b64 {
        Some(value) => decode_fixed_b64_32("bindingB64", value),
        None => Ok(default_attestation_binding()),
    }
}

/// Pack nonce (bytes 0..32) and binding (bytes 32..64) into the 64-byte
/// TDX report_data field. The verifier reconstructs this to check the quote.
pub(crate) fn build_attestation_report_data(nonce: &[u8; 32], binding: &[u8; 32]) -> [u8; 64] {
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(nonce);
    report_data[32..].copy_from_slice(binding);
    report_data
}
