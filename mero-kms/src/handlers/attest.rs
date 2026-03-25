//! `/attest` endpoint: returns KMS quote + event log for client verification.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dstack_sdk::dstack_client::DstackClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::errors::ServiceError;
use super::AppState;

/// Request body for the KMS attestation endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsAttestRequest {
    /// Base64-encoded 32-byte client nonce for freshness.
    pub nonce_b64: String,
    /// Optional base64-encoded 32-byte binding value for channel/session binding.
    #[serde(default)]
    pub binding_b64: Option<String>,
}

/// Response body for the KMS attestation endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsAttestResponse {
    /// Base64-encoded raw TDX quote bytes.
    pub quote_b64: String,
    /// Hex-encoded 64-byte report_data used for quote generation.
    pub report_data_hex: String,
    /// Parsed event log entries associated with the quote.
    pub event_log: serde_json::Value,
    /// VM config string returned by dstack quote API.
    pub vm_config: String,
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
    let report_data = build_attestation_report_data(&nonce, &binding);

    let client = DstackClient::new(Some(&state.config.dstack_socket_path));
    let quote_response = client
        .get_quote(report_data.to_vec())
        .await
        .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?;

    let quote_bytes = hex::decode(&quote_response.quote).map_err(|e| {
        ServiceError::AttestationVerificationFailed(format!(
            "dstack returned invalid quote hex: {}",
            e
        ))
    })?;

    let parsed_event_log = serde_json::from_str::<serde_json::Value>(&quote_response.event_log)
        .map_err(|e| {
            ServiceError::AttestationVerificationFailed(format!(
                "dstack returned invalid event log json: {}",
                e
            ))
        })?;

    Ok(Json(KmsAttestResponse {
        quote_b64: BASE64.encode(quote_bytes),
        report_data_hex: hex::encode(report_data),
        event_log: parsed_event_log,
        vm_config: quote_response.vm_config,
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

/// Domain-separated default binding when the caller doesn't supply one.
/// Ensures the second half of report_data is never all-zeros.
fn default_attestation_binding() -> [u8; 32] {
    Sha256::digest(b"mero-kms-phala-attest-v1").into()
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
