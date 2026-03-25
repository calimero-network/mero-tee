//! `/get-key` endpoint: verifies node attestation/signature and derives key.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use calimero_tee_attestation::{
    is_mock_quote, verify_attestation, verify_mock_attestation, VerificationResult,
};
use dstack_sdk::dstack_client::DstackClient;
use libp2p_identity::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::policy::AttestationPolicy;
use crate::util::CHALLENGE_ID_HEX_LEN;
use crate::Config;

use super::challenge::validate_peer_id_shape;
use super::errors::ServiceError;
use super::AppState;

/// Request body for the get-key endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyRequest {
    pub challenge_id: String,
    pub quote_b64: String,
    pub peer_id: String,
    pub peer_public_key_b64: String,
    pub signature_b64: String,
}

/// Response body for the get-key endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyResponse {
    pub key: String,
}

/// Key release flow: validate inputs → consume single-use challenge → verify
/// peer signature → verify TDX attestation → enforce measurement policy → derive key via dstack.
///
/// The challenge is consumed *before* signature/attestation checks so that a
/// replayed request always fails on the second attempt regardless of where
/// the first attempt errored.
pub(crate) async fn get_key_handler(
    State(state): State<AppState>,
    Json(request): Json<GetKeyRequest>,
) -> Result<Json<GetKeyResponse>, ServiceError> {
    validate_peer_id_shape(&request.peer_id)?;
    validate_challenge_id(&request.challenge_id)?;
    ensure_policy_ready_for_key_release(&state.config)?;
    info!(peer_id = %request.peer_id, "Received key release request");

    let quote_bytes = BASE64
        .decode(&request.quote_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;
    debug!(quote_len = quote_bytes.len(), "Decoded quote");

    let challenge_nonce = state
        .challenge_store
        .consume(&request.challenge_id, &request.peer_id)
        .await
        .map_err(|msg| {
            ServiceError::InvalidChallenge(format!("Challenge validation failed: {}", msg))
        })?;

    verify_peer_signature(
        &request.peer_id,
        &request.peer_public_key_b64,
        &request.signature_b64,
        &request.challenge_id,
        &challenge_nonce,
        &quote_bytes,
    )?;

    let is_mock = is_mock_quote(&quote_bytes);
    if is_mock {
        if state.config.accept_mock_attestation {
            warn!(
                peer_id = %request.peer_id,
                "Accepting mock attestation (development mode)"
            );
        } else {
            error!(
                peer_id = %request.peer_id,
                "Mock attestation rejected (production mode)"
            );
            return Err(ServiceError::MockAttestationRejected);
        }
    }

    let peer_id_hash = hash_peer_id(&request.peer_id);
    debug!(
        peer_id = %request.peer_id,
        peer_id_hash = %hex::encode(peer_id_hash),
        "Created peer ID hash for verification"
    );

    let verification_result = if is_mock {
        verify_mock_attestation(&quote_bytes, &challenge_nonce, Some(&peer_id_hash))
            .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?
    } else {
        verify_attestation(&quote_bytes, &challenge_nonce, Some(&peer_id_hash))
            .await
            .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?
    };

    if !verification_result.is_valid() {
        error!(
            peer_id = %request.peer_id,
            quote_verified = verification_result.quote_verified,
            nonce_verified = verification_result.nonce_verified,
            app_hash_verified = ?verification_result.application_hash_verified,
            "Attestation verification failed"
        );

        if !verification_result.nonce_verified {
            return Err(ServiceError::InvalidChallenge(
                "Attested nonce does not match issued challenge".to_owned(),
            ));
        }

        if verification_result.application_hash_verified == Some(false) {
            return Err(ServiceError::PeerIdMismatch);
        }

        return Err(ServiceError::AttestationVerificationFailed(
            "Quote cryptographic verification failed".to_string(),
        ));
    }

    info!(
        peer_id = %request.peer_id,
        "Attestation verified successfully"
    );

    if !is_mock {
        enforce_attestation_policy(&state.config, &verification_result)?;
    } else {
        warn!("Skipping measurement policy checks for accepted mock attestation");
    }

    let key_path = key_path_for_peer(&state.config, &request.peer_id);
    let client = DstackClient::new(Some(&state.config.dstack_socket_path));
    let key_response = client
        .get_key(Some(key_path), None)
        .await
        .map_err(|e| ServiceError::KeyDerivationFailed(e.to_string()))?;

    info!(peer_id = %request.peer_id, "Key derived successfully");
    Ok(Json(GetKeyResponse {
        key: key_response.key,
    }))
}

/// SHA-256 hash of the peer ID string, used as the `application_data` binding
/// in the TDX quote so the attestation is tied to a specific node identity.
pub(crate) fn hash_peer_id(peer_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(peer_id.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn validate_challenge_id(challenge_id: &str) -> Result<(), ServiceError> {
    if challenge_id.len() != CHALLENGE_ID_HEX_LEN
        || !challenge_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ServiceError::InvalidChallenge(format!(
            "challenge ID must be {} hex characters",
            CHALLENGE_ID_HEX_LEN
        )));
    }
    Ok(())
}

/// Build the dstack key derivation path: `{namespace}/{profile}/{peerId}`.
/// This ensures each profile+peer combination gets a unique deterministic key.
fn key_path_for_peer(config: &Config, peer_id: &str) -> String {
    format!(
        "{}/{}/{}",
        config.key_namespace_prefix.trim_matches('/'),
        config.kms_profile,
        peer_id
    )
}

/// Verify that the claimed peer ID owns the supplied public key and that the
/// signature covers a deterministic payload binding the challenge, quote, and peer ID.
/// This prevents a node from requesting keys for a different peer ID.
pub(crate) fn verify_peer_signature(
    peer_id: &str,
    peer_public_key_b64: &str,
    signature_b64: &str,
    challenge_id: &str,
    challenge_nonce: &[u8; 32],
    quote_bytes: &[u8],
) -> Result<(), ServiceError> {
    let public_key_bytes = BASE64
        .decode(peer_public_key_b64)
        .map_err(|e| ServiceError::InvalidPeerPublicKey(e.to_string()))?;
    let signature_bytes = BASE64
        .decode(signature_b64)
        .map_err(|e| ServiceError::InvalidSignature(e.to_string()))?;

    let public_key = PublicKey::try_decode_protobuf(&public_key_bytes)
        .map_err(|e| ServiceError::InvalidPeerPublicKey(e.to_string()))?;
    let derived_peer_id = public_key.to_peer_id().to_base58();
    if derived_peer_id != peer_id {
        return Err(ServiceError::PeerIdentityMismatch);
    }

    let payload = build_signature_payload(challenge_id, challenge_nonce, quote_bytes, peer_id)?;
    if !public_key.verify(&payload, &signature_bytes) {
        return Err(ServiceError::InvalidSignature(
            "signature verification failed".to_owned(),
        ));
    }
    Ok(())
}

/// Canonical JSON payload that the node must sign. Includes the challenge ID,
/// nonce, SHA-256 of the quote (not the quote itself, to keep the payload small),
/// and the peer ID. Deterministic serialization via `serde_json::to_vec`.
pub(crate) fn build_signature_payload(
    challenge_id: &str,
    challenge_nonce: &[u8; 32],
    quote_bytes: &[u8],
    peer_id: &str,
) -> Result<Vec<u8>, ServiceError> {
    let quote_hash = Sha256::digest(quote_bytes);
    serde_json::to_vec(&serde_json::json!({
        "challengeId": challenge_id,
        "challengeNonceHex": hex::encode(challenge_nonce),
        "quoteHashHex": hex::encode(quote_hash),
        "peerId": peer_id,
    }))
    .map_err(|e| ServiceError::InvalidSignature(format!("failed to serialize payload: {}", e)))
}

/// Verify that the quote's TCB status and all five TDX measurement registers
/// (MRTD, RTMR0-3) match the loaded attestation policy. Skipped entirely when
/// `enforce_measurement_policy` is false (dev/debug only).
pub(crate) fn enforce_attestation_policy(
    config: &Config,
    verification_result: &VerificationResult,
) -> Result<(), ServiceError> {
    let policy = &config.attestation_policy;
    if !policy.enforce_measurement_policy {
        return Ok(());
    }

    enforce_tcb_status(policy, verification_result)?;

    let body = &verification_result.quote.body;
    let register_checks: [(&str, &str, &[crate::measurement::HexMeasurement]); 5] = [
        ("MRTD", &body.mrtd, &policy.allowed_mrtd),
        ("RTMR0", &body.rtmr0, &policy.allowed_rtmr0),
        ("RTMR1", &body.rtmr1, &policy.allowed_rtmr1),
        ("RTMR2", &body.rtmr2, &policy.allowed_rtmr2),
        ("RTMR3", &body.rtmr3, &policy.allowed_rtmr3),
    ];

    for (label, actual, allowlist) in register_checks {
        AttestationPolicy::check_measurement(allowlist, label, actual)
            .map_err(|(_, msg)| ServiceError::MeasurementPolicyRejected(msg))?;
    }

    Ok(())
}

fn enforce_tcb_status(
    policy: &AttestationPolicy,
    verification_result: &VerificationResult,
) -> Result<(), ServiceError> {
    let actual_tcb_status = verification_result.tcb_status.clone().ok_or_else(|| {
        ServiceError::TcbStatusRejected(
            "Quote verification did not provide a TCB status".to_owned(),
        )
    })?;
    let normalized = actual_tcb_status.to_ascii_lowercase();
    if !policy
        .allowed_tcb_statuses
        .iter()
        .any(|allowed| allowed == &normalized)
    {
        return Err(ServiceError::TcbStatusRejected(format!(
            "TCB status '{}' is not allowed. Allowed values: {}",
            actual_tcb_status,
            policy.allowed_tcb_statuses.join(", ")
        )));
    }
    Ok(())
}

pub(crate) fn ensure_policy_ready_for_key_release(config: &Config) -> Result<(), ServiceError> {
    if config.policy_ready {
        return Ok(());
    }
    let details = config.policy_unavailable_reason.clone().unwrap_or_else(|| {
        "Attestation policy is not ready yet. Set MERO_KMS_VERSION and MERO_KMS_PROFILE, or use explicit USE_ENV_POLICY mode.".to_string()
    });
    Err(ServiceError::PolicyNotReady(details))
}
