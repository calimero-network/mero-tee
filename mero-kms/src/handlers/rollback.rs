//! `/rollback/raise` and `/rollback/reset`: a node moves its counter.
//!
//! Neither takes a quote. A v2 key release (`get_key`) sealed a session key to
//! the attested TD, derived from the root, the cluster's key path, the node id
//! and a random session id, so any replica recomputes it and none stores it.
//! Each call is MACed under it, over a domain and every field, and so is the
//! answer, over the node's nonce: a relay can neither move a counter nor fake
//! an acknowledgement. A raise only ever moves the entry up, so a replayed one
//! changes nothing; a reset is the operator's forced rollback (merod's
//! `--accept-rollback`): one epoch up, the entry set to the store's mark.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::hmac;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::counters::{session_key_info, ClusterCounters, Entry};
use crate::policy::Role;

use super::challenge::validate_peer_id_shape;
use super::errors::ServiceError;
use super::get_key::key_path_for_peer;
use super::AppState;

pub(crate) const RAISE_DOMAIN: &[u8] = b"mero-kms/rollback-raise/v1";
pub(crate) const RESET_DOMAIN: &[u8] = b"mero-kms/rollback-reset/v1";
pub(crate) const ACK_DOMAIN: &[u8] = b"mero-kms/rollback-ack/v1";

/// A raise or a reset.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackRequest {
    pub peer_id: String,
    pub node_id: u64,
    /// The 16-byte session id a v2 release sealed with its session key.
    pub session_id_b64: String,
    pub generation: u64,
    pub mark: u64,
    /// 32 fresh bytes; the acknowledgement's MAC covers them.
    pub nonce_b64: String,
    pub mac_b64: String,
}

/// The node's entry and the cluster's epoch after the call, MACed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackAck {
    pub epoch: u64,
    pub generation: u64,
    pub mark: u64,
    pub mac_b64: String,
}

/// What a raise or reset MACs: `domain ‖ peerId ‖ "\n" ‖ nodeId (8 BE) ‖
/// sessionId ‖ generation (8 BE) ‖ mark (8 BE) ‖ nonce`.
pub(crate) fn request_message(
    domain: &[u8],
    peer_id: &str,
    node_id: u64,
    session_id: &[u8; 16],
    generation: u64,
    mark: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + peer_id.len() + 73);
    message.extend_from_slice(domain);
    message.extend_from_slice(peer_id.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(&node_id.to_be_bytes());
    message.extend_from_slice(session_id);
    message.extend_from_slice(&generation.to_be_bytes());
    message.extend_from_slice(&mark.to_be_bytes());
    message.extend_from_slice(nonce);
    message
}

/// The acknowledgement's MAC: `"mero-kms/rollback-ack/v1" ‖ nonce ‖ epoch ‖
/// generation ‖ mark` (each 8 BE).
pub(crate) fn ack_mac(
    session_key: &[u8],
    nonce: &[u8; 32],
    epoch: u64,
    generation: u64,
    mark: u64,
) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, session_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(ACK_DOMAIN);
    ctx.update(nonce);
    ctx.update(&epoch.to_be_bytes());
    ctx.update(&generation.to_be_bytes());
    ctx.update(&mark.to_be_bytes());
    ctx.sign()
}

pub(crate) async fn raise_handler(
    State(state): State<AppState>,
    Json(request): Json<RollbackRequest>,
) -> Result<Json<RollbackAck>, ServiceError> {
    handle(&state, &request, Kind::Raise).await
}

pub(crate) async fn reset_handler(
    State(state): State<AppState>,
    Json(request): Json<RollbackRequest>,
) -> Result<Json<RollbackAck>, ServiceError> {
    handle(&state, &request, Kind::Reset).await
}

#[derive(Clone, Copy)]
enum Kind {
    Raise,
    Reset,
}

async fn handle(
    state: &AppState,
    request: &RollbackRequest,
    kind: Kind,
) -> Result<Json<RollbackAck>, ServiceError> {
    if let Err(e) = validate_peer_id_shape(&request.peer_id) {
        warn!("Refused a rollback call: {e}");
        return Err(e);
    }
    let answered = answer(state, request, kind).await;
    if let Err(e) = &answered {
        warn!(peer_id = %request.peer_id, node = request.node_id, "Refused a rollback call: {e}");
    }
    answered
}

async fn answer(
    state: &AppState,
    request: &RollbackRequest,
    kind: Kind,
) -> Result<Json<RollbackAck>, ServiceError> {
    let session_id: [u8; 16] = BASE64
        .decode(&request.session_id_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?
        .try_into()
        .map_err(|_| {
            ServiceError::InvalidAttestationRequest("sessionIdB64 must be 16 bytes".to_owned())
        })?;
    let nonce = super::decode_fixed_b64_32("nonceB64", &request.nonce_b64)?;
    let mac = BASE64
        .decode(&request.mac_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;

    let key_path = key_path_for_peer(&state.config, Role::Node, &request.peer_id);
    let session_key = state.backend.rollback_session_key(&session_key_info(
        &key_path,
        request.node_id,
        &session_id,
    ))?;
    let domain = match kind {
        Kind::Raise => RAISE_DOMAIN,
        Kind::Reset => RESET_DOMAIN,
    };
    let message = request_message(
        domain,
        &request.peer_id,
        request.node_id,
        &session_id,
        request.generation,
        request.mark,
        &nonce,
    );
    // `hmac::verify` compares in constant time.
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, &*session_key),
        &message,
        &mac,
    )
    .map_err(|_| ServiceError::InvalidMac("the rollback call's MAC".to_owned()))?;

    let counters: ClusterCounters = match kind {
        Kind::Raise => {
            let entry = Entry {
                generation: request.generation,
                mark: request.mark,
            };
            state
                .counters
                .raise(&state.backend, &key_path, request.node_id, entry)
                .await?
        }
        Kind::Reset => {
            let counters = state
                .counters
                .reset(&state.backend, &key_path, request.node_id, request.mark)
                .await?;
            warn!(
                peer_id = %request.peer_id,
                node = request.node_id,
                mark = request.mark,
                epoch = counters.epoch,
                "Forced a rollback: the node's counter is set to its store's"
            );
            counters
        }
    };
    let entry = counters
        .nodes
        .get(&request.node_id)
        .copied()
        .unwrap_or_default();
    if matches!(kind, Kind::Raise) {
        debug!(
            node = request.node_id,
            mark = entry.mark,
            "Raised a rollback counter"
        );
    }
    let tag = ack_mac(
        &*session_key,
        &nonce,
        counters.epoch,
        entry.generation,
        entry.mark,
    );
    Ok(Json(RollbackAck {
        epoch: counters.epoch,
        generation: entry.generation,
        mark: entry.mark,
        mac_b64: BASE64.encode(tag.as_ref()),
    }))
}

#[cfg(test)]
#[path = "rollback_tests.rs"]
mod tests;
