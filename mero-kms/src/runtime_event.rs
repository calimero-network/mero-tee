//! Runtime-event helpers for KMS profile measurement separation.
//!
//! Emits a dstack runtime event that extends RTMR3, binding the KMS instance
//! to a specific profile (e.g. `locked-read-only`). This lets the attestation
//! policy distinguish between KMS images built for different profiles even
//! when the base image is identical.

use dstack_attest::{ccel::RuntimeEvent, emit_runtime_event};
use eyre::{bail, Result as EyreResult};
use tracing::info;

const KMS_PROFILE_RUNTIME_EVENT_NAME: &str = "calimero.kms.profile";

pub fn kms_profile_runtime_event_payload(profile: &str) -> Vec<u8> {
    format!("calimero.kms.profile={}", profile).into_bytes()
}

/// Emit the profile runtime event if not already present, or verify the
/// existing event matches the selected profile. Fails hard if a *different*
/// profile event exists, preventing mixed-profile key derivation.
pub fn ensure_kms_profile_runtime_event(profile: &str) -> EyreResult<()> {
    let expected_payload = kms_profile_runtime_event_payload(profile);
    let events = RuntimeEvent::read_all()
        .map_err(|e| eyre::eyre!("Failed to read runtime event log: {}", e))?;

    if let Some(existing) = events
        .iter()
        .find(|event| event.event == KMS_PROFILE_RUNTIME_EVENT_NAME)
    {
        if existing.payload == expected_payload {
            info!(
                "KMS profile runtime event already present: {}={}",
                KMS_PROFILE_RUNTIME_EVENT_NAME, profile
            );
            return Ok(());
        }
        bail!(
            "Existing runtime event '{}' payload does not match selected profile '{}'; \
             refusing startup to avoid mixed profile measurements.",
            KMS_PROFILE_RUNTIME_EVENT_NAME,
            profile
        );
    }

    emit_runtime_event(KMS_PROFILE_RUNTIME_EVENT_NAME, &expected_payload).map_err(|e| {
        eyre::eyre!(
            "Failed to emit runtime event '{}': {}",
            KMS_PROFILE_RUNTIME_EVENT_NAME,
            e
        )
    })?;
    info!(
        "Emitted runtime event to extend RTMR3: {}={}",
        KMS_PROFILE_RUNTIME_EVENT_NAME, profile
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::kms_profile_runtime_event_payload;

    #[test]
    fn kms_profile_runtime_event_payload_contains_profile() {
        let payload = kms_profile_runtime_event_payload("debug");
        assert_eq!(payload, b"calimero.kms.profile=debug".to_vec());
    }
}
