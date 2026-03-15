//! Runtime-event helpers for profile measurement separation.

use dstack_attest::{ccel::RuntimeEvent, emit_runtime_event};
use eyre::{bail, Result as EyreResult};
use tracing::info;

const KMS_PROFILE_RUNTIME_EVENT_NAME: &str = "calimero.kms.profile";

pub fn kms_profile_runtime_event_payload(profile: &str) -> Vec<u8> {
    format!("calimero.kms.profile={}", profile).into_bytes()
}

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
