//! Shared test helpers available to all `#[cfg(test)]` modules.

use crate::util::MEASUREMENT_BYTES;

pub const ENV_KEYS: &[&str] = &[
    "LISTEN_ADDR",
    "DSTACK_SOCKET_PATH",
    "CHALLENGE_TTL_SECS",
    "MAX_PENDING_CHALLENGES",
    "ACCEPT_MOCK_ATTESTATION",
    "REDIS_URL",
    "MERO_KMS_VERSION",
    "MERO_KMS_PROFILE",
    "KMS_POLICY_PROFILE",
    "KEY_NAMESPACE_PREFIX",
    "MERO_KMS_POLICY_SHA256",
    "CORS_ALLOWED_ORIGINS",
    "ENFORCE_MEASUREMENT_POLICY",
    "USE_ENV_POLICY",
    "ALLOWED_TCB_STATUSES",
    "ALLOWED_MRTD",
    "ALLOWED_RTMR0",
    "ALLOWED_RTMR1",
    "ALLOWED_RTMR2",
    "ALLOWED_RTMR3",
];

pub fn valid_measurement_hex() -> String {
    "ab".repeat(MEASUREMENT_BYTES)
}

pub async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read response body");
    serde_json::from_slice(&body).expect("response body must be valid json")
}
