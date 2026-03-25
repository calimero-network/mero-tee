//! Shared test helpers available to all `#[cfg(test)]` modules.

use crate::util::MEASUREMENT_BYTES;

/// All environment variable names read by [`Config::from_env`](crate::Config),
/// used by test guards to snapshot and restore env state.
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

/// Return a valid 96-character hex string (`"ab"` repeated 48 times) suitable
/// for use as a TDX measurement register value in tests.
pub fn valid_measurement_hex() -> String {
    "ab".repeat(MEASUREMENT_BYTES)
}

/// Build a minimal mock TDX quote with the given nonce embedded in report_data.
pub fn create_mock_quote(nonce: &[u8; 32]) -> Vec<u8> {
    let mut quote = b"MOCK_TDX_QUOTE_V1".to_vec();
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(nonce);
    quote.extend_from_slice(&report_data);
    quote.resize(256, 0);
    quote
}

/// Read the full body of an Axum response and parse it as JSON.
///
/// Panics if the body cannot be read or is not valid JSON.
pub async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read response body");
    serde_json::from_slice(&body).expect("response body must be valid json")
}
