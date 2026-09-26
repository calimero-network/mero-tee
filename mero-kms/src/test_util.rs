//! Shared test helpers available to all `#[cfg(test)]` modules.

use calimero_server_primitives::admin::{
    CertificationData, QeReportCertificationDataInfo, Quote, QuoteBody, QuoteHeader,
};

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
    "MERO_KMS_REQUIRE_SEALED_KEY_RELEASE",
    "USE_ENV_POLICY",
    "ALLOWED_TCB_STATUSES",
    "ALLOWED_MRTD",
    "ALLOWED_RTMR0",
    "ALLOWED_RTMR1",
    "ALLOWED_RTMR2",
    "ALLOWED_RTMR3",
    "MERO_KMS_BACKEND",
    "MERO_KMS_BOOTSTRAP",
    "MERO_KMS_PEERS",
    "MERO_KMS_JOIN_RETRY_SECS",
];

/// Return a valid 96-character hex string (`"ab"` repeated 48 times) suitable
/// for use as a TDX measurement register value in tests.
pub fn valid_measurement_hex() -> String {
    "ab".repeat(MEASUREMENT_BYTES)
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

/// A quote with every register zeroed, as a mock quote reports, carrying
/// `report_data`. Built by hand so tests using it run without the
/// `mock-attestation` feature.
pub fn zero_quote(report_data: &[u8; 64]) -> Quote {
    let zero_48b = "0".repeat(96);
    let zero_16b = "0".repeat(32);
    let zero_8b = "0".repeat(16);

    Quote {
        header: QuoteHeader {
            version: 4,
            attestation_key_type: 2,
            tee_type: 0x81,
            qe_vendor_id: "939a7233f79c4ca9940a0db3957f0607".to_owned(),
            user_data: zero_16b.clone(),
        },
        body: QuoteBody {
            tdx_version: "1.0".to_owned(),
            tee_tcb_svn: zero_16b,
            mrseam: zero_48b.clone(),
            mrsignerseam: zero_48b.clone(),
            seamattributes: zero_8b.clone(),
            tdattributes: zero_8b.clone(),
            xfam: zero_8b,
            mrtd: zero_48b.clone(),
            mrconfigid: zero_48b.clone(),
            mrowner: zero_48b.clone(),
            mrownerconfig: zero_48b.clone(),
            rtmr0: zero_48b.clone(),
            rtmr1: zero_48b.clone(),
            rtmr2: zero_48b.clone(),
            rtmr3: zero_48b,
            reportdata: hex::encode(report_data),
            tee_tcb_svn_2: None,
            mrservicetd: None,
        },
        signature: "0".repeat(128),
        attestation_key: "04".to_owned() + &"0".repeat(128),
        certification_data: CertificationData::QeReportCertificationData(
            QeReportCertificationDataInfo {
                qe_report: "0".repeat(768),
                signature: "0".repeat(128),
                qe_authentication_data: "0".repeat(64),
                certification_data_type: "PckCertChain".to_owned(),
                certification_data: "0".repeat(200),
            },
        ),
    }
}
