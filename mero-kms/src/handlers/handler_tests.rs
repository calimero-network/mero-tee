//! Integration tests for the HTTP handler layer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use libp2p_identity::Keypair;
use tower::util::ServiceExt;

use crate::test_util::read_json_body;
use crate::AttestationPolicy;

use super::errors::ServiceError;
use super::*;

fn post_json_request(uri: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request should build")
}

/// Build a `VerificationResult` fixture for exercising the *real* measurement
/// policy machinery (`enforce_attestation_policy`).
///
/// This is deliberately built by hand from `calimero_server_primitives` types
/// rather than via core's `verify_mock_attestation`, so that the policy tests
/// below stay compiled and running in the default (no-`mock-attestation`) build.
/// All measurement registers are zeroed, matching what a mock quote produced.
fn policy_verification_result(nonce_seed: u8) -> calimero_tee_attestation::VerificationResult {
    use calimero_server_primitives::admin::{
        CertificationData, QeReportCertificationDataInfo, Quote, QuoteBody, QuoteHeader,
    };

    let zero_48b = "0".repeat(96);
    let zero_16b = "0".repeat(32);
    let zero_8b = "0".repeat(16);

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&[nonce_seed; 32]);

    let quote = Quote {
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
    };

    calimero_tee_attestation::VerificationResult {
        quote_verified: true,
        nonce_verified: true,
        application_hash_verified: true,
        tcb_status: Some("Mock".to_owned()),
        advisory_ids: Vec::new(),
        quote,
    }
}

#[test]
fn test_hash_peer_id() {
    let peer_id = "12D3KooWAbcdefghijklmnopqrstuvwxyz";
    let hash = get_key::hash_peer_id(peer_id);
    assert_eq!(hash.len(), 32);

    let hash2 = get_key::hash_peer_id(peer_id);
    assert_eq!(hash, hash2);

    let hash3 = get_key::hash_peer_id("12D3KooWDifferentPeerId");
    assert_ne!(hash, hash3);
}

#[test]
fn test_error_response_serialization() {
    let error = errors::ErrorResponse {
        error: "test_error".to_string(),
        details: Some("Test details".to_string()),
    };
    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("test_error"));
    assert!(json.contains("Test details"));

    let error_no_details = errors::ErrorResponse {
        error: "test_error".to_string(),
        details: None,
    };
    let json = serde_json::to_string(&error_no_details).unwrap();
    assert!(!json.contains("details"));
}

#[test]
fn test_error_response_display_with_details() {
    let error = errors::ErrorResponse {
        error: "rate_limited".to_string(),
        details: Some("Too many requests".to_string()),
    };
    assert_eq!(error.to_string(), "rate_limited: Too many requests");
}

#[test]
fn test_error_response_display_without_details() {
    let error = errors::ErrorResponse {
        error: "not_found".to_string(),
        details: None,
    };
    assert_eq!(error.to_string(), "not_found");
}

#[test]
fn test_policy_not_ready_blocks_key_release() {
    let config = Config {
        policy_ready: false,
        policy_unavailable_reason: Some("policy is still syncing".to_string()),
        ..Config::default()
    };
    let err = get_key::ensure_policy_ready_for_key_release(&config)
        .expect_err("unready policy should block key release");
    assert!(matches!(err, ServiceError::PolicyNotReady(_)));
}

#[test]
fn test_policy_rejects_tcb_status() {
    let mut verification = policy_verification_result(0x11);
    verification.tcb_status = Some("OutOfDate".to_owned());

    let config = Config {
        attestation_policy: AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_owned()],
            ..AttestationPolicy::default()
        },
        ..Config::default()
    };

    let result = get_key::enforce_attestation_policy(&config, &verification);
    assert!(matches!(result, Err(ServiceError::TcbStatusRejected(_))));
}

#[test]
fn test_policy_rejects_untrusted_mrtd() {
    use crate::measurement::HexMeasurement;

    let mut verification = policy_verification_result(0x22);
    verification.tcb_status = Some("UpToDate".to_owned());

    let config = Config {
        attestation_policy: AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_owned()],
            allowed_mrtd: vec![HexMeasurement::parse(&"1".repeat(96)).unwrap()],
            ..AttestationPolicy::default()
        },
        ..Config::default()
    };

    let result = get_key::enforce_attestation_policy(&config, &verification);
    assert!(matches!(
        result,
        Err(ServiceError::MeasurementPolicyRejected(_))
    ));
}

#[test]
fn test_policy_accepts_allowlisted_measurements() {
    use crate::measurement::HexMeasurement;

    let mut verification = policy_verification_result(0x33);
    verification.tcb_status = Some("UpToDate".to_owned());
    let zero_48b = HexMeasurement::parse(&"0".repeat(96)).unwrap();

    let config = Config {
        attestation_policy: AttestationPolicy {
            enforce_measurement_policy: true,
            allowed_tcb_statuses: vec!["uptodate".to_owned()],
            allowed_mrtd: vec![zero_48b.clone()],
            allowed_rtmr0: vec![zero_48b.clone()],
            allowed_rtmr1: vec![zero_48b.clone()],
            allowed_rtmr2: vec![zero_48b.clone()],
            allowed_rtmr3: vec![zero_48b],
        },
        ..Config::default()
    };

    let result = get_key::enforce_attestation_policy(&config, &verification);
    assert!(result.is_ok());
}

#[test]
fn test_key_path_for_peer_includes_namespace_profile_and_peer_id() {
    let config = Config {
        key_namespace_prefix: "merod/storage".to_string(),
        kms_profile: "locked-read-only".to_string(),
        ..Config::default()
    };
    let path = get_key::key_path_for_peer(&config, "12D3KooWTestPeer");
    assert_eq!(path, "merod/storage/locked-read-only/12D3KooWTestPeer");
}

#[test]
fn test_signature_payload_is_deterministic() {
    let challenge_id = "abc123abc123abc123abc123abc12345";
    let nonce = [0x5a; 32];
    let quote = b"quote-bytes";
    let peer_id = "12D3KooWAbcdefghijklmnopqrstuvwxyz";

    let payload1 = get_key::build_signature_payload(challenge_id, &nonce, quote, peer_id).unwrap();
    let payload2 = get_key::build_signature_payload(challenge_id, &nonce, quote, peer_id).unwrap();
    assert_eq!(payload1, payload2);
}

#[test]
fn test_decode_fixed_b64_32_rejects_invalid_length() {
    let bad = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
    let err = attest::decode_fixed_b64_32("nonceB64", &bad).unwrap_err();
    assert!(matches!(err, ServiceError::InvalidAttestationRequest(_)));
}

#[test]
fn test_validate_peer_id_shape_rejects_non_base58() {
    let err = challenge::validate_peer_id_shape("not-valid-peer-id-0OIl").unwrap_err();
    assert!(matches!(err, ServiceError::InvalidPeerId(_)));
}

#[test]
fn test_validate_peer_id_shape_accepts_valid_base58_peer_id() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id().to_base58();
    assert!(challenge::validate_peer_id_shape(&peer_id).is_ok());
}

#[test]
fn test_validate_peer_id_shape_rejects_empty() {
    let err = challenge::validate_peer_id_shape("").unwrap_err();
    assert!(matches!(err, ServiceError::InvalidPeerId(_)));
}

#[test]
fn test_validate_challenge_id_rejects_invalid_shape() {
    let err = get_key::validate_challenge_id("abc").unwrap_err();
    assert!(matches!(err, ServiceError::InvalidChallenge(_)));
}

#[test]
fn test_resolve_attestation_binding_defaults_to_domain_separator() {
    let binding = attest::resolve_attestation_binding(None).unwrap();
    assert_eq!(binding.len(), 32);
    assert_ne!(binding, [0u8; 32]);

    let binding2 = attest::resolve_attestation_binding(None).unwrap();
    assert_eq!(binding, binding2);
}

#[test]
fn test_build_attestation_report_data_layout() {
    let nonce = [0x11; 32];
    let binding = [0x22; 32];
    let report_data = attest::build_attestation_report_data(&nonce, &binding);
    assert_eq!(&report_data[..32], &nonce);
    assert_eq!(&report_data[32..], &binding);
}

#[test]
fn test_verify_peer_signature_accepts_matching_peer_identity() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id().to_base58();
    let peer_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(keypair.public().encode_protobuf());
    let challenge_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    let challenge_nonce = [0x7b; 32];
    let quote_bytes = b"quote-bytes-for-signature";
    let payload =
        get_key::build_signature_payload(challenge_id, &challenge_nonce, quote_bytes, &peer_id)
            .unwrap();
    let signature = keypair.sign(&payload).unwrap();
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);

    let result = get_key::verify_peer_signature(
        &peer_id,
        &peer_public_key_b64,
        &signature_b64,
        challenge_id,
        &challenge_nonce,
        quote_bytes,
    );
    assert!(result.is_ok());
}

#[test]
fn test_verify_peer_signature_rejects_spoofed_peer_id() {
    let attacker = Keypair::generate_ed25519();
    let victim = Keypair::generate_ed25519();
    let claimed_peer_id = victim.public().to_peer_id().to_base58();
    let attacker_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(attacker.public().encode_protobuf());

    let challenge_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d5";
    let challenge_nonce = [0x42; 32];
    let quote_bytes = b"quote-bytes-for-spoof";
    let payload = get_key::build_signature_payload(
        challenge_id,
        &challenge_nonce,
        quote_bytes,
        &claimed_peer_id,
    )
    .unwrap();
    let attacker_signature_b64 =
        base64::engine::general_purpose::STANDARD.encode(attacker.sign(&payload).unwrap());

    let result = get_key::verify_peer_signature(
        &claimed_peer_id,
        &attacker_public_key_b64,
        &attacker_signature_b64,
        challenge_id,
        &challenge_nonce,
        quote_bytes,
    );
    assert!(matches!(result, Err(ServiceError::PeerIdentityMismatch)));
}

#[tokio::test]
async fn test_health_endpoint_response() {
    let app = create_router(Config::default()).expect("router should build");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .method("GET")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let payload = read_json_body(response).await;
    assert_eq!(payload["status"], "alive");
    assert_eq!(payload["service"], "mero-kms-phala");
}

#[tokio::test]
async fn test_attest_endpoint_rejects_invalid_nonce_length() {
    let app = create_router(Config::default()).expect("router should build");
    let bad_nonce_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
    let body = serde_json::json!({
        "nonceB64": bad_nonce_b64
    });

    let response = app
        .oneshot(post_json_request("/attest", &body))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let payload = read_json_body(response).await;
    assert_eq!(payload["error"], "invalid_attestation_request");
}

#[tokio::test]
async fn test_policy_not_ready_error_maps_to_service_unavailable() {
    let response = ServiceError::PolicyNotReady("policy fetch pending".to_string()).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload = read_json_body(response).await;
    assert_eq!(payload["error"], "policy_not_ready");
}

#[tokio::test]
async fn test_challenge_is_single_use_even_when_signature_fails() {
    let app = create_router(Config::default()).expect("router should build");
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id().to_base58();
    let challenge_body = serde_json::json!({
        "peerId": peer_id
    });

    let challenge_response = app
        .clone()
        .oneshot(post_json_request("/challenge", &challenge_body))
        .await
        .expect("request should succeed");
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge_payload = read_json_body(challenge_response).await;

    let challenge_id = challenge_payload["challengeId"]
        .as_str()
        .expect("challengeId should be a string");
    let quote_b64 = base64::engine::general_purpose::STANDARD.encode(b"dummy-quote");
    let bad_public_key_b64 = base64::engine::general_purpose::STANDARD.encode(b"not-protobuf");
    let bad_signature_b64 = base64::engine::general_purpose::STANDARD.encode(b"bad-signature");

    let request_body = serde_json::json!({
        "challengeId": challenge_id,
        "quoteB64": quote_b64,
        "peerId": peer_id,
        "peerPublicKeyB64": bad_public_key_b64,
        "signatureB64": bad_signature_b64
    });

    let first = app
        .clone()
        .oneshot(post_json_request("/get-key", &request_body))
        .await
        .expect("request should succeed");

    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    let first_payload = read_json_body(first).await;
    assert_eq!(first_payload["error"], "invalid_peer_public_key");

    let second = app
        .oneshot(post_json_request("/get-key", &request_body))
        .await
        .expect("request should succeed");

    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    let second_payload = read_json_body(second).await;
    assert_eq!(second_payload["error"], "invalid_challenge");
}
