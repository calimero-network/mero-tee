//! Integration tests for the HTTP handler layer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use calimero_tee_attestation::verify_mock_attestation;
use libp2p_identity::Keypair;
use tower::util::ServiceExt;

use crate::test_util::{create_mock_quote, read_json_body};
use crate::AttestationPolicy;

use super::errors::ServiceError;
use super::*;

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
    let nonce = [0x11; 32];
    let mock_quote = create_mock_quote(&nonce);
    let mut verification = verify_mock_attestation(&mock_quote, &nonce, None).unwrap();
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

    let nonce = [0x22; 32];
    let mock_quote = create_mock_quote(&nonce);
    let mut verification = verify_mock_attestation(&mock_quote, &nonce, None).unwrap();
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

    let nonce = [0x33; 32];
    let mock_quote = create_mock_quote(&nonce);
    let mut verification = verify_mock_attestation(&mock_quote, &nonce, None).unwrap();
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
        .oneshot(
            Request::builder()
                .uri("/attest")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
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
        .oneshot(
            Request::builder()
                .uri("/challenge")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(challenge_body.to_string()))
                .expect("request should build"),
        )
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
        .oneshot(
            Request::builder()
                .uri("/get-key")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    let first_payload = read_json_body(first).await;
    assert_eq!(first_payload["error"], "invalid_peer_public_key");

    let second = app
        .oneshot(
            Request::builder()
                .uri("/get-key")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    let second_payload = read_json_body(second).await;
    assert_eq!(second_payload["error"], "invalid_challenge");
}
