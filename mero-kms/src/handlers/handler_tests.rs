//! Integration tests for the HTTP handler layer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use libp2p_identity::Keypair;
use tower::util::ServiceExt;

use crate::backend::{test_tdx_backend, Root, TdxBackend, KEY_LEN};
use crate::test_util::read_json_body;
use crate::AttestationPolicy;

use super::errors::ServiceError;
use super::*;

/// A replica holding the root `[seed; 32]`; two replicas with the same seed
/// are one cluster.
fn replica(seed: u8) -> Arc<TdxBackend> {
    Arc::new(test_tdx_backend(Some(
        Root::from_bytes(&[seed; KEY_LEN]).expect("32-byte root"),
    )))
}

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
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&[nonce_seed; 32]);
    let quote = crate::test_util::zero_quote(&report_data);

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

    let payload1 =
        get_key::build_signature_payload(challenge_id, &nonce, quote, peer_id, None).unwrap();
    let payload2 =
        get_key::build_signature_payload(challenge_id, &nonce, quote, peer_id, None).unwrap();
    assert_eq!(payload1, payload2);
}

/// A merod that predates sealing signs the legacy payload. A proxy that adds a
/// `sealToB64` of its own to such a request, hoping to have the key sealed to
/// itself, changes the payload the signature must cover and is refused.
#[test]
fn a_seal_key_added_to_a_request_the_node_did_not_sign_is_refused() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id().to_base58();
    let peer_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(keypair.public().encode_protobuf());
    let challenge_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d6";
    let challenge_nonce = [0x7c; 32];
    let quote_bytes = b"quote-bytes-for-seal";
    let signed_seal = [0x10; 32];
    let payload = get_key::build_signature_payload(
        challenge_id,
        &challenge_nonce,
        quote_bytes,
        &peer_id,
        Some(&signed_seal),
    )
    .unwrap();
    let signature_b64 =
        base64::engine::general_purpose::STANDARD.encode(keypair.sign(&payload).unwrap());

    let verify = |seal_to: Option<&[u8; 32]>| {
        get_key::verify_peer_signature(
            &peer_id,
            &peer_public_key_b64,
            &signature_b64,
            challenge_id,
            &challenge_nonce,
            quote_bytes,
            seal_to,
        )
    };
    assert!(verify(Some(&signed_seal)).is_ok());
    assert!(matches!(
        verify(Some(&[0x20; 32])),
        Err(ServiceError::InvalidSignature(_))
    ));
    assert!(matches!(
        verify(None),
        Err(ServiceError::InvalidSignature(_))
    ));
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
    let payload = get_key::build_signature_payload(
        challenge_id,
        &challenge_nonce,
        quote_bytes,
        &peer_id,
        None,
    )
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
        None,
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
        None,
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
        None,
    );
    assert!(matches!(result, Err(ServiceError::PeerIdentityMismatch)));
}

#[tokio::test]
async fn test_health_endpoint_response() {
    let app = create_router(Config::default(), replica(7));
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
    assert_eq!(payload["service"], "mero-kms");
    assert_eq!(payload["clusterRootReady"], true);
}

/// A locked replica has no console: `/health` is where an operator reads why
/// it has not joined, and the error goes once the replica holds the root.
#[tokio::test]
async fn health_reports_the_last_join_error_until_the_replica_holds_the_root() {
    let health = |backend: Arc<TdxBackend>| async move {
        let response = create_router(Config::default(), backend)
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .method("GET")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        read_json_body(response).await
    };

    let joining = Arc::new(test_tdx_backend(None));
    joining.record_join_error("http://10.0.0.2:8080: peer TCB status 'revoked'".to_owned());
    let payload = health(Arc::clone(&joining)).await;
    assert_eq!(payload["clusterRootReady"], false);
    assert_eq!(
        payload["lastJoinError"],
        "http://10.0.0.2:8080: peer TCB status 'revoked'"
    );

    let joined = replica(7);
    joined.record_join_error("an earlier failure".to_owned());
    let payload = health(joined).await;
    assert_eq!(payload["clusterRootReady"], true);
    assert!(payload.get("lastJoinError").is_none(), "{payload}");
}

#[tokio::test]
async fn test_attest_endpoint_rejects_invalid_nonce_length() {
    let app = create_router(Config::default(), replica(7));
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

/// The event log is opt-in, and a TD without one says so instead of returning a
/// quote with nothing beside it.
#[cfg(feature = "mock-attestation")]
#[tokio::test]
async fn the_attest_event_log_is_opt_in() {
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let app = create_router(Config::default(), replica(7));
    let response = app
        .oneshot(post_json_request(
            "/attest",
            &serde_json::json!({ "nonceB64": nonce_b64 }),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = read_json_body(response).await;
    assert!(payload.get("eventLogB64").is_none(), "{payload}");

    let app = create_router(Config::default(), replica(7));
    let response = app
        .oneshot(post_json_request(
            "/attest",
            &serde_json::json!({ "nonceB64": nonce_b64, "eventLog": true }),
        ))
        .await
        .expect("request should succeed");
    let payload = read_json_body(response).await;
    assert_eq!(payload["error"], "attestation_verification_failed");
}

#[tokio::test]
async fn test_policy_not_ready_error_maps_to_service_unavailable() {
    let response =
        ServiceError::PolicyNotReady("replica has not joined".to_string()).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload = read_json_body(response).await;
    assert_eq!(payload["error"], "policy_not_ready");
}

#[tokio::test]
async fn test_challenge_is_single_use_even_when_signature_fails() {
    let app = create_router(Config::default(), replica(7));
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
        "signatureB64": bad_signature_b64,
        "sealToB64": base64::engine::general_purpose::STANDARD.encode([0x42u8; 32])
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

/// Sealed release is the default: a request that does not name a key to seal
/// to (a merod older than 0.11.0-rc.47) is refused, because the key would cross
/// the wire readable by whatever terminates TLS in front of this service.
#[tokio::test]
async fn an_unsealed_key_request_is_refused_by_default() {
    let config = Config::default();
    assert!(config.require_sealed_key_release);
    let app = create_router(config, replica(7));
    let request_body = serde_json::json!({
        "challengeId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d7",
        "quoteB64": base64::engine::general_purpose::STANDARD.encode(b"quote"),
        "peerId": Keypair::generate_ed25519().public().to_peer_id().to_base58(),
        "peerPublicKeyB64": "",
        "signatureB64": ""
    });

    let response = app
        .oneshot(post_json_request("/get-key", &request_body))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let payload = read_json_body(response).await;
    assert_eq!(payload["error"], "invalid_attestation_request");
    assert!(
        payload["details"]
            .as_str()
            .unwrap_or_default()
            .contains("sealed only"),
        "{payload}"
    );
}

/// Ask `app` for a challenge for `peer_id` and return its token.
async fn issue_challenge(app: &Router, peer_id: &str) -> String {
    let response = app
        .clone()
        .oneshot(post_json_request(
            "/challenge",
            &serde_json::json!({ "peerId": peer_id }),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    read_json_body(response).await["challengeId"]
        .as_str()
        .expect("challengeId should be a string")
        .to_owned()
}

/// A `/get-key` request that passes every check before the challenge and fails
/// the first one after it (the peer public key), so its error tells whether
/// the challenge was accepted.
async fn get_key_error(app: &Router, challenge_id: &str, peer_id: &str) -> String {
    let body = serde_json::json!({
        "challengeId": challenge_id,
        "quoteB64": base64::engine::general_purpose::STANDARD.encode(b"dummy-quote"),
        "peerId": peer_id,
        "peerPublicKeyB64": base64::engine::general_purpose::STANDARD.encode(b"not-protobuf"),
        "signatureB64": base64::engine::general_purpose::STANDARD.encode(b"bad-signature"),
        "sealToB64": base64::engine::general_purpose::STANDARD.encode([0x42u8; 32])
    });
    let response = app
        .clone()
        .oneshot(post_json_request("/get-key", &body))
        .await
        .expect("request should succeed");
    read_json_body(response).await["error"]
        .as_str()
        .expect("error should be a string")
        .to_owned()
}

/// Replicas share no storage: a challenge one replica issued must pass on any
/// other replica of the same cluster, once per replica. (Another cluster opens
/// it to a different nonce, which the node's signature and quote then fail;
/// `stateless_challenge`'s tests cover that binding.)
#[tokio::test]
async fn a_challenge_from_one_replica_is_accepted_by_another_of_the_same_cluster() {
    let peer_id = Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_base58();
    let replica_a = create_router(Config::default(), replica(7));
    let replica_b = create_router(Config::default(), replica(7));

    let challenge_id = issue_challenge(&replica_a, &peer_id).await;
    assert_eq!(challenge_id.len(), crate::stateless_challenge::ID_HEX_LEN);
    assert_eq!(
        get_key_error(&replica_b, &challenge_id, &peer_id).await,
        "invalid_peer_public_key"
    );
    assert_eq!(
        get_key_error(&replica_b, &challenge_id, &peer_id).await,
        "invalid_challenge"
    );
}

#[tokio::test]
async fn an_expired_challenge_is_refused() {
    let peer_id = Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_base58();
    let app = create_router(Config::default(), replica(7));
    let mut challenge_id = issue_challenge(&app, &peer_id).await;
    // Set the expiry (bytes 16..24) to the epoch.
    challenge_id.replace_range(32..48, &"0".repeat(16));
    assert_eq!(
        get_key_error(&app, &challenge_id, &peer_id).await,
        "invalid_challenge"
    );
}

#[tokio::test]
async fn a_tampered_challenge_is_refused() {
    let peer_id = Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_base58();
    let app = create_router(Config::default(), replica(7));
    let mut challenge_id = issue_challenge(&app, &peer_id).await;
    // Push the expiry (bytes 16..24) far past anything this KMS issues.
    challenge_id.replace_range(32..34, "ff");
    assert_eq!(
        get_key_error(&app, &challenge_id, &peer_id).await,
        "invalid_challenge"
    );
}

#[tokio::test]
async fn a_malformed_challenge_id_is_refused() {
    let peer_id = Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_base58();
    let app = create_router(Config::default(), replica(7));
    assert_eq!(
        get_key_error(&app, &"a".repeat(32), &peer_id).await,
        "invalid_challenge"
    );
}

/// The challenge key comes from the root, so a replica that has not joined its
/// cluster yet can neither issue nor check one.
#[tokio::test]
async fn a_replica_without_a_root_issues_no_challenge() {
    let app = create_router(Config::default(), Arc::new(test_tdx_backend(None)));
    let response = app
        .oneshot(post_json_request(
            "/challenge",
            &serde_json::json!({
                "peerId": Keypair::generate_ed25519().public().to_peer_id().to_base58()
            }),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(read_json_body(response).await["error"], "policy_not_ready");
}
