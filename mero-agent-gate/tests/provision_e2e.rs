//! A provisioner against a gate over real HTTP, with mock quotes.
#![cfg(feature = "mock-attestation")]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mero_agent_gate::keys::ProvisioningKey;
use mero_agent_gate::protocol::{
    keypair_from_secret, AttestRequest, AttestResponse, SecretsBundle,
};
use mero_agent_gate::server::{router, Gate, MockQuoter};
use mero_agent_gate::verify::{attest_gate, provision_gate, verify_attest_response, AgentPolicy};

const PROVISIONER: [u8; 32] = [0x42; 32];

fn policy() -> AgentPolicy {
    // Never consulted for an accepted mock quote; a real quote must match it.
    AgentPolicy {
        allowed_tcb_statuses: vec!["UpToDate".to_owned()],
        allowed_mrtd: vec!["a".repeat(96)],
        allowed_rtmr0: vec!["a".repeat(96)],
        allowed_rtmr1: vec!["a".repeat(96)],
        allowed_rtmr2: vec!["a".repeat(96)],
        allowed_rtmr3: vec!["a".repeat(96)],
    }
}

async fn serve(secrets_dir: std::path::PathBuf) -> (String, Arc<Gate>) {
    let (_, provisioner) = keypair_from_secret(&PROVISIONER).unwrap();
    let gate = Arc::new(Gate {
        quoter: Arc::new(MockQuoter),
        provisioning: ProvisioningKey::generate(),
        signing_public: [0x55; 32],
        secrets_dir,
        provisioners: vec![provisioner],
        allow_unauthenticated: false,
        provisioned: AtomicBool::new(false),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(Arc::clone(&gate));
    drop(tokio::spawn(
        async move { axum::serve(listener, app).await },
    ));
    (url, gate)
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mero-agent-gate-e2e-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test]
async fn a_verified_gate_receives_the_secrets() {
    let dir = temp_dir("ok");
    let (url, _gate) = serve(dir.join("secrets")).await;
    let client = reqwest::Client::new();

    let verified = attest_gate(&client, &url, &policy(), true).await.unwrap();
    assert_eq!(verified.signing_public_key, [0x55; 32]);

    let bundle = SecretsBundle {
        secrets: [("MODEL_API_KEY".to_owned(), "sk-test".to_owned())].into(),
    };
    let written = provision_gate(&client, &url, &verified, Some(&PROVISIONER), &bundle)
        .await
        .unwrap();
    assert_eq!(written.written, vec!["MODEL_API_KEY"]);
    assert_eq!(
        std::fs::read_to_string(dir.join("secrets/MODEL_API_KEY")).unwrap(),
        "sk-test"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_mock_quote_is_refused_unless_allowed() {
    let dir = temp_dir("mock");
    let (url, _gate) = serve(dir.join("secrets")).await;
    let err = attest_gate(&reqwest::Client::new(), &url, &policy(), false)
        .await
        .unwrap_err();
    assert!(err.contains("mock"), "{err}");
}

/// Something between the provisioner and the gate (or a gate lying about its
/// keys) substitutes a provisioning key of its own. The quote does not commit
/// to it, so nothing is sealed to it.
#[tokio::test]
async fn a_substituted_provisioning_key_is_caught() {
    let dir = temp_dir("swap");
    let (url, _gate) = serve(dir.join("secrets")).await;
    let nonce = [9u8; 32];
    let mut response: AttestResponse = reqwest::Client::new()
        .post(format!("{url}/attest"))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode(nonce),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    response.provisioning_public_key_b64 = BASE64.encode(ProvisioningKey::generate().public);
    let err = verify_attest_response(&response, &nonce, &policy(), true)
        .await
        .unwrap_err();
    assert!(err.contains("does not commit to the keys"), "{err}");
}

#[tokio::test]
async fn a_replayed_quote_fails_on_a_fresh_nonce() {
    let dir = temp_dir("replay");
    let (url, _gate) = serve(dir.join("secrets")).await;
    let response: AttestResponse = reqwest::Client::new()
        .post(format!("{url}/attest"))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode([1u8; 32]),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let err = verify_attest_response(&response, &[2u8; 32], &policy(), true)
        .await
        .unwrap_err();
    assert!(err.contains("nonce"), "{err}");
}
