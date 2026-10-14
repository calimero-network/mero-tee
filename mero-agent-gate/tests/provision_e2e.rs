//! A provisioner against a gate over real HTTP, with mock quotes.
#![cfg(feature = "mock-attestation")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mero_agent_gate::keys::ProvisioningKey;
use mero_agent_gate::protocol::{
    keypair_from_secret, AttestRequest, AttestResponse, SecretsBundle,
};
use mero_agent_gate::server::{router, Gate, MockQuoter, NoUnits};
use mero_agent_gate::slots::open_slots;
use mero_agent_gate::verify::{
    attest_gate, provision_gate, release_gate, verify_attest_response, AgentPolicy,
};

const OWNER: [u8; 32] = [0x42; 32];
const SOMEONE_ELSE: [u8; 32] = [0x43; 32];

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

const AGENT: &str = "agent-1";

async fn serve(dir: &std::path::Path) -> (String, Arc<Gate>) {
    let gate = Arc::new(Gate::new(
        Arc::new(MockQuoter),
        ProvisioningKey::generate(),
        open_slots(&dir.join("agents"), 2, "").unwrap(),
        Arc::new(NoUnits),
    ));
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
async fn the_first_provisioner_claims_the_agent_and_only_it_provisions_again() {
    let dir = temp_dir("ok");
    let (url, _gate) = serve(&dir).await;
    let client = reqwest::Client::new();
    let (_, owner) = keypair_from_secret(&OWNER).unwrap();

    let verified = attest_gate(&client, &url, Some(AGENT), &policy(), true)
        .await
        .unwrap();
    assert_eq!(verified.signing_public_key, None);
    assert_eq!(verified.owner_public_key, None);

    let bundle = SecretsBundle {
        secrets: [("MODEL_API_KEY".to_owned(), "sk-test".to_owned())].into(),
    };
    let written = provision_gate(&client, &url, &verified, &OWNER, &bundle)
        .await
        .unwrap();
    assert_eq!(written.written, vec!["MODEL_API_KEY"]);
    assert!(written.claimed);
    assert_eq!(
        std::fs::read_to_string(dir.join("agents/1/secrets/MODEL_API_KEY")).unwrap(),
        "sk-test"
    );

    // A fresh quote binds the owner and the signing key the claim made.
    let claimed = attest_gate(&client, &url, Some(AGENT), &policy(), true)
        .await
        .unwrap();
    assert_eq!(claimed.owner_public_key, Some(owner));
    assert!(claimed.signing_public_key.is_some());

    // Someone else is refused by their own CLI before anything is sent...
    let err = provision_gate(&client, &url, &claimed, &SOMEONE_ELSE, &bundle)
        .await
        .unwrap_err();
    assert!(err.contains("not yours"), "{err}");
    // ...and by the gate, if they skip that check by trusting an old quote.
    let err = provision_gate(&client, &url, &verified, &SOMEONE_ELSE, &bundle)
        .await
        .unwrap_err();
    assert!(err.contains("403"), "{err}");

    // The owner provisions again.
    let bundle = SecretsBundle {
        secrets: [("MODEL_API_KEY".to_owned(), "sk-rotated".to_owned())].into(),
    };
    let again = provision_gate(&client, &url, &claimed, &OWNER, &bundle)
        .await
        .unwrap();
    assert!(!again.claimed);
    assert_eq!(
        std::fs::read_to_string(dir.join("agents/1/secrets/MODEL_API_KEY")).unwrap(),
        "sk-rotated"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The claim is on the disk: a restarted gate (a new provisioning key) still
/// binds the same owner and refuses everyone else.
#[tokio::test]
async fn a_claim_survives_a_gate_restart() {
    let dir = temp_dir("restart");
    let client = reqwest::Client::new();
    let bundle = SecretsBundle {
        secrets: [("A".to_owned(), "1".to_owned())].into(),
    };
    {
        let (url, _gate) = serve(&dir).await;
        let verified = attest_gate(&client, &url, Some(AGENT), &policy(), true)
            .await
            .unwrap();
        provision_gate(&client, &url, &verified, &OWNER, &bundle)
            .await
            .unwrap();
    }
    let (url, _gate) = serve(&dir).await;
    let (_, owner) = keypair_from_secret(&OWNER).unwrap();
    let verified = attest_gate(&client, &url, Some(AGENT), &policy(), true)
        .await
        .unwrap();
    assert_eq!(verified.owner_public_key, Some(owner));
    assert!(
        provision_gate(&client, &url, &verified, &SOMEONE_ELSE, &bundle)
            .await
            .is_err()
    );
    provision_gate(&client, &url, &verified, &OWNER, &bundle)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_mock_quote_is_refused_unless_allowed() {
    let dir = temp_dir("mock");
    let (url, _gate) = serve(&dir).await;
    let err = attest_gate(&reqwest::Client::new(), &url, Some(AGENT), &policy(), false)
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
    let (url, _gate) = serve(&dir).await;
    let nonce = [9u8; 32];
    let mut response: AttestResponse = reqwest::Client::new()
        .post(format!("{url}/attest"))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode(nonce),
            agent_id: Some(AGENT.to_owned()),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    response.provisioning_public_key_b64 = BASE64.encode(ProvisioningKey::generate().public);
    let err = verify_attest_response(&response, &nonce, Some(AGENT), &policy(), true)
        .await
        .unwrap_err();
    assert!(err.contains("does not commit to the agent, keys"), "{err}");
}

#[tokio::test]
async fn a_replayed_quote_fails_on_a_fresh_nonce() {
    let dir = temp_dir("replay");
    let (url, _gate) = serve(&dir).await;
    let response: AttestResponse = reqwest::Client::new()
        .post(format!("{url}/attest"))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode([1u8; 32]),
            agent_id: Some(AGENT.to_owned()),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let err = verify_attest_response(&response, &[2u8; 32], Some(AGENT), &policy(), true)
        .await
        .unwrap_err();
    assert!(err.contains("nonce"), "{err}");
}

/// Two owners on one TD: each has its own agent, signing key and secrets, and
/// neither can provision or release the other's.
#[tokio::test]
async fn two_owners_share_a_td_and_neither_reaches_the_other() {
    let dir = temp_dir("tenants");
    let (url, _gate) = serve(&dir).await;
    let client = reqwest::Client::new();
    let secret = |v: &str| SecretsBundle {
        secrets: [("MODEL_API_KEY".to_owned(), v.to_owned())].into(),
    };

    let mine = attest_gate(&client, &url, Some("mine"), &policy(), true)
        .await
        .unwrap();
    provision_gate(&client, &url, &mine, &OWNER, &secret("sk-mine"))
        .await
        .unwrap();
    let theirs = attest_gate(&client, &url, Some("theirs"), &policy(), true)
        .await
        .unwrap();
    provision_gate(&client, &url, &theirs, &SOMEONE_ELSE, &secret("sk-theirs"))
        .await
        .unwrap();

    let mine = attest_gate(&client, &url, Some("mine"), &policy(), true)
        .await
        .unwrap();
    let theirs = attest_gate(&client, &url, Some("theirs"), &policy(), true)
        .await
        .unwrap();
    assert_ne!(mine.signing_public_key, theirs.signing_public_key);
    assert_ne!(mine.owner_public_key, theirs.owner_public_key);

    // A quote for one agent is not a quote for the other.
    let nonce = [5u8; 32];
    let response: AttestResponse = client
        .post(format!("{url}/attest"))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode(nonce),
            agent_id: Some("theirs".to_owned()),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut posing = response;
    posing.agent_id = Some("mine".to_owned());
    let err = verify_attest_response(&posing, &nonce, Some("mine"), &policy(), true)
        .await
        .unwrap_err();
    assert!(err.contains("does not commit"), "{err}");

    // Neither touches the other's agent.
    assert!(
        provision_gate(&client, &url, &mine, &SOMEONE_ELSE, &secret("evil"))
            .await
            .unwrap_err()
            .contains("not yours")
    );
    assert!(release_gate(&client, &url, &mine, &SOMEONE_ELSE)
        .await
        .unwrap_err()
        .contains("not yours"));

    // Its owner releases one; the other is untouched.
    release_gate(&client, &url, &mine, &OWNER).await.unwrap();
    let after = attest_gate(&client, &url, Some("mine"), &policy(), true)
        .await
        .unwrap();
    assert_eq!(after.owner_public_key, None);
    assert!(!dir.join("agents/1/secrets/MODEL_API_KEY").exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("agents/2/secrets/MODEL_API_KEY")).unwrap(),
        "sk-theirs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
