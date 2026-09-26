//! How a TDX replica gets its cluster's root, and gives it on.
//!
//! The rule is **"same as me"**: a replica hands the root only to a TD whose
//! quote carries exactly its own MRTD and RTMR0–3, is not a debug TD, and has a
//! TCB status the image's baked policy allows. There is no allowlist to extend
//! and no owner to ask, so the only code that can ever hold the root is the code
//! already holding it.
//!
//! Both sides attest. If the joiner did not check the giver, anyone could hand
//! it a root they chose, and then know every key it derives.
//!
//! 1. The joiner asks a peer for a single-use nonce (`POST /cluster/nonce`).
//! 2. It sends `POST /cluster/join` with a one-time X25519 key and a quote over
//!    `nonce ‖ SHA-256(JOIN_DOMAIN ‖ joiner_public)`.
//! 3. The giver checks that quote against itself, seals the root to the joiner's
//!    key under a one-time key of its own, and returns the sealed root with its
//!    own quote over `nonce ‖ SHA-256(GIVE_DOMAIN ‖ joiner_public ‖
//!    giver_public ‖ seal_nonce ‖ sealed_root)`.
//! 4. The joiner checks that quote against itself the same way before it opens
//!    the root.
//!
//! Peer addresses come from the environment. They are not trusted: a wrong
//! address only fails a join.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
#[cfg(feature = "mock-attestation")]
use calimero_tee_attestation::verify_mock_attestation;
use calimero_tee_attestation::{verify_attestation, VerificationResult};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::backend::{Backend, Measurements, Root, TdxBackend};
use crate::handlers::errors::ServiceError;
use crate::handlers::AppState;
use crate::measurement::is_debug_td;
use crate::policy::AttestationPolicy;

const JOIN_DOMAIN: &[u8] = b"mero-kms/cluster/join/v1";
const GIVE_DOMAIN: &[u8] = b"mero-kms/cluster/give/v1";
const ROOT_SEAL_DOMAIN: &[u8] = b"mero-kms/cluster/root-seal/v1";

/// How long a join nonce stays valid, and how many may be outstanding.
const JOIN_NONCE_TTL: Duration = Duration::from_secs(60);
const MAX_JOIN_NONCES: usize = 1024;

/// Single-use nonces this replica issued to joiners.
#[derive(Default)]
pub(crate) struct JoinNonces(Mutex<HashMap<[u8; 32], Instant>>);

impl JoinNonces {
    fn issue(&self) -> Result<[u8; 32], ServiceError> {
        let mut nonces = self.lock()?;
        let now = Instant::now();
        nonces.retain(|_, expiry| *expiry > now);
        if nonces.len() >= MAX_JOIN_NONCES {
            return Err(ServiceError::RateLimited(
                "too many outstanding join nonces".to_owned(),
            ));
        }
        let nonce: [u8; 32] = rand::random();
        let _ = nonces.insert(nonce, now + JOIN_NONCE_TTL);
        Ok(nonce)
    }

    /// Remove `nonce` whatever happens next, so a failed join cannot be retried
    /// with it.
    fn consume(&self, nonce: &[u8; 32]) -> Result<(), ServiceError> {
        match self.lock()?.remove(nonce) {
            Some(expiry) if expiry > Instant::now() => Ok(()),
            Some(_) => Err(ServiceError::InvalidChallenge(
                "join nonce expired".to_owned(),
            )),
            None => Err(ServiceError::InvalidChallenge(
                "unknown join nonce".to_owned(),
            )),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<[u8; 32], Instant>>, ServiceError> {
        self.0
            .lock()
            .map_err(|_| ServiceError::KeyDerivationFailed("nonce lock poisoned".to_owned()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinNonceResponse {
    pub nonce_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub nonce_b64: String,
    /// The joiner's one-time X25519 key.
    pub joiner_public_b64: String,
    /// The joiner's quote over `nonce ‖ join_binding(joiner_public)`.
    pub quote_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    /// The giver's quote over `nonce ‖ give_binding(...)`.
    pub quote_b64: String,
    /// The giver's one-time X25519 key.
    pub giver_public_b64: String,
    pub seal_nonce_b64: String,
    pub sealed_root_b64: String,
}

/// What the joiner's quote commits to after the nonce.
fn join_binding(joiner_public: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(JOIN_DOMAIN);
    hasher.update(joiner_public);
    hasher.finalize().into()
}

/// What the giver's quote commits to after the nonce: everything the joiner is
/// about to trust.
fn give_binding(
    joiner_public: &[u8; 32],
    giver_public: &[u8; 32],
    seal_nonce: &[u8; NONCE_LEN],
    sealed_root: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GIVE_DOMAIN);
    hasher.update(joiner_public);
    hasher.update(giver_public);
    hasher.update(seal_nonce);
    hasher.update(sealed_root);
    hasher.finalize().into()
}

/// The AES-256-GCM key both sides derive from their X25519 exchange.
fn root_seal_key(
    secret: &[u8; 32],
    their_public: &[u8; 32],
    giver_public: &[u8; 32],
    joiner_public: &[u8; 32],
    join_nonce: &[u8; 32],
) -> Result<LessSafeKey, ServiceError> {
    let shared = Zeroizing::new(MontgomeryPoint(*their_public).mul_clamped(*secret).0);
    // A low-order point gives an all-zero secret anybody can compute.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(ServiceError::InvalidAttestationRequest(
            "a cluster key is a low-order point".to_owned(),
        ));
    }
    let info: [&[u8]; 3] = [ROOT_SEAL_DOMAIN, giver_public, joiner_public];
    let prk = Salt::new(HKDF_SHA256, join_nonce).extract(shared.as_ref());
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| ServiceError::KeyDerivationFailed("HKDF expansion failed".to_owned()))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn seal_root(
    root: &Root,
    giver_secret: &[u8; 32],
    joiner_public: &[u8; 32],
    join_nonce: &[u8; 32],
    seal_nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, ServiceError> {
    let giver_public = MontgomeryPoint::mul_base_clamped(*giver_secret).0;
    let key = root_seal_key(
        giver_secret,
        joiner_public,
        &giver_public,
        joiner_public,
        join_nonce,
    )?;
    let mut buffer = root.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(seal_nonce),
        Aad::from(ROOT_SEAL_DOMAIN),
        &mut buffer,
    )
    .map_err(|_| ServiceError::KeyDerivationFailed("sealing the root failed".to_owned()))?;
    Ok(buffer)
}

fn open_root(
    joiner_secret: &[u8; 32],
    giver_public: &[u8; 32],
    join_nonce: &[u8; 32],
    seal_nonce: [u8; NONCE_LEN],
    sealed_root: &[u8],
) -> Result<Root, ServiceError> {
    let joiner_public = MontgomeryPoint::mul_base_clamped(*joiner_secret).0;
    let key = root_seal_key(
        joiner_secret,
        giver_public,
        giver_public,
        &joiner_public,
        join_nonce,
    )?;
    let mut buffer = Zeroizing::new(sealed_root.to_vec());
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(seal_nonce),
            Aad::from(ROOT_SEAL_DOMAIN),
            buffer.as_mut(),
        )
        .map_err(|_| {
            ServiceError::KeyDerivationFailed("the sealed root does not open".to_owned())
        })?;
    Root::from_bytes(plain)
}

/// The "same as me" rule, over a quote that already passed cryptographic
/// verification and its report-data binding.
fn check_peer(
    verification: &VerificationResult,
    own: &Measurements,
    policy: &AttestationPolicy,
) -> Result<(), ServiceError> {
    if !verification.is_valid() {
        return Err(ServiceError::AttestationVerificationFailed(format!(
            "peer quote failed verification (signature {}, nonce {}, binding {})",
            verification.quote_verified,
            verification.nonce_verified,
            verification.application_hash_verified
        )));
    }
    let body = &verification.quote.body;
    if is_debug_td(&body.tdattributes) {
        return Err(ServiceError::AttestationVerificationFailed(
            "peer is a debug TD".to_owned(),
        ));
    }
    let status = verification.tcb_status.as_deref().ok_or_else(|| {
        ServiceError::TcbStatusRejected("peer quote has no TCB status".to_owned())
    })?;
    if !policy
        .allowed_tcb_statuses
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(status))
    {
        return Err(ServiceError::TcbStatusRejected(format!(
            "peer TCB status '{status}' is not in this image's policy"
        )));
    }
    let theirs = Measurements::of(body);
    if &theirs != own {
        return Err(ServiceError::MeasurementPolicyRejected(format!(
            "peer measurements differ from this replica's: {theirs:?}"
        )));
    }
    Ok(())
}

/// Verify `quote` against `nonce ‖ binding` and apply the "same as me" rule.
async fn verify_peer(
    tdx: &TdxBackend,
    policy: &AttestationPolicy,
    quote: &[u8],
    nonce: &[u8; 32],
    binding: &[u8; 32],
) -> Result<(), ServiceError> {
    let verification = if tdx.is_mock() {
        #[cfg(feature = "mock-attestation")]
        {
            let mut result = verify_mock_attestation(quote, nonce, binding)
                .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?;
            // A mock quote has no TCB; accept it as the policy's first status so
            // the rest of the rule still runs.
            result.tcb_status = policy.allowed_tcb_statuses.first().cloned();
            result
        }
        #[cfg(not(feature = "mock-attestation"))]
        unreachable!("is_mock() is false without the mock-attestation feature")
    } else {
        verify_attestation(quote, nonce, binding)
            .await
            .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?
    };
    check_peer(&verification, tdx.own(), policy)
}

fn tdx_of(state: &AppState) -> Result<&Arc<TdxBackend>, ServiceError> {
    match &state.backend {
        Backend::Tdx(tdx) => Ok(tdx),
        Backend::Dstack { .. } => Err(ServiceError::InvalidAttestationRequest(
            "this KMS is not a TDX cluster replica".to_owned(),
        )),
    }
}

/// `POST /cluster/nonce`
pub(crate) async fn join_nonce_handler(
    State(state): State<AppState>,
) -> Result<Json<JoinNonceResponse>, ServiceError> {
    let tdx = tdx_of(&state)?;
    tdx.with_root(|_| Ok(()))?;
    let nonce = state.join_nonces.issue()?;
    Ok(Json(JoinNonceResponse {
        nonce_b64: BASE64.encode(nonce),
    }))
}

/// `POST /cluster/join`
pub(crate) async fn join_handler(
    State(state): State<AppState>,
    Json(request): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, ServiceError> {
    let tdx = tdx_of(&state)?;
    let nonce = decode_32("nonceB64", &request.nonce_b64)?;
    state.join_nonces.consume(&nonce)?;
    let joiner_public = decode_32("joinerPublicB64", &request.joiner_public_b64)?;
    let quote = BASE64
        .decode(&request.quote_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;

    verify_peer(
        tdx,
        &state.config.attestation_policy,
        &quote,
        &nonce,
        &join_binding(&joiner_public),
    )
    .await
    .inspect_err(|e| warn!("Refused a cluster join: {e}"))?;

    let giver_secret = Zeroizing::new(rand::random::<[u8; 32]>());
    let giver_public = MontgomeryPoint::mul_base_clamped(*giver_secret).0;
    let seal_nonce: [u8; NONCE_LEN] = rand::random();
    let sealed_root =
        tdx.with_root(|root| seal_root(root, &giver_secret, &joiner_public, &nonce, seal_nonce))?;

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&nonce);
    report_data[32..].copy_from_slice(&give_binding(
        &joiner_public,
        &giver_public,
        &seal_nonce,
        &sealed_root,
    ));
    let own_quote = tdx.quote(report_data).await?;
    info!("Gave the cluster root to a replica with this replica's measurements");
    Ok(Json(JoinResponse {
        quote_b64: BASE64.encode(own_quote.quote_bytes),
        giver_public_b64: BASE64.encode(giver_public),
        seal_nonce_b64: BASE64.encode(seal_nonce),
        sealed_root_b64: BASE64.encode(sealed_root),
    }))
}

/// Get the root from one peer. `peer` is a base URL such as `http://10.0.0.5:8080`.
async fn join_from(
    client: &reqwest::Client,
    tdx: &TdxBackend,
    policy: &AttestationPolicy,
    peer: &str,
) -> Result<Root, ServiceError> {
    let peer = peer.trim_end_matches('/');
    let fail =
        |e: reqwest::Error| ServiceError::AttestationVerificationFailed(format!("{peer}: {e}"));

    let nonce: JoinNonceResponse = client
        .post(format!("{peer}/cluster/nonce"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(fail)?
        .json()
        .await
        .map_err(fail)?;
    let nonce = decode_32("nonceB64", &nonce.nonce_b64)?;

    let joiner_secret = Zeroizing::new(rand::random::<[u8; 32]>());
    let joiner_public = MontgomeryPoint::mul_base_clamped(*joiner_secret).0;
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&nonce);
    report_data[32..].copy_from_slice(&join_binding(&joiner_public));
    let quote = tdx.quote(report_data).await?;

    let response: JoinResponse = client
        .post(format!("{peer}/cluster/join"))
        .json(&JoinRequest {
            nonce_b64: BASE64.encode(nonce),
            joiner_public_b64: BASE64.encode(joiner_public),
            quote_b64: BASE64.encode(&quote.quote_bytes),
        })
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(fail)?
        .json()
        .await
        .map_err(fail)?;

    let giver_public = decode_32("giverPublicB64", &response.giver_public_b64)?;
    let seal_nonce: [u8; NONCE_LEN] = BASE64
        .decode(&response.seal_nonce_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?
        .try_into()
        .map_err(|_| {
            ServiceError::InvalidAttestationRequest("sealNonceB64 is 12 bytes".to_owned())
        })?;
    let sealed_root = BASE64
        .decode(&response.sealed_root_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;
    let giver_quote = BASE64
        .decode(&response.quote_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;

    verify_peer(
        tdx,
        policy,
        &giver_quote,
        &nonce,
        &give_binding(&joiner_public, &giver_public, &seal_nonce, &sealed_root),
    )
    .await?;
    open_root(
        &joiner_secret,
        &giver_public,
        &nonce,
        seal_nonce,
        &sealed_root,
    )
}

/// Try every peer until one hands over the root, then keep it. Runs until it
/// succeeds: until then this replica answers `/get-key` with 503.
pub(crate) async fn join_until_ready(
    tdx: Arc<TdxBackend>,
    policy: AttestationPolicy,
    peers: Vec<String>,
    retry: Duration,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("a default reqwest client always builds");
    loop {
        for peer in &peers {
            match join_from(&client, &tdx, &policy, peer).await {
                Ok(root) => match tdx.set_root(root) {
                    Ok(()) => {
                        info!(%peer, "Joined the cluster");
                        return;
                    }
                    Err(e) => {
                        warn!(%peer, "Could not install the root: {e}");
                        return;
                    }
                },
                Err(e) => warn!(%peer, "Cluster join failed: {e}"),
            }
        }
        tokio::time::sleep(retry).await;
    }
}

fn decode_32(field: &str, value: &str) -> Result<[u8; 32], ServiceError> {
    crate::handlers::decode_fixed_b64_32(field, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{test_tdx_backend, KEY_LEN};
    use crate::test_util::zero_quote;

    const JOIN_NONCE: [u8; 32] = [0x11; 32];

    fn policy() -> AttestationPolicy {
        AttestationPolicy {
            allowed_tcb_statuses: vec!["uptodate".to_owned(), "outofdate".to_owned()],
            ..AttestationPolicy::default()
        }
    }

    /// A verified quote from a production (non-debug) TD with `own`'s registers.
    fn verified(own: &Measurements) -> VerificationResult {
        let mut quote = zero_quote(&[0; 64]);
        quote.body.mrtd.clone_from(&own.mrtd);
        quote.body.rtmr0.clone_from(&own.rtmr0);
        quote.body.rtmr1.clone_from(&own.rtmr1);
        quote.body.rtmr2.clone_from(&own.rtmr2);
        quote.body.rtmr3.clone_from(&own.rtmr3);
        quote.body.tdattributes = "0000001000000000".to_owned();
        VerificationResult {
            quote_verified: true,
            nonce_verified: true,
            application_hash_verified: true,
            tcb_status: Some("UpToDate".to_owned()),
            advisory_ids: Vec::new(),
            quote,
        }
    }

    fn own() -> Measurements {
        test_tdx_backend(None).own().clone()
    }

    #[test]
    fn a_peer_with_the_same_measurements_passes() {
        check_peer(&verified(&own()), &own(), &policy()).unwrap();
    }

    #[test]
    fn a_peer_with_any_other_register_is_refused() {
        for register in 0..5 {
            let mut result = verified(&own());
            let body = &mut result.quote.body;
            let field = match register {
                0 => &mut body.mrtd,
                1 => &mut body.rtmr0,
                2 => &mut body.rtmr1,
                3 => &mut body.rtmr2,
                _ => &mut body.rtmr3,
            };
            *field = "1".repeat(96);
            assert!(
                matches!(
                    check_peer(&result, &own(), &policy()),
                    Err(ServiceError::MeasurementPolicyRejected(_))
                ),
                "register {register} differs but the peer passed"
            );
        }
    }

    #[test]
    fn a_debug_peer_is_refused_even_with_equal_measurements() {
        let mut result = verified(&own());
        result.quote.body.tdattributes = "0100001000000000".to_owned();
        assert!(check_peer(&result, &own(), &policy()).is_err());
    }

    #[test]
    fn an_out_of_date_tcb_passes_when_the_policy_allows_it() {
        let mut result = verified(&own());
        result.tcb_status = Some("OutOfDate".to_owned());
        check_peer(&result, &own(), &policy()).unwrap();
        result.tcb_status = Some("Revoked".to_owned());
        assert!(matches!(
            check_peer(&result, &own(), &policy()),
            Err(ServiceError::TcbStatusRejected(_))
        ));
    }

    #[test]
    fn a_quote_that_failed_verification_is_refused() {
        let mut result = verified(&own());
        result.application_hash_verified = false;
        assert!(check_peer(&result, &own(), &policy()).is_err());
    }

    #[test]
    fn the_root_round_trips_between_the_two_one_time_keys() {
        let root = Root::from_bytes(&[0x42; KEY_LEN]).unwrap();
        let giver_secret = [0x22; 32];
        let joiner_secret = [0x33; 32];
        let giver_public = MontgomeryPoint::mul_base_clamped(giver_secret).0;
        let joiner_public = MontgomeryPoint::mul_base_clamped(joiner_secret).0;
        let seal_nonce = [0x44; NONCE_LEN];
        let sealed = seal_root(
            &root,
            &giver_secret,
            &joiner_public,
            &JOIN_NONCE,
            seal_nonce,
        )
        .unwrap();
        assert_ne!(&sealed[..KEY_LEN], root.as_bytes());
        let opened = open_root(
            &joiner_secret,
            &giver_public,
            &JOIN_NONCE,
            seal_nonce,
            &sealed,
        )
        .unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());
    }

    #[test]
    fn a_sealed_root_opens_only_for_its_joiner_and_nonce() {
        let root = Root::from_bytes(&[0x42; KEY_LEN]).unwrap();
        let giver_secret = [0x22; 32];
        let joiner_public = MontgomeryPoint::mul_base_clamped([0x33; 32]).0;
        let giver_public = MontgomeryPoint::mul_base_clamped(giver_secret).0;
        let seal_nonce = [0x44; NONCE_LEN];
        let sealed = seal_root(
            &root,
            &giver_secret,
            &joiner_public,
            &JOIN_NONCE,
            seal_nonce,
        )
        .unwrap();
        assert!(open_root(&[0x55; 32], &giver_public, &JOIN_NONCE, seal_nonce, &sealed).is_err());
        assert!(open_root(&[0x33; 32], &giver_public, &[0x12; 32], seal_nonce, &sealed).is_err());
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(open_root(
            &[0x33; 32],
            &giver_public,
            &JOIN_NONCE,
            seal_nonce,
            &tampered
        )
        .is_err());
    }

    #[test]
    fn a_low_order_joiner_key_is_refused() {
        let root = Root::from_bytes(&[0x42; KEY_LEN]).unwrap();
        assert!(seal_root(&root, &[0x22; 32], &[0; 32], &JOIN_NONCE, [0; NONCE_LEN]).is_err());
    }

    #[test]
    fn the_give_binding_covers_everything_the_joiner_trusts() {
        let base = give_binding(&[1; 32], &[2; 32], &[3; NONCE_LEN], &[4; 48]);
        assert_ne!(
            base,
            give_binding(&[9; 32], &[2; 32], &[3; NONCE_LEN], &[4; 48])
        );
        assert_ne!(
            base,
            give_binding(&[1; 32], &[9; 32], &[3; NONCE_LEN], &[4; 48])
        );
        assert_ne!(
            base,
            give_binding(&[1; 32], &[2; 32], &[9; NONCE_LEN], &[4; 48])
        );
        assert_ne!(
            base,
            give_binding(&[1; 32], &[2; 32], &[3; NONCE_LEN], &[9; 48])
        );
        assert_ne!(join_binding(&[1; 32]), join_binding(&[2; 32]));
    }

    #[test]
    fn a_join_nonce_works_once() {
        let nonces = JoinNonces::default();
        let nonce = nonces.issue().unwrap();
        nonces.consume(&nonce).unwrap();
        assert!(nonces.consume(&nonce).is_err());
        assert!(nonces.consume(&[0; 32]).is_err());
    }

    /// Two replicas over real HTTP: the joiner runs the whole protocol against
    /// the giver and must end up deriving the giver's keys.
    #[cfg(feature = "mock-attestation")]
    mod over_http {
        use std::net::SocketAddr;

        use super::*;
        use crate::backend::test_tdx_backend_with_rtmr3;
        use crate::handlers::create_router;
        use crate::Config;

        fn config() -> Config {
            Config {
                accept_mock_attestation: true,
                attestation_policy: policy(),
                ..Config::default()
            }
        }

        async fn serve(tdx: Arc<TdxBackend>) -> SocketAddr {
            let app = create_router(config(), Backend::Tdx(tdx)).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(tokio::spawn(
                async move { axum::serve(listener, app).await },
            ));
            addr
        }

        #[tokio::test]
        async fn a_replica_with_the_same_measurements_joins_and_derives_the_same_keys() {
            let giver = Arc::new(test_tdx_backend(Some(Root::generate())));
            let addr = serve(Arc::clone(&giver)).await;
            let joiner = Arc::new(test_tdx_backend(None));

            tokio::time::timeout(
                Duration::from_secs(20),
                join_until_ready(
                    Arc::clone(&joiner),
                    policy(),
                    vec![format!("http://{addr}")],
                    Duration::from_millis(100),
                ),
            )
            .await
            .expect("the joiner got the root");

            let path = "merod/storage/locked-read-only/12D3KooWPeer";
            let giver_key = Backend::Tdx(giver).derive_key_hex(path).await.unwrap();
            let joiner_key = Backend::Tdx(joiner).derive_key_hex(path).await.unwrap();
            assert_eq!(*giver_key, *joiner_key);
        }

        #[tokio::test]
        async fn a_replica_of_a_different_image_is_refused() {
            // The giver believes it runs another image, so the joiner's quote
            // does not match it.
            let giver = Arc::new(test_tdx_backend_with_rtmr3(
                Some(Root::generate()),
                &"1".repeat(96),
            ));
            let addr = serve(giver).await;
            let joiner = test_tdx_backend(None);
            let client = reqwest::Client::new();
            let refused = join_from(&client, &joiner, &policy(), &format!("http://{addr}")).await;
            assert!(refused.is_err());
            assert!(!joiner.has_root());
        }

        #[tokio::test]
        async fn a_replica_without_a_root_gives_nothing() {
            let addr = serve(Arc::new(test_tdx_backend(None))).await;
            let joiner = test_tdx_backend(None);
            let client = reqwest::Client::new();
            assert!(
                join_from(&client, &joiner, &policy(), &format!("http://{addr}"))
                    .await
                    .is_err()
            );
        }
    }
}
