//! The gate's HTTP service: `/health`, `/attest`, `/provision`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::keys::{store_owner, ProvisioningKey, Share};
use crate::protocol::{
    key_binding, open_bundle, report_data, AttestRequest, AttestResponse, OpenError,
    ProvisionRequest, ProvisionResponse, SecretsBundle,
};

/// A sealed bundle is at most 64 secrets of 64 KiB, plus base64 and JSON.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Where quotes come from. A trait so the HTTP layer is tested without a TD.
pub trait Quoter: Send + Sync + 'static {
    /// Raw quote bytes over `report_data`.
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String>;
}

/// Quotes from this TD, through configfs-tsm (core's `generate_attestation`,
/// the same code mero-kms and merod quote with).
pub struct TdxQuoter;

impl Quoter for TdxQuoter {
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        calimero_tee_attestation::generate_attestation(report_data)
            .map(|result| result.quote_bytes)
            .map_err(|e| e.to_string())
    }
}

/// Mock quotes, for development without a TD. Only in the default-off
/// `mock-attestation` build, and only a provisioner built the same way
/// accepts them.
#[cfg(feature = "mock-attestation")]
pub struct MockQuoter;

#[cfg(feature = "mock-attestation")]
impl Quoter for MockQuoter {
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        Ok(calimero_tee_attestation::generate_mock_attestation(report_data).quote_bytes)
    }
}

/// Everything a request handler needs.
pub struct Gate {
    pub quoter: Arc<dyn Quoter>,
    pub provisioning: ProvisioningKey,
    pub signing_public: [u8; 32],
    /// Where secrets are written, one file per name. On the encrypted disk.
    pub secrets_dir: PathBuf,
    /// Who besides the gate reads them: the agent's group.
    pub share: Share,
    /// The owner's X25519 key, once claimed; held across a claim so two
    /// first bundles cannot both claim.
    pub owner: Mutex<Option<[u8; 32]>>,
    /// Where the claim is recorded, on the encrypted disk.
    pub owner_path: PathBuf,
    /// Whether any bundle has been written since this start.
    pub provisioned: AtomicBool,
}

impl Gate {
    /// A gate as `main` builds it: no bundle written yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        quoter: Arc<dyn Quoter>,
        provisioning: ProvisioningKey,
        signing_public: [u8; 32],
        secrets_dir: PathBuf,
        share: Share,
        owner: Option<[u8; 32]>,
        owner_path: PathBuf,
    ) -> Self {
        Self {
            quoter,
            provisioning,
            signing_public,
            secrets_dir,
            share,
            owner: Mutex::new(owner),
            owner_path,
            provisioned: AtomicBool::new(false),
        }
    }
}

pub fn router(gate: Arc<Gate>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .route("/provision", post(provision))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(gate)
}

/// A refusal, as `{ "error": ..., "details": ... }`. Never carries a secret.
#[derive(Debug)]
pub struct GateError {
    status: StatusCode,
    error: &'static str,
    details: String,
}

impl GateError {
    fn new(status: StatusCode, error: &'static str, details: impl Into<String>) -> Self {
        Self {
            status,
            error,
            details: details.into(),
        }
    }

    fn bad_request(details: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", details)
    }
}

impl IntoResponse for GateError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({ "error": self.error, "details": self.details })),
        )
            .into_response()
    }
}

async fn health(State(gate): State<Arc<Gate>>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "claimed": gate.owner.lock().await.is_some(),
        "provisioned": gate.provisioned.load(Ordering::Relaxed),
    }))
}

fn decode_32(field: &str, value: &str) -> Result<[u8; 32], GateError> {
    BASE64
        .decode(value.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| GateError::bad_request(format!("{field} must be 32 bytes of base64")))
}

async fn attest(
    State(gate): State<Arc<Gate>>,
    Json(request): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, GateError> {
    let nonce = decode_32("nonceB64", &request.nonce_b64)?;
    let owner = *gate.owner.lock().await;
    let binding = key_binding(
        &gate.provisioning.public,
        &gate.signing_public,
        owner.as_ref(),
    );
    let data = report_data(&nonce, &binding);
    let quoter = Arc::clone(&gate.quoter);
    let quote = tokio::task::spawn_blocking(move || quoter.quote(data))
        .await
        .map_err(|e| {
            GateError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "quote_failed",
                e.to_string(),
            )
        })?
        .map_err(|e| GateError::new(StatusCode::INTERNAL_SERVER_ERROR, "quote_failed", e))?;
    Ok(Json(AttestResponse {
        quote_b64: BASE64.encode(quote),
        report_data_hex: hex::encode(data),
        provisioning_public_key_b64: BASE64.encode(gate.provisioning.public),
        signing_public_key_b64: BASE64.encode(gate.signing_public),
        owner_public_key_b64: owner.map(|key| BASE64.encode(key)),
    }))
}

async fn provision(
    State(gate): State<Arc<Gate>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, GateError> {
    let addressed_to = decode_32(
        "provisioningPublicKeyB64",
        &request.provisioning_public_key_b64,
    )?;
    if addressed_to != gate.provisioning.public {
        // The gate restarted since the provisioner's /attest; its quote no
        // longer covers this key. Say so, rather than "cannot open".
        return Err(GateError::new(
            StatusCode::CONFLICT,
            "stale_provisioning_key",
            "sealed to a provisioning key this gate no longer holds; attest again",
        ));
    }
    let sender = decode_32("senderPublicKeyB64", &request.sender_public_key_b64)?;
    let encapped = BASE64
        .decode(request.encapped_key_b64.trim())
        .map_err(|_| GateError::bad_request("encappedKeyB64 is not base64"))?;
    let ciphertext = BASE64
        .decode(request.ciphertext_b64.trim())
        .map_err(|_| GateError::bad_request("ciphertextB64 is not base64"))?;

    // Held to the end: a claim and the secrets it brings are one step, and a
    // second first bundle waits, then finds the agent claimed.
    let mut owner = gate.owner.lock().await;
    if let Some(current) = *owner {
        if current != sender {
            warn!("Refused a bundle from a key that does not own this agent");
            return Err(GateError::new(
                StatusCode::FORBIDDEN,
                "not_the_owner",
                "this agent is claimed by another key",
            ));
        }
    }
    let bundle = open_bundle(
        &gate.provisioning.private,
        &gate.provisioning.public,
        &sender,
        &encapped,
        &ciphertext,
    )
    .map_err(|e| match e {
        OpenError::NotFromSender => {
            warn!("Refused a bundle not sealed by the key it names");
            GateError::new(StatusCode::FORBIDDEN, "not_from_sender", e.to_string())
        }
        OpenError::Malformed(_) => GateError::bad_request(e.to_string()),
    })?;
    bundle.validate().map_err(GateError::bad_request)?;

    // The claim is durable before any secret is written: an owner told it
    // claimed the agent has, even if the gate dies next.
    let claimed = owner.is_none();
    if claimed {
        let path = gate.owner_path.clone();
        let share = gate.share;
        blocking(move || store_owner(&path, share, &sender).map_err(|e| e.to_string())).await?;
        *owner = Some(sender);
        info!(owner = %BASE64.encode(sender), "Agent claimed");
    }

    let secrets_dir = gate.secrets_dir.clone();
    let share = gate.share;
    let written = blocking(move || write_secrets(&secrets_dir, share, &bundle)).await?;
    gate.provisioned.store(true, Ordering::Relaxed);
    info!(secrets = ?written, "Provisioned secrets");
    Ok(Json(ProvisionResponse { written, claimed }))
}

/// Run file I/O off the async workers; any failure is a 500.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, GateError> {
    let fail = |e: String| GateError::new(StatusCode::INTERNAL_SERVER_ERROR, "write_failed", e);
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| fail(e.to_string()))?
        .map_err(fail)
}

/// Write each secret to `dir/<name>`, readable by the gate and the agent's
/// group only, through a temporary file and a rename, so the agent never reads
/// half a value. Names were validated, so none is a path, hidden, or one of
/// these temporaries.
fn write_secrets(dir: &Path, share: Share, bundle: &SecretsBundle) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, value) in &bundle.secrets {
        let target = dir.join(name);
        let temporary = dir.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&temporary);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(share.file_mode())
            .open(&temporary)
            .map_err(|e| format!("{}: {e}", temporary.display()))?;
        share
            .apply(&temporary)
            .map_err(|e| format!("{}: {e}", temporary.display()))?;
        file.write_all(value.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", temporary.display()))?;
        std::fs::rename(&temporary, &target).map_err(|e| format!("{}: {e}", target.display()))?;
    }
    // The renames are durable once the directory is.
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(bundle.secrets.keys().cloned().collect())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    use super::*;
    use crate::keys::load_owner;
    use crate::protocol::{keypair_from_secret, seal_bundle};
    use crate::test_util::TempDir;

    /// A quote that is just the report data, so tests can read it back.
    struct EchoQuoter;
    impl Quoter for EchoQuoter {
        fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
            Ok(report_data.to_vec())
        }
    }

    const OWNER_SECRET: [u8; 32] = [0x22; 32];
    const OTHER_SECRET: [u8; 32] = [0x33; 32];

    fn public(secret: &[u8; 32]) -> [u8; 32] {
        keypair_from_secret(secret).unwrap().1
    }

    /// A gate over `dir`, picking up a claim an earlier start recorded there.
    fn gate(dir: &TempDir) -> Arc<Gate> {
        let owner_path = dir.path().join("owner.x25519");
        Arc::new(Gate::new(
            Arc::new(EchoQuoter),
            ProvisioningKey::generate(),
            [0x55; 32],
            dir.path().join("secrets"),
            Share::default(),
            load_owner(&owner_path).unwrap(),
            owner_path,
        ))
    }

    async fn post(
        gate: &Arc<Gate>,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = router(Arc::clone(gate))
            .oneshot(
                Request::post(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// A bundle sealed by `sealed_by`, naming `named` as its sender.
    fn request_naming(
        gate: &Gate,
        sealed_by: &[u8; 32],
        named: &[u8; 32],
        pairs: &[(&str, &str)],
    ) -> serde_json::Value {
        let bundle = SecretsBundle {
            secrets: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        };
        let (enc, ct) = seal_bundle(&gate.provisioning.public, sealed_by, &bundle).unwrap();
        json!({
            "provisioningPublicKeyB64": BASE64.encode(gate.provisioning.public),
            "senderPublicKeyB64": BASE64.encode(public(named)),
            "encappedKeyB64": BASE64.encode(enc),
            "ciphertextB64": BASE64.encode(ct),
        })
    }

    fn request(gate: &Gate, sender: &[u8; 32], pairs: &[(&str, &str)]) -> serde_json::Value {
        request_naming(gate, sender, sender, pairs)
    }

    async fn attest(gate: &Arc<Gate>) -> serde_json::Value {
        let (status, body) = post(
            gate,
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 32]) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        body
    }

    #[tokio::test]
    async fn an_unclaimed_quote_binds_no_owner() {
        let dir = TempDir::new("attest");
        let gate = gate(&dir);
        let body = attest(&gate).await;
        let quote = BASE64.decode(body["quoteB64"].as_str().unwrap()).unwrap();
        let expected = report_data(
            &[7; 32],
            &key_binding(&gate.provisioning.public, &[0x55; 32], None),
        );
        assert_eq!(quote, expected);
        assert!(body.get("ownerPublicKeyB64").is_none());
    }

    #[tokio::test]
    async fn a_short_nonce_is_refused() {
        let dir = TempDir::new("attest-nonce");
        let (status, _) = post(
            &gate(&dir),
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 16]) }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_first_bundle_claims_the_agent_and_the_quote_says_so() {
        let dir = TempDir::new("claim");
        let gate = gate(&dir);
        let (status, body) = post(
            &gate,
            "/provision",
            request(
                &gate,
                &OWNER_SECRET,
                &[("API_KEY", "s3cret"), ("MODEL", "m")],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["written"], json!(["API_KEY", "MODEL"]));
        assert_eq!(body["claimed"], true);
        let path = dir.path().join("secrets/API_KEY");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "s3cret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let owner = public(&OWNER_SECRET);
        let body = attest(&gate).await;
        assert_eq!(body["ownerPublicKeyB64"], BASE64.encode(owner));
        let quote = BASE64.decode(body["quoteB64"].as_str().unwrap()).unwrap();
        assert_eq!(
            quote,
            report_data(
                &[7; 32],
                &key_binding(&gate.provisioning.public, &[0x55; 32], Some(&owner))
            )
        );
    }

    #[tokio::test]
    async fn the_owner_provisions_again_without_claiming_again() {
        let dir = TempDir::new("claim-again");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, &OWNER_SECRET, &[("A", "2")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["claimed"], false);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("secrets/A")).unwrap(),
            "2"
        );
    }

    #[tokio::test]
    async fn another_key_cannot_provision_a_claimed_agent() {
        let dir = TempDir::new("claim-other");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, &OWNER_SECRET, &[("API_KEY", "mine")]),
        )
        .await;
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, &OTHER_SECRET, &[("API_KEY", "evil")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_the_owner");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("secrets/API_KEY")).unwrap(),
            "mine"
        );
    }

    #[tokio::test]
    async fn naming_the_owner_without_its_key_is_refused() {
        let dir = TempDir::new("claim-impersonate");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, &OWNER_SECRET, &[("API_KEY", "mine")]),
        )
        .await;
        let forged = request_naming(&gate, &OTHER_SECRET, &OWNER_SECRET, &[("API_KEY", "evil")]);
        let (status, body) = post(&gate, "/provision", forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_from_sender");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("secrets/API_KEY")).unwrap(),
            "mine"
        );
    }

    #[tokio::test]
    async fn a_forged_first_bundle_claims_nothing() {
        let dir = TempDir::new("claim-forged");
        let gate = gate(&dir);
        let forged = request_naming(&gate, &OTHER_SECRET, &OWNER_SECRET, &[("A", "b")]);
        let (status, _) = post(&gate, "/provision", forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!dir.path().join("owner.x25519").exists());
        assert!(gate.owner.lock().await.is_none());
    }

    #[tokio::test]
    async fn a_claim_survives_a_restart() {
        let dir = TempDir::new("claim-restart");
        let before = gate(&dir);
        post(
            &before,
            "/provision",
            request(&before, &OWNER_SECRET, &[("A", "b")]),
        )
        .await;
        let after = gate(&dir);
        let body = attest(&after).await;
        assert_eq!(
            body["ownerPublicKeyB64"],
            BASE64.encode(public(&OWNER_SECRET))
        );
        let (status, _) = post(
            &after,
            "/provision",
            request(&after, &OTHER_SECRET, &[("A", "c")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_message_for_an_earlier_start_is_stale() {
        let dir = TempDir::new("provision-stale");
        let before_restart = gate(&dir);
        let request = request(&before_restart, &OWNER_SECRET, &[("A", "b")]);
        let after_restart = gate(&dir);
        let (status, body) = post(&after_restart, "/provision", request).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "stale_provisioning_key");
    }

    #[tokio::test]
    async fn a_bad_name_writes_nothing_and_claims_nothing() {
        let dir = TempDir::new("provision-name");
        let gate = gate(&dir);
        let request = request(&gate, &OWNER_SECRET, &[("GOOD", "x"), ("../escape", "y")]);
        let (status, _) = post(&gate, "/provision", request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !dir.path().join("secrets/GOOD").exists(),
            "validated before any write"
        );
        assert!(!dir.path().join("escape").exists());
        assert!(
            gate.owner.lock().await.is_none(),
            "a refused bundle claims nothing"
        );
    }
}
