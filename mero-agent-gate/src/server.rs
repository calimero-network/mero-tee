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
use tracing::{info, warn};

use crate::keys::ProvisioningKey;
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
    /// X25519 keys of the provisioners baked into the image.
    pub provisioners: Vec<[u8; 32]>,
    /// Accept Base-mode (unauthenticated) bundles. Debug images only.
    pub allow_unauthenticated: bool,
    /// Whether any bundle has been written since this start.
    pub provisioned: AtomicBool,
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
    let binding = key_binding(&gate.provisioning.public, &gate.signing_public);
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
    let encapped = BASE64
        .decode(request.encapped_key_b64.trim())
        .map_err(|_| GateError::bad_request("encappedKeyB64 is not base64"))?;
    let ciphertext = BASE64
        .decode(request.ciphertext_b64.trim())
        .map_err(|_| GateError::bad_request("ciphertextB64 is not base64"))?;

    let (bundle, sender) = open_bundle(
        &gate.provisioning.private,
        &gate.provisioning.public,
        &gate.provisioners,
        gate.allow_unauthenticated,
        &encapped,
        &ciphertext,
    )
    .map_err(|e| match e {
        OpenError::Unauthorized => {
            warn!("Refused a provisioning message no listed provisioner sealed");
            GateError::new(
                StatusCode::FORBIDDEN,
                "unauthorized_provisioner",
                e.to_string(),
            )
        }
        OpenError::Malformed(_) => GateError::bad_request(e.to_string()),
    })?;
    bundle.validate().map_err(GateError::bad_request)?;

    let secrets_dir = gate.secrets_dir.clone();
    let written = tokio::task::spawn_blocking(move || write_secrets(&secrets_dir, &bundle))
        .await
        .map_err(|e| {
            GateError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                e.to_string(),
            )
        })?
        .map_err(|e| GateError::new(StatusCode::INTERNAL_SERVER_ERROR, "write_failed", e))?;
    gate.provisioned.store(true, Ordering::Relaxed);
    info!(
        secrets = ?written,
        provisioner = %sender.map_or_else(|| "unauthenticated".to_owned(), |key| BASE64.encode(key)),
        "Provisioned secrets"
    );
    Ok(Json(ProvisionResponse { written }))
}

/// Write each secret to `dir/<name>`, mode 0600, through a temporary file and a
/// rename, so the agent never reads half a value. Names were validated, so
/// none is a path, hidden, or one of these temporaries.
fn write_secrets(dir: &Path, bundle: &SecretsBundle) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, value) in &bundle.secrets {
        let target = dir.join(name);
        let temporary = dir.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&temporary);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
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
    use crate::protocol::{keypair_from_secret, seal_bundle};
    use crate::test_util::TempDir;

    /// A quote that is just the report data, so tests can read it back.
    struct EchoQuoter;
    impl Quoter for EchoQuoter {
        fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
            Ok(report_data.to_vec())
        }
    }

    const PROVISIONER_SECRET: [u8; 32] = [0x22; 32];

    fn gate(dir: &TempDir, allow_unauthenticated: bool) -> Arc<Gate> {
        let (_, provisioner) = keypair_from_secret(&PROVISIONER_SECRET).unwrap();
        Arc::new(Gate {
            quoter: Arc::new(EchoQuoter),
            provisioning: ProvisioningKey::generate(),
            signing_public: [0x55; 32],
            secrets_dir: dir.path().join("secrets"),
            provisioners: vec![provisioner],
            allow_unauthenticated,
            provisioned: AtomicBool::new(false),
        })
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

    fn sealed_request(
        gate: &Gate,
        sender: Option<&[u8; 32]>,
        pairs: &[(&str, &str)],
    ) -> serde_json::Value {
        let bundle = SecretsBundle {
            secrets: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        };
        let (enc, ct) = seal_bundle(&gate.provisioning.public, sender, &bundle).unwrap();
        json!({
            "provisioningPublicKeyB64": BASE64.encode(gate.provisioning.public),
            "encappedKeyB64": BASE64.encode(enc),
            "ciphertextB64": BASE64.encode(ct),
        })
    }

    #[tokio::test]
    async fn the_quote_binds_the_nonce_and_both_keys() {
        let dir = TempDir::new("attest");
        let gate = gate(&dir, false);
        let (status, body) = post(
            &gate,
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 32]) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let quote = BASE64.decode(body["quoteB64"].as_str().unwrap()).unwrap();
        let expected = report_data(
            &[7; 32],
            &key_binding(&gate.provisioning.public, &[0x55; 32]),
        );
        assert_eq!(quote, expected);
        assert_eq!(body["reportDataHex"], hex::encode(expected));
        assert_eq!(body["signingPublicKeyB64"], BASE64.encode([0x55u8; 32]));
    }

    #[tokio::test]
    async fn a_short_nonce_is_refused() {
        let dir = TempDir::new("attest-nonce");
        let (status, _) = post(
            &gate(&dir, false),
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 16]) }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_listed_provisioner_writes_owner_only_files() {
        let dir = TempDir::new("provision");
        let gate = gate(&dir, false);
        let request = sealed_request(
            &gate,
            Some(&PROVISIONER_SECRET),
            &[("API_KEY", "s3cret"), ("MODEL", "m")],
        );
        let (status, body) = post(&gate, "/provision", request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["written"], json!(["API_KEY", "MODEL"]));
        let path = dir.path().join("secrets/API_KEY");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "s3cret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(gate.provisioned.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn an_unlisted_provisioner_writes_nothing() {
        let dir = TempDir::new("provision-unlisted");
        let gate = gate(&dir, false);
        let request = sealed_request(&gate, Some(&[0x33; 32]), &[("API_KEY", "evil")]);
        let (status, body) = post(&gate, "/provision", request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "unauthorized_provisioner");
        assert!(!dir.path().join("secrets/API_KEY").exists());
    }

    #[tokio::test]
    async fn base_mode_needs_a_gate_that_allows_it() {
        let dir = TempDir::new("provision-base");
        let strict = gate(&dir, false);
        let (status, _) = post(
            &strict,
            "/provision",
            sealed_request(&strict, None, &[("A", "b")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let debug = gate(&dir, true);
        let (status, _) = post(
            &debug,
            "/provision",
            sealed_request(&debug, None, &[("A", "b")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_message_for_an_earlier_start_is_stale() {
        let dir = TempDir::new("provision-stale");
        let before_restart = gate(&dir, false);
        let request = sealed_request(&before_restart, Some(&PROVISIONER_SECRET), &[("A", "b")]);
        let after_restart = gate(&dir, false);
        let (status, body) = post(&after_restart, "/provision", request).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "stale_provisioning_key");
    }

    #[tokio::test]
    async fn a_bad_name_writes_nothing_at_all() {
        let dir = TempDir::new("provision-name");
        let gate = gate(&dir, false);
        let request = sealed_request(
            &gate,
            Some(&PROVISIONER_SECRET),
            &[("GOOD", "x"), ("../escape", "y")],
        );
        let (status, _) = post(&gate, "/provision", request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !dir.path().join("secrets/GOOD").exists(),
            "validated before any write"
        );
        assert!(!dir.path().join("escape").exists());
    }
}
