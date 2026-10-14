//! The gate's HTTP service: `/health`, `/attest`, `/provision`, `/release`,
//! `/operator`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

use crate::keys::{ProvisioningKey, Share};
use crate::protocol::{
    key_binding, open_message, open_operator_message, report_data, validate_agent_id,
    AttestRequest, AttestResponse, OpenError, ProvisionRequest, ProvisionResponse, ReleaseOrder,
    ReleaseResponse, SecretsBundle,
};
use crate::slots::Slot;

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

/// Stops and starts a slot's agent, so a release never erases files under a
/// running agent. A trait so the HTTP layer is tested without systemd.
pub trait Units: Send + Sync + 'static {
    fn stop(&self, slot: u32) -> Result<(), String>;
    fn start(&self, slot: u32) -> Result<(), String>;
}

/// No agent processes to manage (tests, or a gate run by hand).
pub struct NoUnits;

impl Units for NoUnits {
    fn stop(&self, _slot: u32) -> Result<(), String> {
        Ok(())
    }
    fn start(&self, _slot: u32) -> Result<(), String> {
        Ok(())
    }
}

/// Each slot's agent as a systemd unit, named by `template` with `{slot}` in
/// it (`mero-agent@{slot}.service`).
pub struct SystemdUnits {
    pub template: String,
}

impl SystemdUnits {
    fn run(&self, verb: &str, slot: u32) -> Result<(), String> {
        let unit = self.template.replace("{slot}", &slot.to_string());
        let status = std::process::Command::new("systemctl")
            .args([verb, &unit])
            .status()
            .map_err(|e| format!("systemctl {verb} {unit}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("systemctl {verb} {unit}: {status}"))
        }
    }
}

impl Units for SystemdUnits {
    fn stop(&self, slot: u32) -> Result<(), String> {
        self.run("stop", slot)
    }
    fn start(&self, slot: u32) -> Result<(), String> {
        self.run("start", slot)
    }
}

/// Everything a request handler needs.
pub struct Gate {
    pub quoter: Arc<dyn Quoter>,
    pub provisioning: ProvisioningKey,
    /// Every agent's place on the TD; held across a claim, so two first
    /// bundles cannot both claim one agent id or one slot.
    pub slots: Mutex<Vec<Slot>>,
    pub units: Arc<dyn Units>,
    /// The X25519 key that may write [`crate::protocol::OPERATOR_SECRETS`]
    /// into a claimed agent (`/operator`). Whoever runs the VM names it; it
    /// can neither claim nor release an agent nor touch the owner's secrets.
    /// None: `/operator` refuses everything.
    pub operator: Option<[u8; 32]>,
}

impl Gate {
    pub fn new(
        quoter: Arc<dyn Quoter>,
        provisioning: ProvisioningKey,
        slots: Vec<Slot>,
        units: Arc<dyn Units>,
    ) -> Self {
        Self {
            quoter,
            provisioning,
            slots: Mutex::new(slots),
            units,
            operator: None,
        }
    }

    /// The gate, with `operator` allowed to write the operator's secrets.
    #[must_use]
    pub fn with_operator(mut self, operator: Option<[u8; 32]>) -> Self {
        self.operator = operator;
        self
    }
}

pub fn router(gate: Arc<Gate>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .route("/provision", post(provision))
        .route("/release", post(release))
        .route("/operator", post(operator))
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

    fn internal(error: &'static str, details: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error, details)
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

/// Counts only: which agents a TD hosts, and whose they are, is for their
/// owners to ask about, one agent id at a time.
async fn health(State(gate): State<Arc<Gate>>) -> Json<serde_json::Value> {
    let slots = gate.slots.lock().await;
    let claimed = slots.iter().filter(|s| s.claim.is_some()).count();
    Json(json!({
        "status": "ok",
        "slots": slots.len(),
        "claimed": claimed,
        "free": slots.len() - claimed,
        "provisioned": slots.iter().filter(|s| s.provisioned).count(),
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
    let agent_id = request.agent_id.unwrap_or_default();
    if !agent_id.is_empty() {
        validate_agent_id(&agent_id).map_err(GateError::bad_request)?;
    }
    let claim = if agent_id.is_empty() {
        None
    } else {
        gate.slots
            .lock()
            .await
            .iter()
            .find_map(|s| s.claim.clone().filter(|c| c.agent_id == agent_id))
    };
    let signing = claim.as_ref().map(|c| c.signing_public);
    let owner = claim.as_ref().map(|c| c.owner);
    let binding = key_binding(
        &gate.provisioning.public,
        &agent_id,
        signing.as_ref(),
        owner.as_ref(),
    );
    let data = report_data(&nonce, &binding);
    let quoter = Arc::clone(&gate.quoter);
    let quote = tokio::task::spawn_blocking(move || quoter.quote(data))
        .await
        .map_err(|e| GateError::internal("quote_failed", e.to_string()))?
        .map_err(|e| GateError::internal("quote_failed", e))?;
    Ok(Json(AttestResponse {
        quote_b64: BASE64.encode(quote),
        report_data_hex: hex::encode(data),
        provisioning_public_key_b64: BASE64.encode(gate.provisioning.public),
        agent_id: (!agent_id.is_empty()).then_some(agent_id),
        signing_public_key_b64: signing.map(|key| BASE64.encode(key)),
        owner_public_key_b64: owner.map(|key| BASE64.encode(key)),
    }))
}

/// A sealed request, decoded: for which agent, from whom, and its HPKE parts.
struct Sealed {
    agent_id: String,
    sender: [u8; 32],
    encapped: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn decode_sealed(gate: &Gate, request: ProvisionRequest) -> Result<Sealed, GateError> {
    validate_agent_id(&request.agent_id).map_err(GateError::bad_request)?;
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
    Ok(Sealed {
        agent_id: request.agent_id,
        sender,
        encapped,
        ciphertext,
    })
}

fn open<T: serde::de::DeserializeOwned>(gate: &Gate, sealed: &Sealed) -> Result<T, GateError> {
    open_message(
        &gate.provisioning.private,
        &gate.provisioning.public,
        &sealed.agent_id,
        &sealed.sender,
        &sealed.encapped,
        &sealed.ciphertext,
    )
    .map_err(|e| open_error(sealed, e))
}

fn open_error(sealed: &Sealed, e: OpenError) -> GateError {
    match e {
        OpenError::NotFromSender => {
            warn!(agent = %sealed.agent_id, "Refused a message not sealed by the key it names");
            GateError::new(StatusCode::FORBIDDEN, "not_from_sender", e.to_string())
        }
        OpenError::Malformed(_) => GateError::bad_request(e.to_string()),
    }
}

fn not_the_owner(agent_id: &str) -> GateError {
    warn!(agent = %agent_id, "Refused a message from a key that does not own this agent");
    GateError::new(
        StatusCode::FORBIDDEN,
        "not_the_owner",
        "this agent is claimed by another key",
    )
}

async fn provision(
    State(gate): State<Arc<Gate>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, GateError> {
    let sealed = decode_sealed(&gate, request)?;

    // Held to the end: a claim and the secrets it brings are one step, and a
    // second first bundle waits, then finds the agent claimed.
    let mut slots = gate.slots.lock().await;
    let held = slots.iter().position(|s| {
        s.claim
            .as_ref()
            .is_some_and(|c| c.agent_id == sealed.agent_id)
    });
    let index = match held {
        Some(index) => {
            if slots[index].claim.as_ref().map(|c| c.owner) != Some(sealed.sender) {
                return Err(not_the_owner(&sealed.agent_id));
            }
            index
        }
        None => slots
            .iter()
            .position(|s| s.claim.is_none())
            .ok_or_else(|| {
                GateError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no_free_slot",
                    "every slot on this agent TD is taken; place the agent on another",
                )
            })?,
    };
    let bundle: SecretsBundle = open(&gate, &sealed)?;
    bundle.validate().map_err(GateError::bad_request)?;

    // The claim is durable before any secret is written: an owner told it
    // claimed the agent has, even if the gate dies next.
    let slot = &mut slots[index];
    let claimed = held.is_none();
    if claimed {
        slot.claim(&sealed.agent_id, &sealed.sender)
            .map_err(|e| GateError::internal("write_failed", format!("{e:#}")))?;
        info!(
            agent = %sealed.agent_id,
            slot = slot.number,
            owner = %BASE64.encode(sealed.sender),
            "Agent claimed"
        );
    }

    let written = write_secrets(&slot.secrets_dir(), slot.share, &bundle)
        .map_err(|e| GateError::internal("write_failed", e))?;
    slot.provisioned = true;
    info!(agent = %sealed.agent_id, slot = slot.number, secrets = ?written, "Provisioned secrets");
    Ok(Json(ProvisionResponse { written, claimed }))
}

async fn release(
    State(gate): State<Arc<Gate>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ReleaseResponse>, GateError> {
    let sealed = decode_sealed(&gate, request)?;
    let mut slots = gate.slots.lock().await;
    let index = slots
        .iter()
        .position(|s| {
            s.claim
                .as_ref()
                .is_some_and(|c| c.agent_id == sealed.agent_id)
        })
        .ok_or_else(|| {
            GateError::new(
                StatusCode::NOT_FOUND,
                "unknown_agent",
                "no agent with this id on this TD",
            )
        })?;
    if slots[index].claim.as_ref().map(|c| c.owner) != Some(sealed.sender) {
        return Err(not_the_owner(&sealed.agent_id));
    }
    let order: ReleaseOrder = open(&gate, &sealed)?;
    if !order.release {
        return Err(GateError::bad_request(
            "the message does not ask for a release",
        ));
    }

    let number = slots[index].number;
    // Stopped first: nothing of the agent's runs while its files go.
    unit(&gate, number, false)
        .await
        .map_err(|e| GateError::internal("stop_failed", e))?;
    slots[index]
        .release()
        .map_err(|e| GateError::internal("erase_failed", format!("{e:#}")))?;
    info!(agent = %sealed.agent_id, slot = number, "Agent released; its slot is erased");
    // Started again empty: it waits for the slot's next owner.
    if let Err(e) = unit(&gate, number, true).await {
        warn!(slot = number, "Could not start the freed slot's agent: {e}");
    }
    Ok(Json(ReleaseResponse {
        released: sealed.agent_id,
    }))
}

/// The operator's secrets for a claimed agent: only names in
/// [`crate::protocol::OPERATOR_SECRETS`], only into the slot's `operator/`, and
/// only from the operator key. Claiming, releasing and the owner's own secrets
/// stay the owner's alone; an agent that is not claimed is refused, so the
/// operator never chooses who holds a slot.
async fn operator(
    State(gate): State<Arc<Gate>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, GateError> {
    let sealed = decode_sealed(&gate, request)?;
    if gate.operator != Some(sealed.sender) {
        warn!(agent = %sealed.agent_id, "Refused operator secrets from a key that is not the operator's");
        return Err(GateError::new(
            StatusCode::FORBIDDEN,
            "not_the_operator",
            if gate.operator.is_none() {
                "this TD was started with no operator key"
            } else {
                "sealed under a key that is not this TD's operator key"
            },
        ));
    }
    let mut slots = gate.slots.lock().await;
    let slot = slots
        .iter_mut()
        .find(|s| {
            s.claim
                .as_ref()
                .is_some_and(|c| c.agent_id == sealed.agent_id)
        })
        .ok_or_else(|| {
            GateError::new(
                StatusCode::NOT_FOUND,
                "unknown_agent",
                "no claimed agent with this id on this TD; its owner claims it first",
            )
        })?;
    let bundle = open_operator_message(
        &gate.provisioning.private,
        &gate.provisioning.public,
        &sealed.agent_id,
        &sealed.sender,
        &sealed.encapped,
        &sealed.ciphertext,
    )
    .map_err(|e| open_error(&sealed, e))?;
    bundle.validate_operator().map_err(GateError::bad_request)?;
    let written = write_secrets(&slot.operator_dir(), slot.share, &bundle)
        .map_err(|e| GateError::internal("write_failed", e))?;
    info!(agent = %sealed.agent_id, slot = slot.number, secrets = ?written, "Wrote operator secrets");
    Ok(Json(ProvisionResponse {
        written,
        claimed: false,
    }))
}

/// Stop or start slot `number`'s agent, off the async workers: a stop waits
/// for the agent to exit.
async fn unit(gate: &Gate, number: u32, start: bool) -> Result<(), String> {
    let units = Arc::clone(&gate.units);
    tokio::task::spawn_blocking(move || {
        if start {
            units.start(number)
        } else {
            units.stop(number)
        }
    })
    .await
    .map_err(|e| e.to_string())?
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
    use std::sync::Mutex as StdMutex;

    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    use super::*;
    use crate::protocol::{keypair_from_secret, seal_message};
    use crate::slots::open_slots;
    use crate::test_util::TempDir;

    /// A quote that is just the report data, so tests can read it back.
    struct EchoQuoter;
    impl Quoter for EchoQuoter {
        fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
            Ok(report_data.to_vec())
        }
    }

    /// Records what the gate asked of systemd.
    #[derive(Default)]
    struct RecordedUnits(StdMutex<Vec<String>>);
    impl Units for RecordedUnits {
        fn stop(&self, slot: u32) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("stop {slot}"));
            Ok(())
        }
        fn start(&self, slot: u32) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("start {slot}"));
            Ok(())
        }
    }

    const OWNER_SECRET: [u8; 32] = [0x22; 32];
    const OTHER_SECRET: [u8; 32] = [0x33; 32];

    fn public(secret: &[u8; 32]) -> [u8; 32] {
        keypair_from_secret(secret).unwrap().1
    }

    /// A gate with `count` slots over `dir`, picking up claims an earlier start
    /// recorded there.
    fn gate_with(dir: &TempDir, count: u32, units: Arc<dyn Units>) -> Arc<Gate> {
        Arc::new(Gate::new(
            Arc::new(EchoQuoter),
            ProvisioningKey::generate(),
            open_slots(&dir.path().join("agents"), count, "").unwrap(),
            units,
        ))
    }

    fn gate(dir: &TempDir) -> Arc<Gate> {
        gate_with(dir, 2, Arc::new(NoUnits))
    }

    fn slot_dir(dir: &TempDir, slot: u32) -> std::path::PathBuf {
        dir.path().join("agents").join(slot.to_string())
    }

    async fn call(
        gate: &Arc<Gate>,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let response = router(Arc::clone(gate)).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn post(
        gate: &Arc<Gate>,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        call(gate, "POST", uri, Some(body)).await
    }

    /// A message for `agent` sealed by `sealed_by`, naming `named` as its sender.
    fn sealed<T: serde::Serialize>(
        gate: &Gate,
        agent: &str,
        sealed_by: &[u8; 32],
        named: &[u8; 32],
        message: &T,
    ) -> serde_json::Value {
        let (enc, ct) = seal_message(&gate.provisioning.public, agent, sealed_by, message).unwrap();
        json!({
            "agentId": agent,
            "provisioningPublicKeyB64": BASE64.encode(gate.provisioning.public),
            "senderPublicKeyB64": BASE64.encode(public(named)),
            "encappedKeyB64": BASE64.encode(enc),
            "ciphertextB64": BASE64.encode(ct),
        })
    }

    fn bundle(pairs: &[(&str, &str)]) -> SecretsBundle {
        SecretsBundle {
            secrets: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn request(
        gate: &Gate,
        agent: &str,
        sender: &[u8; 32],
        pairs: &[(&str, &str)],
    ) -> serde_json::Value {
        sealed(gate, agent, sender, sender, &bundle(pairs))
    }

    fn release_request(gate: &Gate, agent: &str, sender: &[u8; 32]) -> serde_json::Value {
        sealed(gate, agent, sender, sender, &ReleaseOrder { release: true })
    }

    async fn attest(gate: &Arc<Gate>, agent: Option<&str>) -> serde_json::Value {
        let mut body = json!({ "nonceB64": BASE64.encode([7u8; 32]) });
        if let Some(agent) = agent {
            body["agentId"] = json!(agent);
        }
        let (status, body) = post(gate, "/attest", body).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    fn quoted(body: &serde_json::Value) -> Vec<u8> {
        BASE64.decode(body["quoteB64"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_quote_without_an_agent_measures_the_td_alone() {
        let dir = TempDir::new("attest-td");
        let gate = gate(&dir);
        let body = attest(&gate, None).await;
        let expected = report_data(
            &[7; 32],
            &key_binding(&gate.provisioning.public, "", None, None),
        );
        assert_eq!(quoted(&body), expected);
        assert!(body.get("agentId").is_none());
        assert!(body.get("signingPublicKeyB64").is_none());
    }

    #[tokio::test]
    async fn an_unclaimed_agent_quote_binds_its_id_and_no_keys() {
        let dir = TempDir::new("attest-unclaimed");
        let gate = gate(&dir);
        let body = attest(&gate, Some("ana")).await;
        let expected = report_data(
            &[7; 32],
            &key_binding(&gate.provisioning.public, "ana", None, None),
        );
        assert_eq!(quoted(&body), expected);
        assert_eq!(body["agentId"], "ana");
        assert!(body.get("ownerPublicKeyB64").is_none());
    }

    #[tokio::test]
    async fn bad_nonces_and_agent_ids_are_refused() {
        let dir = TempDir::new("attest-bad");
        let gate = gate(&dir);
        let (status, _) = post(
            &gate,
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 16]) }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post(
            &gate,
            "/attest",
            json!({ "nonceB64": BASE64.encode([7u8; 32]), "agentId": "../x" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_first_bundle_claims_a_slot_and_the_agent_quote_says_so() {
        let dir = TempDir::new("claim");
        let gate = gate(&dir);
        let (status, body) = post(
            &gate,
            "/provision",
            request(
                &gate,
                "ana",
                &OWNER_SECRET,
                &[("API_KEY", "s3cret"), ("MODEL", "m")],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["written"], json!(["API_KEY", "MODEL"]));
        assert_eq!(body["claimed"], true);
        let path = slot_dir(&dir, 1).join("secrets/API_KEY");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "s3cret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("id")).unwrap(),
            "ana"
        );

        let owner = public(&OWNER_SECRET);
        let body = attest(&gate, Some("ana")).await;
        assert_eq!(body["ownerPublicKeyB64"], BASE64.encode(owner));
        let signing = gate.slots.lock().await[0]
            .claim
            .clone()
            .unwrap()
            .signing_public;
        assert_eq!(body["signingPublicKeyB64"], BASE64.encode(signing));
        assert_eq!(
            quoted(&body),
            report_data(
                &[7; 32],
                &key_binding(
                    &gate.provisioning.public,
                    "ana",
                    Some(&signing),
                    Some(&owner)
                )
            )
        );
    }

    #[tokio::test]
    async fn two_owners_hold_two_slots_with_their_own_keys_and_secrets() {
        let dir = TempDir::new("two-owners");
        let gate = gate(&dir);
        let (status, _) = post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("API_KEY", "ana-key")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, "bob", &OTHER_SECRET, &[("API_KEY", "bob-key")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["claimed"], true);
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("secrets/API_KEY")).unwrap(),
            "ana-key"
        );
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 2).join("secrets/API_KEY")).unwrap(),
            "bob-key"
        );
        let ana = attest(&gate, Some("ana")).await;
        let bob = attest(&gate, Some("bob")).await;
        assert_eq!(
            ana["ownerPublicKeyB64"],
            BASE64.encode(public(&OWNER_SECRET))
        );
        assert_eq!(
            bob["ownerPublicKeyB64"],
            BASE64.encode(public(&OTHER_SECRET))
        );
        assert_ne!(ana["signingPublicKeyB64"], bob["signingPublicKeyB64"]);

        // Neither provisions the other's agent.
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, "ana", &OTHER_SECRET, &[("API_KEY", "evil")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_the_owner");
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("secrets/API_KEY")).unwrap(),
            "ana-key"
        );
    }

    #[tokio::test]
    async fn a_full_td_takes_no_new_agent_but_its_owners_still_provision() {
        let dir = TempDir::new("full");
        let gate = gate_with(&dir, 1, Arc::new(NoUnits));
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, "bob", &OTHER_SECRET, &[("A", "1")]),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "no_free_slot");
        let (status, _) = post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "2")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_bundle_for_one_agent_cannot_be_replayed_to_another() {
        let dir = TempDir::new("replay-agent");
        let gate = gate(&dir);
        let mut replayed = request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]);
        replayed["agentId"] = json!("bob");
        let (status, body) = post(&gate, "/provision", replayed).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_from_sender");
        assert!(gate.slots.lock().await.iter().all(|s| s.claim.is_none()));
    }

    #[tokio::test]
    async fn the_owner_provisions_again_without_claiming_again() {
        let dir = TempDir::new("claim-again");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "2")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["claimed"], false);
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("secrets/A")).unwrap(),
            "2"
        );
        assert!(
            gate.slots.lock().await[1].claim.is_none(),
            "one agent, one slot"
        );
    }

    #[tokio::test]
    async fn naming_the_owner_without_its_key_is_refused() {
        let dir = TempDir::new("claim-impersonate");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("API_KEY", "mine")]),
        )
        .await;
        let forged = sealed(
            &gate,
            "ana",
            &OTHER_SECRET,
            &OWNER_SECRET,
            &bundle(&[("API_KEY", "evil")]),
        );
        let (status, body) = post(&gate, "/provision", forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_from_sender");
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("secrets/API_KEY")).unwrap(),
            "mine"
        );
    }

    #[tokio::test]
    async fn a_forged_first_bundle_claims_nothing() {
        let dir = TempDir::new("claim-forged");
        let gate = gate(&dir);
        let forged = sealed(
            &gate,
            "ana",
            &OTHER_SECRET,
            &OWNER_SECRET,
            &bundle(&[("A", "b")]),
        );
        let (status, _) = post(&gate, "/provision", forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!slot_dir(&dir, 1).join("id").exists());
        assert!(gate.slots.lock().await.iter().all(|s| s.claim.is_none()));
    }

    #[tokio::test]
    async fn a_claim_survives_a_restart() {
        let dir = TempDir::new("claim-restart");
        let before = gate(&dir);
        post(
            &before,
            "/provision",
            request(&before, "ana", &OWNER_SECRET, &[("A", "b")]),
        )
        .await;
        let signing_before = attest(&before, Some("ana")).await["signingPublicKeyB64"].clone();
        let after = gate(&dir);
        let body = attest(&after, Some("ana")).await;
        assert_eq!(
            body["ownerPublicKeyB64"],
            BASE64.encode(public(&OWNER_SECRET))
        );
        assert_eq!(body["signingPublicKeyB64"], signing_before);
        let (status, _) = post(
            &after,
            "/provision",
            request(&after, "ana", &OTHER_SECRET, &[("A", "c")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_message_for_an_earlier_start_is_stale() {
        let dir = TempDir::new("provision-stale");
        let before_restart = gate(&dir);
        let request = request(&before_restart, "ana", &OWNER_SECRET, &[("A", "b")]);
        let after_restart = gate(&dir);
        let (status, body) = post(&after_restart, "/provision", request).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "stale_provisioning_key");
    }

    #[tokio::test]
    async fn a_bad_name_writes_nothing_and_claims_nothing() {
        let dir = TempDir::new("provision-name");
        let gate = gate(&dir);
        let request = request(
            &gate,
            "ana",
            &OWNER_SECRET,
            &[("GOOD", "x"), ("../escape", "y")],
        );
        let (status, _) = post(&gate, "/provision", request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !slot_dir(&dir, 1).join("secrets/GOOD").exists(),
            "validated before any write"
        );
        assert!(
            gate.slots.lock().await.iter().all(|s| s.claim.is_none()),
            "a refused bundle claims nothing"
        );
    }

    #[tokio::test]
    async fn the_owner_releases_its_agent_and_the_slot_is_erased_for_the_next() {
        let dir = TempDir::new("release");
        let units = Arc::new(RecordedUnits::default());
        let gate = gate_with(&dir, 1, units.clone());
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("API_KEY", "ana-key")]),
        )
        .await;
        std::fs::write(slot_dir(&dir, 1).join("state/memory"), "ana's notes").unwrap();

        // Nobody else releases it.
        let (status, body) = post(
            &gate,
            "/release",
            release_request(&gate, "ana", &OTHER_SECRET),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_the_owner");
        assert!(units.0.lock().unwrap().is_empty());

        let (status, body) = post(
            &gate,
            "/release",
            release_request(&gate, "ana", &OWNER_SECRET),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["released"], "ana");
        assert_eq!(*units.0.lock().unwrap(), vec!["stop 1", "start 1"]);
        for sub in ["keys", "secrets", "state"] {
            assert_eq!(
                std::fs::read_dir(slot_dir(&dir, 1).join(sub))
                    .unwrap()
                    .count(),
                0,
                "{sub} left behind"
            );
        }
        let body = attest(&gate, Some("ana")).await;
        assert!(body.get("ownerPublicKeyB64").is_none());

        // The slot takes the next owner, who gets a signing key of its own.
        let (status, body) = post(
            &gate,
            "/provision",
            request(&gate, "bob", &OTHER_SECRET, &[("API_KEY", "bob-key")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read_to_string(slot_dir(&dir, 1).join("secrets/API_KEY")).unwrap(),
            "bob-key"
        );
    }

    #[tokio::test]
    async fn a_release_needs_a_known_agent_and_a_release_order() {
        let dir = TempDir::new("release-bad");
        let gate = gate(&dir);
        let (status, body) = post(
            &gate,
            "/release",
            release_request(&gate, "ana", &OWNER_SECRET),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown_agent");

        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let no = sealed(
            &gate,
            "ana",
            &OWNER_SECRET,
            &OWNER_SECRET,
            &ReleaseOrder { release: false },
        );
        let (status, _) = post(&gate, "/release", no).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // A secrets bundle is not a release order.
        let (status, _) = post(
            &gate,
            "/release",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(gate.slots.lock().await[0].claim.is_some());
    }

    const OPERATOR_SECRET: [u8; 32] = [0x44; 32];

    /// A gate whose operator is [`OPERATOR_SECRET`]'s key.
    fn gate_with_operator(dir: &TempDir) -> Arc<Gate> {
        Arc::new(
            Gate::new(
                Arc::new(EchoQuoter),
                ProvisioningKey::generate(),
                open_slots(&dir.path().join("agents"), 2, "").unwrap(),
                Arc::new(NoUnits),
            )
            .with_operator(Some(public(&OPERATOR_SECRET))),
        )
    }

    fn operator_request(
        gate: &Gate,
        agent: &str,
        sender: &[u8; 32],
        pairs: &[(&str, &str)],
    ) -> serde_json::Value {
        let (enc, ct) = crate::protocol::seal_operator_message(
            &gate.provisioning.public,
            agent,
            sender,
            &bundle(pairs),
        )
        .unwrap();
        json!({
            "agentId": agent,
            "provisioningPublicKeyB64": BASE64.encode(gate.provisioning.public),
            "senderPublicKeyB64": BASE64.encode(public(sender)),
            "encappedKeyB64": BASE64.encode(enc),
            "ciphertextB64": BASE64.encode(ct),
        })
    }

    #[tokio::test]
    async fn the_operator_writes_the_near_key_beside_the_owner_s_secrets() {
        let dir = TempDir::new("operator-writes");
        let gate = gate_with_operator(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("MERO_AGENTS_JSON", "{}")]),
        )
        .await;
        let (status, body) = post(
            &gate,
            "/operator",
            operator_request(
                &gate,
                "ana",
                &OPERATOR_SECRET,
                &[("NEAR_AI_API_KEY", "ours")],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["written"], json!(["NEAR_AI_API_KEY"]));
        let slot = slot_dir(&dir, 1);
        assert_eq!(
            std::fs::read_to_string(slot.join("operator/NEAR_AI_API_KEY")).unwrap(),
            "ours"
        );
        // Apart from the owner's: neither overwrites the other.
        assert!(!slot.join("secrets/NEAR_AI_API_KEY").exists());
        assert_eq!(
            std::fs::read_to_string(slot.join("secrets/MERO_AGENTS_JSON")).unwrap(),
            "{}"
        );
        // The owner is unchanged.
        assert_eq!(
            gate.slots.lock().await[0].claim.as_ref().unwrap().owner,
            public(&OWNER_SECRET)
        );
    }

    #[tokio::test]
    async fn only_the_operator_key_writes_operator_secrets() {
        let dir = TempDir::new("operator-only");
        let gate = gate_with_operator(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        // Not the owner, and not anyone else.
        for key in [OWNER_SECRET, OTHER_SECRET] {
            let (status, body) = post(
                &gate,
                "/operator",
                operator_request(&gate, "ana", &key, &[("NEAR_AI_API_KEY", "x")]),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert_eq!(body["error"], "not_the_operator");
        }
        // Naming the operator's key without holding it does not open.
        let (enc, ct) = crate::protocol::seal_operator_message(
            &gate.provisioning.public,
            "ana",
            &OTHER_SECRET,
            &bundle(&[("NEAR_AI_API_KEY", "x")]),
        )
        .unwrap();
        let forged = json!({
            "agentId": "ana",
            "provisioningPublicKeyB64": BASE64.encode(gate.provisioning.public),
            "senderPublicKeyB64": BASE64.encode(public(&OPERATOR_SECRET)),
            "encappedKeyB64": BASE64.encode(enc),
            "ciphertextB64": BASE64.encode(ct),
        });
        let (status, body) = post(&gate, "/operator", forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "not_from_sender");
        assert!(!slot_dir(&dir, 1).join("operator/NEAR_AI_API_KEY").exists());
    }

    #[tokio::test]
    async fn the_operator_cannot_claim_write_other_names_or_act_without_a_key() {
        let dir = TempDir::new("operator-limits");
        let gate = gate_with_operator(&dir);
        // An unclaimed agent: the operator never chooses who holds a slot.
        let (status, body) = post(
            &gate,
            "/operator",
            operator_request(&gate, "ana", &OPERATOR_SECRET, &[("NEAR_AI_API_KEY", "x")]),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(gate.slots.lock().await.iter().all(|s| s.claim.is_none()));

        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, _) = post(
            &gate,
            "/operator",
            operator_request(
                &gate,
                "ana",
                &OPERATOR_SECRET,
                &[("CALIMERO_NODE_URL", "https://elsewhere")],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!slot_dir(&dir, 1)
            .join("operator/CALIMERO_NODE_URL")
            .exists());

        // A TD started with no operator key refuses everything.
        let dir = TempDir::new("operator-none");
        let plain = super::tests::gate(&dir);
        post(
            &plain,
            "/provision",
            request(&plain, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, body) = post(
            &plain,
            "/operator",
            operator_request(&plain, "ana", &OPERATOR_SECRET, &[("NEAR_AI_API_KEY", "x")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn a_release_erases_the_operator_s_secrets_too() {
        let dir = TempDir::new("operator-release");
        let gate = gate_with_operator(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        post(
            &gate,
            "/operator",
            operator_request(&gate, "ana", &OPERATOR_SECRET, &[("NEAR_AI_API_KEY", "x")]),
        )
        .await;
        let (status, _) = post(
            &gate,
            "/release",
            release_request(&gate, "ana", &OWNER_SECRET),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!slot_dir(&dir, 1).join("operator/NEAR_AI_API_KEY").exists());
    }

    #[tokio::test]
    async fn health_counts_slots_and_names_no_agent() {
        let dir = TempDir::new("health");
        let gate = gate(&dir);
        post(
            &gate,
            "/provision",
            request(&gate, "ana", &OWNER_SECRET, &[("A", "1")]),
        )
        .await;
        let (status, body) = call(&gate, "GET", "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "status": "ok", "slots": 2, "claimed": 1, "free": 1, "provisioned": 1 })
        );
        assert!(!body.to_string().contains("ana"));
    }
}
