//! The gate's HTTP layer: `/health`, `/attest`, and `/v1/*` passed to vLLM.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::json;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::attest::{binding, parse_nonce, report_data, sha256, AttestRequest, AttestResponse};
use crate::gpu::GpuEvidence;
use crate::tokens::Tokens;

/// A chat request is JSON: prompts, tools and images inline. Far more than
/// any context window a single H100 serves.
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// At most this many `/attest` at once: each asks the GPU to sign a report.
const ATTEST_CONCURRENCY: usize = 4;

/// Request headers never passed to vLLM: hop-by-hop ones, and the caller's
/// token, which is the gate's to check and vLLM's not to see.
const DROPPED_REQUEST_HEADERS: &[HeaderName] = &[
    header::HOST,
    header::AUTHORIZATION,
    header::CONNECTION,
    header::CONTENT_LENGTH,
    header::TRANSFER_ENCODING,
    header::TE,
    header::UPGRADE,
    header::PROXY_AUTHORIZATION,
];

/// Response headers never passed back: hop-by-hop ones, which the gate's own
/// connection sets.
const DROPPED_RESPONSE_HEADERS: &[HeaderName] = &[
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::CONTENT_LENGTH,
    header::UPGRADE,
];

/// Where quotes come from. A trait so the HTTP layer is tested without a TD.
pub trait Quoter: Send + Sync + 'static {
    /// Raw quote bytes over `report_data`.
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String>;
}

/// Quotes from this TD, through configfs-tsm (core's `generate_attestation`,
/// the same code mero-kms, merod and mero-agent-gate quote with).
pub struct TdxQuoter;

impl Quoter for TdxQuoter {
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        calimero_tee_attestation::generate_attestation(report_data)
            .map(|result| result.quote_bytes)
            .map_err(|e| e.to_string())
    }
}

/// Mock quotes, for development without a TD. Only in the default-off
/// `mock-attestation` build.
#[cfg(feature = "mock-attestation")]
pub struct MockQuoter;

#[cfg(feature = "mock-attestation")]
impl Quoter for MockQuoter {
    fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        Ok(calimero_tee_attestation::generate_mock_attestation(report_data).quote_bytes)
    }
}

pub struct Gate {
    pub quoter: Box<dyn Quoter>,
    pub gpu: GpuEvidence,
    pub spki_sha256: [u8; 32],
    /// The configuration inference-init loaded and measured, exactly as
    /// written; empty on the measurement VM, which loads no model and so
    /// serves `/attest` only.
    pub config_json: String,
    /// `servedModelName` from the configuration, for `/health`.
    pub served_model: Option<String>,
    pub tokens: Tokens,
    /// vLLM's base URL, on loopback.
    pub upstream: String,
    pub client: reqwest::Client,
    attest_slots: Semaphore,
}

impl Gate {
    pub fn new(
        quoter: Box<dyn Quoter>,
        gpu: GpuEvidence,
        spki_sha256: [u8; 32],
        config_json: String,
        tokens: Tokens,
        upstream: String,
    ) -> Result<Self, String> {
        let served_model = if config_json.is_empty() {
            None
        } else {
            let config: serde_json::Value = serde_json::from_str(&config_json)
                .map_err(|e| format!("config.json is not JSON: {e}"))?;
            Some(
                config
                    .get("servedModelName")
                    .and_then(|n| n.as_str())
                    .ok_or("config.json names no servedModelName")?
                    .to_owned(),
            )
        };
        // No timeout on the whole request: a streamed answer may take minutes.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            quoter,
            gpu,
            spki_sha256,
            config_json,
            served_model,
            tokens,
            upstream: upstream.trim_end_matches('/').to_owned(),
            client,
            attest_slots: Semaphore::new(ATTEST_CONCURRENCY),
        })
    }

    pub fn config_digest(&self) -> [u8; 32] {
        sha256(self.config_json.as_bytes())
    }
}

pub fn router(gate: Arc<Gate>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .fallback(proxy)
        .with_state(gate)
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": code, "message": message.into() })),
    )
        .into_response()
}

async fn health(State(gate): State<Arc<Gate>>) -> Response {
    let Some(model) = gate.served_model.as_deref() else {
        return Json(json!({ "status": "ok", "model": null, "measureOnly": true })).into_response();
    };
    let ready = gate
        .client
        .get(format!("{}/health", gate.upstream))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    Json(json!({ "status": if ready { "ok" } else { "starting" }, "model": model })).into_response()
}

async fn attest(State(gate): State<Arc<Gate>>, Json(request): Json<AttestRequest>) -> Response {
    let nonce = match parse_nonce(&request.nonce_hex) {
        Ok(nonce) => nonce,
        Err(message) => return error(StatusCode::BAD_REQUEST, "bad_nonce", message),
    };
    let Ok(_slot) = gate.attest_slots.acquire().await else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "closing",
            "the gate is shutting down",
        );
    };
    let nonce_hex = hex::encode(nonce);
    let gpu_json = match gate.gpu.collect(&nonce_hex).await {
        Ok(gpu_json) => gpu_json,
        // The measurement VM loads no model and readies no GPU: its quote is
        // for the image alone, and no client takes one without evidence.
        Err(message) if gate.served_model.is_none() => {
            warn!(%message, "GPU evidence, on the measurement VM: answering without it");
            None
        }
        Err(message) => {
            warn!(%message, "GPU evidence");
            return error(StatusCode::SERVICE_UNAVAILABLE, "gpu_evidence", message);
        }
    };
    let config_digest = gate.config_digest();
    let data = report_data(
        &nonce,
        &binding(&gate.spki_sha256, &config_digest, gpu_json.as_deref()),
    );
    let quoting = Arc::clone(&gate);
    let quote = match tokio::task::spawn_blocking(move || quoting.quoter.quote(data)).await {
        Ok(Ok(quote)) => quote,
        Ok(Err(message)) => return error(StatusCode::SERVICE_UNAVAILABLE, "quote", message),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, "quote", e.to_string()),
    };
    Json(AttestResponse {
        quote_b64: BASE64.encode(quote),
        report_data_hex: hex::encode(data),
        tls_spki_sha256: hex::encode(gate.spki_sha256),
        config_json: gate.config_json.clone(),
        config_digest: hex::encode(config_digest),
        gpu_json,
    })
    .into_response()
}

fn copy_headers(from: &HeaderMap, to: &mut HeaderMap, dropped: &[HeaderName]) {
    for (name, value) in from {
        if !dropped.contains(name) {
            to.append(name.clone(), value.clone());
        }
    }
}

/// `/v1/*` to vLLM, answers streamed back as they come.
async fn proxy(State(gate): State<Arc<Gate>>, request: Request) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/v1/") || gate.served_model.is_none() {
        return error(StatusCode::NOT_FOUND, "not_found", "no such route");
    }
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !gate.tokens.allows(authorization) {
        let mut response = error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid access token is required",
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
        return response;
    }
    let target = format!(
        "{}{}",
        gate.upstream,
        request
            .uri()
            .path_and_query()
            .map_or(path, |pq| pq.as_str())
    );
    let method = request.method().clone();
    let mut headers = HeaderMap::new();
    copy_headers(request.headers(), &mut headers, DROPPED_REQUEST_HEADERS);
    let body = match to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "the request is too large",
            )
        }
    };
    let upstream = match gate
        .client
        .request(method, &target)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(upstream) => upstream,
        Err(e) => {
            info!(error = %e, "vLLM unreachable");
            return error(
                StatusCode::BAD_GATEWAY,
                "upstream",
                "the model server is not answering yet",
            );
        }
    };
    let mut response = Response::builder().status(upstream.status());
    if let Some(headers) = response.headers_mut() {
        copy_headers(upstream.headers(), headers, DROPPED_RESPONSE_HEADERS);
    }
    response
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|e| error(StatusCode::INTERNAL_SERVER_ERROR, "response", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    /// "Quotes" that are the report data itself.
    struct EchoQuoter;
    impl Quoter for EchoQuoter {
        fn quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
            Ok(report_data.to_vec())
        }
    }

    const CONFIG: &str = r#"{"engine":{},"repo":"o/m","revision":"0000000000000000000000000000000000000000","schema":1,"servedModelName":"m","weightsSha256":"00"}"#;
    const GPU: &str = r#"{"nonce":"{nonce}","arch":"HOPPER","evidence_list":[{"certificate":"c","evidence":"e"}]}"#;

    fn gate(config: &str, upstream: &str) -> Arc<Gate> {
        let tokens = Tokens::parse(&hex::encode(sha256(b"secret"))).unwrap();
        Arc::new(
            Gate::new(
                Box::new(EchoQuoter),
                GpuEvidence::Template(GPU.into()),
                [5; 32],
                config.into(),
                tokens,
                upstream.into(),
            )
            .unwrap(),
        )
    }

    async fn call(gate: Arc<Gate>, request: HttpRequest<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = router(gate).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        (
            status,
            headers,
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
    }

    fn attest_request(nonce: &str) -> HttpRequest<Body> {
        HttpRequest::post("/attest")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "nonceHex": nonce }).to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn attest_binds_the_key_the_config_and_the_gpu() {
        let gate = gate(CONFIG, "http://127.0.0.1:9");
        let nonce = "11".repeat(32);
        let (status, _, body) = call(Arc::clone(&gate), attest_request(&nonce)).await;
        assert_eq!(status, StatusCode::OK);
        let answer: AttestResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(answer.config_json, CONFIG);
        assert_eq!(answer.config_digest, hex::encode(sha256(CONFIG.as_bytes())));
        assert_eq!(answer.tls_spki_sha256, hex::encode([5; 32]));
        let gpu = answer.gpu_json.unwrap();
        assert!(gpu.contains(&nonce));
        let expected = report_data(
            &[0x11; 32],
            &binding(&[5; 32], &sha256(CONFIG.as_bytes()), Some(&gpu)),
        );
        assert_eq!(BASE64.decode(answer.quote_b64).unwrap(), expected.to_vec());
        assert_eq!(answer.report_data_hex, hex::encode(expected));
    }

    #[tokio::test]
    async fn without_gpu_evidence_only_the_measurement_vm_answers() {
        let tokens = Tokens::default();
        let broken = |config: &str| {
            Arc::new(
                Gate::new(
                    Box::new(EchoQuoter),
                    GpuEvidence::Helper("/nonexistent".into()),
                    [5; 32],
                    config.into(),
                    tokens.clone(),
                    "http://127.0.0.1:9".into(),
                )
                .unwrap(),
            )
        };
        let (status, _, _) = call(broken(CONFIG), attest_request(&"33".repeat(32))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _, body) = call(broken(""), attest_request(&"33".repeat(32))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<AttestResponse>(&body)
                .unwrap()
                .gpu_json,
            None
        );
    }

    #[tokio::test]
    async fn attest_refuses_a_bad_nonce() {
        let (status, _, _) = call(gate(CONFIG, "http://127.0.0.1:9"), attest_request("abcd")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_measurement_vm_attests_and_serves_nothing_else() {
        let gate = gate("", "http://127.0.0.1:9");
        let (status, _, body) = call(Arc::clone(&gate), attest_request(&"22".repeat(32))).await;
        assert_eq!(status, StatusCode::OK);
        let answer: AttestResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(answer.config_json, "");
        let (_, _, body) = call(
            Arc::clone(&gate),
            HttpRequest::get("/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["measureOnly"],
            true
        );
        let request = HttpRequest::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(gate, request).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn v1_needs_a_token() {
        let gate = gate(CONFIG, "http://127.0.0.1:9");
        for authorization in [None, Some("Bearer wrong"), Some("secret")] {
            let mut request = HttpRequest::post("/v1/chat/completions");
            if let Some(value) = authorization {
                request = request.header(header::AUTHORIZATION, value);
            }
            let (status, headers, _) =
                call(Arc::clone(&gate), request.body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization:?}");
            assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        }
    }

    #[tokio::test]
    async fn only_v1_is_proxied() {
        let request = HttpRequest::get("/metrics")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            call(gate(CONFIG, "http://127.0.0.1:9"), request).await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// A stand-in vLLM that echoes what it was sent.
    async fn upstream() -> String {
        let app = Router::new().fallback(|request: Request| async move {
            let headers: serde_json::Map<String, serde_json::Value> = request
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
                .collect();
            let path = request.uri().to_string();
            let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
            (
                [("x-upstream", "vllm")],
                Json(json!({ "path": path, "headers": headers, "body": String::from_utf8_lossy(&body) })),
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn v1_reaches_vllm_without_the_token() {
        let gate = gate(CONFIG, &upstream().await);
        let request = HttpRequest::post("/v1/chat/completions?x=1")
            .header(header::AUTHORIZATION, "Bearer secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"model":"m"}"#))
            .unwrap();
        let (status, headers, body) = call(Arc::clone(&gate), request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["x-upstream"], "vllm");
        let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["path"], "/v1/chat/completions?x=1");
        assert_eq!(echoed["body"], r#"{"model":"m"}"#);
        assert_eq!(echoed["headers"]["content-type"], "application/json");
        assert!(echoed["headers"].get("authorization").is_none());
        // And /health follows vLLM's.
        let (_, _, body) = call(
            gate,
            HttpRequest::get("/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({ "status": "ok", "model": "m" })
        );
    }

    #[tokio::test]
    async fn health_is_starting_until_vllm_answers() {
        let (_, _, body) = call(
            gate(CONFIG, "http://127.0.0.1:9"),
            HttpRequest::get("/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["status"],
            "starting"
        );
    }
}
