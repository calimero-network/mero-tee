//! The rollback counters through the HTTP layer: one replica, and three over
//! real sockets.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use libp2p_identity::Keypair;
use tower::util::ServiceExt;

use crate::backend::{test_tdx_backend, Root, TdxBackend, KEY_LEN};
use crate::counters::{session_key_info, Counters};
use crate::handlers::{create_router, create_router_with};
use crate::test_util::read_json_body;
use crate::Config;

use super::*;

const NODE: u64 = 3;

fn backend(seed: u8) -> Arc<TdxBackend> {
    Arc::new(test_tdx_backend(Some(
        Root::from_bytes(&[seed; KEY_LEN]).expect("32-byte root"),
    )))
}

fn peer_id() -> String {
    Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_base58()
}

/// A node's session, as a v2 release would have sealed it to the node.
struct Session {
    peer_id: String,
    id: [u8; 16],
    key: [u8; 32],
}

impl Session {
    fn new(tdx: &TdxBackend, peer_id: &str) -> Self {
        let id = [0x55; 16];
        let path = key_path_for_peer(&Config::default(), Role::Node, peer_id);
        let key = *tdx
            .rollback_session_key(&session_key_info(&path, NODE, &id))
            .expect("root");
        Self {
            peer_id: peer_id.to_owned(),
            id,
            key,
        }
    }

    fn call(&self, domain: &[u8], generation: u64, mark: u64) -> (serde_json::Value, [u8; 32]) {
        let nonce: [u8; 32] = rand::random();
        let message = request_message(
            domain,
            &self.peer_id,
            NODE,
            &self.id,
            generation,
            mark,
            &nonce,
        );
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &self.key), &message);
        let body = serde_json::json!({
            "peerId": self.peer_id,
            "nodeId": NODE,
            "sessionIdB64": BASE64.encode(self.id),
            "generation": generation,
            "mark": mark,
            "nonceB64": BASE64.encode(nonce),
            "macB64": BASE64.encode(tag.as_ref()),
        });
        (body, nonce)
    }

    /// POST a raise or reset to `app`; the acknowledgement, MAC checked.
    async fn send(
        &self,
        app: &Router,
        path: &str,
        generation: u64,
        mark: u64,
    ) -> Result<(u64, u64, u64), (StatusCode, String)> {
        let domain = if path.ends_with("reset") {
            RESET_DOMAIN
        } else {
            RAISE_DOMAIN
        };
        let (body, nonce) = self.call(domain, generation, mark);
        let response = post(app, path, &body).await;
        let status = response.status();
        let json = read_json_body(response).await;
        if status != StatusCode::OK {
            return Err((
                status,
                json["error"].as_str().unwrap_or_default().to_owned(),
            ));
        }
        let (epoch, generation, mark) = (
            json["epoch"].as_u64().unwrap(),
            json["generation"].as_u64().unwrap(),
            json["mark"].as_u64().unwrap(),
        );
        let tag = ack_mac(&self.key, &nonce, epoch, generation, mark);
        assert_eq!(
            json["macB64"].as_str().unwrap(),
            BASE64.encode(tag.as_ref()),
            "the acknowledgement is MACed over the node's nonce"
        );
        Ok((epoch, generation, mark))
    }
}

async fn post(app: &Router, path: &str, body: &serde_json::Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("request should succeed")
}

/// Fixed vectors, repeated in merod's rollback client and reproduced with
/// Python's `hmac`: session key `[0x66; 32]`, peer `12D3KooWPeer`, node 3,
/// session id `[0x55; 16]`, generation 1, mark 42, nonce `[0x77; 32]`, epoch 1.
#[test]
fn the_rollback_macs_match_the_published_vectors() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0x66; 32]);
    let message =
        |domain| request_message(domain, "12D3KooWPeer", 3, &[0x55; 16], 1, 42, &[0x77; 32]);
    assert_eq!(
        hex::encode(hmac::sign(&key, &message(RAISE_DOMAIN)).as_ref()),
        "171f21d4c094f60435bdc07f917f22340fb69f21cf5bc6afc055276f6c9d8107"
    );
    assert_eq!(
        hex::encode(hmac::sign(&key, &message(RESET_DOMAIN)).as_ref()),
        "bc9633cc88afc2a7234b76a84257f2f1fb2a65b8b8dd934907dfeab90bb2fc03"
    );
    assert_eq!(
        hex::encode(ack_mac(&[0x66; 32], &[0x77; 32], 1, 1, 42).as_ref()),
        "7000a4d3e234b832028ec7d8a9f17a6d93d6389e3564575b15787718ce1cfed8"
    );
}

#[tokio::test]
async fn a_raise_moves_the_counter_up_only() {
    let tdx = backend(7);
    let app = create_router(Config::default(), Arc::clone(&tdx));
    let session = Session::new(&tdx, &peer_id());

    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 5).await,
        Ok((0, 0, 5))
    );
    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 3).await,
        Ok((0, 0, 5)),
        "a lower raise is ignored and answered with the counter as kept"
    );
    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 6).await,
        Ok((0, 0, 6))
    );
}

#[tokio::test]
async fn a_raise_with_a_wrong_mac_is_refused() {
    let tdx = backend(7);
    let app = create_router(Config::default(), Arc::clone(&tdx));
    let peer = peer_id();
    let session = Session::new(&tdx, &peer);

    // Signed as a raise, sent as a reset.
    let (body, _) = session.call(RAISE_DOMAIN, 0, 1);
    let response = post(&app, "/rollback/reset", &body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(read_json_body(response).await["error"], "invalid_mac");

    // A field changed after signing.
    let (mut body, _) = session.call(RAISE_DOMAIN, 0, 1);
    body["mark"] = serde_json::json!(1_000_000);
    assert_eq!(
        read_json_body(post(&app, "/rollback/raise", &body).await).await["error"],
        "invalid_mac"
    );

    // Another cluster's session key (another root).
    let other = Session::new(&backend(8), &peer);
    assert_eq!(
        other.send(&app, "/rollback/raise", 0, 1).await,
        Err((StatusCode::UNAUTHORIZED, "invalid_mac".to_owned()))
    );

    // Another node's session cannot move this node's counter.
    let mut wrong_node = session.call(RAISE_DOMAIN, 0, 1).0;
    wrong_node["nodeId"] = serde_json::json!(NODE + 1);
    assert_eq!(
        read_json_body(post(&app, "/rollback/raise", &wrong_node).await).await["error"],
        "invalid_mac"
    );

    // An unknown field is refused, not ignored.
    let mut extra = session.call(RAISE_DOMAIN, 0, 1).0;
    extra["epoch"] = serde_json::json!(0);
    assert!(!post(&app, "/rollback/raise", &extra)
        .await
        .status()
        .is_success());
}

/// The operator's forced rollback: one epoch up, the node's counter down to its
/// store's. A raise from the old generation, however high, no longer wins.
#[tokio::test]
async fn a_reset_raises_the_epoch_and_sets_the_mark() {
    let tdx = backend(7);
    let app = create_router(Config::default(), Arc::clone(&tdx));
    let session = Session::new(&tdx, &peer_id());

    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 9).await,
        Ok((0, 0, 9))
    );
    assert_eq!(
        session.send(&app, "/rollback/reset", 0, 4).await,
        Ok((1, 1, 4))
    );
    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 100).await,
        Ok((1, 1, 4)),
        "a raise of the generation before the reset changes nothing"
    );
    assert_eq!(
        session.send(&app, "/rollback/raise", 1, 5).await,
        Ok((1, 1, 5))
    );
    assert_eq!(
        session.send(&app, "/rollback/reset", 1, 2).await,
        Ok((2, 2, 2))
    );
}

/// A replica that has the root but has not synced its counters answers no
/// counter request: its empty view would hide every acknowledged write.
#[tokio::test]
async fn a_replica_that_has_not_synced_refuses_counter_requests() {
    let tdx = backend(7);
    let counters = Arc::new(Counters::new(3, vec!["http://127.0.0.1:9".to_owned()]));
    let app = create_router_with(Config::default(), Arc::clone(&tdx), counters);
    let session = Session::new(&tdx, &peer_id());
    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 1).await,
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "counters_unavailable".to_owned()
        ))
    );
}

/// A replica serving on a real socket, until aborted.
struct Served {
    url: String,
    tdx: Arc<TdxBackend>,
    counters: Arc<Counters>,
    app: Router,
    task: tokio::task::JoinHandle<()>,
}

/// Bind `n` sockets first, so each replica can name the others as peers.
async fn listeners(n: usize) -> Vec<(tokio::net::TcpListener, String)> {
    let mut out = Vec::new();
    for _ in 0..n {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        out.push((listener, url));
    }
    out
}

fn serve(
    listener: tokio::net::TcpListener,
    url: String,
    tdx: Arc<TdxBackend>,
    peers: Vec<String>,
) -> Served {
    let config = Config {
        replicas: 3,
        cluster_peers: peers.clone(),
        ..Config::default()
    };
    let counters = Arc::new(Counters::new(3, peers));
    let app = create_router_with(config, Arc::clone(&tdx), Arc::clone(&counters));
    let served = app.clone();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, served).await;
    });
    Served {
        url,
        tdx,
        counters,
        app,
        task,
    }
}

/// Three replicas of one cluster: the first bootstraps, the others sync in
/// genesis. A write needs two of three; a replica that replaces a lost one
/// syncs from a majority, so it holds every acknowledged write, and serves
/// it once the replica it synced from is gone too.
#[tokio::test]
async fn counters_need_a_majority_and_survive_a_replaced_replica() {
    let mut sockets = listeners(4).await;
    let (d_listener, d_url) = sockets.pop().unwrap();
    let urls: Vec<String> = sockets.iter().map(|(_, url)| url.clone()).collect();
    let others = |i: usize| -> Vec<String> {
        urls.iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, u)| u.clone())
            .collect()
    };
    let mut replicas: Vec<Served> = sockets
        .into_iter()
        .enumerate()
        .map(|(i, (listener, url))| serve(listener, url, backend(7), others(i)))
        .collect();
    replicas[0].counters.bootstrap();
    for r in &replicas[1..] {
        assert!(r.counters.sync_once(&r.tdx).await.unwrap(), "genesis sync");
    }

    let peer = peer_id();
    let session = Session::new(&replicas[0].tdx, &peer);
    let a = replicas[0].app.clone();
    assert_eq!(
        session.send(&a, "/rollback/raise", 0, 5).await,
        Ok((0, 0, 5))
    );
    assert!(replicas[0].counters.is_formed());

    // C is lost; A and B still make a majority.
    let c = replicas.pop().unwrap();
    c.task.abort();
    let _ = c.task.await;
    assert_eq!(
        session.send(&a, "/rollback/raise", 0, 7).await,
        Ok((0, 0, 7))
    );

    // D replaces C: it syncs from A and B, and holds 7.
    let d = serve(d_listener, d_url, backend(7), others(2));
    assert!(d.counters.sync_once(&d.tdx).await.unwrap());

    // A is lost too: D and B are a majority, and both hold 7.
    let a_replica = replicas.remove(0);
    a_replica.task.abort();
    let _ = a_replica.task.await;
    let path = key_path_for_peer(&Config::default(), Role::Node, &peer);
    let view = d.counters.read(&d.tdx, &path).await.unwrap();
    assert_eq!(view.nodes[&NODE].mark, 7);
    assert_eq!(
        session.send(&d.app, "/rollback/raise", 0, 8).await,
        Ok((0, 0, 8))
    );

    // B is lost: D alone is no majority.
    let b = replicas.remove(0);
    b.task.abort();
    let _ = b.task.await;
    assert_eq!(
        session.send(&d.app, "/rollback/raise", 0, 9).await,
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "counters_unavailable".to_owned()
        ))
    );
    d.task.abort();
}

/// Replicas of another cluster (another root) answer under another key: they
/// never count toward this cluster's majority, nor form it.
#[tokio::test]
async fn replicas_of_another_cluster_do_not_count() {
    let sockets = listeners(3).await;
    let urls: Vec<String> = sockets.iter().map(|(_, url)| url.clone()).collect();
    let mut served = Vec::new();
    for (i, (listener, url)) in sockets.into_iter().enumerate() {
        let peers = urls
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, u)| u.clone())
            .collect();
        let r = serve(listener, url, backend(if i == 0 { 7 } else { 8 }), peers);
        r.counters.bootstrap();
        served.push(r);
    }
    let session = Session::new(&served[0].tdx, &peer_id());
    assert_eq!(
        session.send(&served[0].app, "/rollback/raise", 0, 1).await,
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "counters_unavailable".to_owned()
        ))
    );
    for r in served {
        r.task.abort();
        let _ = r.url;
    }
}

/// The whole v2 release over a mock quote: the record is sealed, names the
/// node's counter, and its session key moves that counter.
#[cfg(feature = "mock-attestation")]
#[tokio::test]
async fn a_v2_release_carries_the_counter_sealed() {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    use crate::handlers::get_key::signature_payload;
    use crate::sealed;

    let tdx = backend(7);
    let config = Config {
        accept_mock_attestation: true,
        ..Config::default()
    };
    let app = create_router(config, Arc::clone(&tdx));
    let keypair = Keypair::generate_ed25519();
    let peer = keypair.public().to_peer_id().to_base58();
    let node_secret = [0x33; 32];
    let seal_to = MontgomeryPoint::mul_base_clamped(node_secret).0;
    let transport = *tdx.transport_key().unwrap().public();

    // Release for `node`, signing `signed_node` (None: the node id unsigned).
    let release = |node: u64, signed_node: Option<u64>| {
        let app = app.clone();
        let keypair = keypair.clone();
        let peer = peer.clone();
        async move {
            let challenge = read_json_body(
                post(&app, "/challenge", &serde_json::json!({ "peerId": peer })).await,
            )
            .await;
            let challenge_id = challenge["challengeId"].as_str().unwrap().to_owned();
            let nonce: [u8; 32] = BASE64
                .decode(challenge["nonceB64"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let mut report_data = [0u8; 64];
            report_data[..32].copy_from_slice(&nonce);
            report_data[32..].copy_from_slice(&sealed::request_binding_v2(&seal_to, &peer, node));
            let quote =
                calimero_tee_attestation::generate_mock_attestation(report_data).quote_bytes;
            let payload = signature_payload(
                &challenge_id,
                &nonce,
                &quote,
                &peer,
                Some(&seal_to),
                signed_node,
            )
            .unwrap();
            let body = serde_json::json!({
                "challengeId": challenge_id,
                "quoteB64": BASE64.encode(&quote),
                "peerId": peer,
                "peerPublicKeyB64": BASE64.encode(keypair.public().encode_protobuf()),
                "signatureB64": BASE64.encode(keypair.sign(&payload).unwrap()),
                "sealToB64": BASE64.encode(seal_to),
                "rollbackNodeId": node,
            });
            let response = post(&app, "/get-key", &body).await;
            let status = response.status();
            (status, read_json_body(response).await, nonce)
        }
    };
    let open = |json: &serde_json::Value, nonce: &[u8; 32]| -> serde_json::Value {
        let sealed_record = BASE64
            .decode(json["sealedKeyB64"].as_str().unwrap())
            .unwrap();
        let seal_nonce: [u8; 12] = BASE64
            .decode(json["sealNonceB64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let plain = sealed::open_v2(
            &node_secret,
            &transport,
            nonce,
            &peer,
            &seal_nonce,
            &sealed_record,
        )
        .expect("the record opens for the node");
        serde_json::from_slice(&plain).unwrap()
    };

    // The node id is unsigned: refused.
    let (status, json, _) = release(NODE, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["error"], "invalid_signature");

    let (status, json, nonce) = release(NODE, Some(NODE)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json.get("key").is_none());
    let record = open(&json, &nonce);
    assert_eq!(record["epoch"], 0);
    assert_eq!(record["generation"], 0);
    assert!(record.get("mark").is_none(), "no counter yet: {record}");
    let path = key_path_for_peer(&Config::default(), Role::Node, &peer);
    assert_eq!(
        record["keyHex"].as_str().unwrap(),
        tdx.derive_key_hex(&path).unwrap().as_str(),
        "the same key a v1 release gives"
    );

    // The sealed session key moves the counter, and the next release says so.
    let session = Session {
        peer_id: peer.clone(),
        id: BASE64
            .decode(record["sessionIdB64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        key: hex::decode(record["sessionKeyHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    assert_eq!(
        session.send(&app, "/rollback/raise", 0, 41).await,
        Ok((0, 0, 41))
    );
    let (_, json, nonce) = release(NODE, Some(NODE)).await;
    let record = open(&json, &nonce);
    assert_eq!(record["mark"], 41);
    assert_ne!(
        record["sessionIdB64"],
        BASE64.encode(session.id),
        "each release opens a session of its own"
    );

    // Another node of the same cluster has a counter of its own.
    let (_, json, nonce) = release(NODE + 1, Some(NODE + 1)).await;
    assert!(open(&json, &nonce).get("mark").is_none());
}

/// `/attest` reports its capabilities only when asked, and its quote then
/// commits to them (the v2 binding); otherwise it is unchanged.
#[cfg(feature = "mock-attestation")]
#[tokio::test]
async fn attest_commits_to_its_capabilities_when_asked() {
    use sha2::Digest;

    use crate::sealed;

    let tdx = backend(7);
    let app = create_router(Config::default(), Arc::clone(&tdx));
    let transport = *tdx.transport_key().unwrap().public();
    let nonce = [0x11; 32];
    let ask = |capabilities: bool| {
        serde_json::json!({
            "nonceB64": BASE64.encode(nonce),
            "transportKey": true,
            "capabilities": capabilities,
        })
    };
    let default_binding: [u8; 32] = sha2::Sha256::digest(b"mero-kms-attest-v1").into();

    let v2 = read_json_body(post(&app, "/attest", &ask(true)).await).await;
    assert_eq!(v2["capabilities"], serde_json::json!(["rollback/v1"]));
    assert_eq!(
        v2["reportDataHex"].as_str().unwrap()[64..],
        hex::encode(sealed::attest_binding_v2(&default_binding, &transport))
    );

    let v1 = read_json_body(post(&app, "/attest", &ask(false)).await).await;
    assert!(v1.get("capabilities").is_none());
    assert_eq!(
        v1["reportDataHex"].as_str().unwrap()[64..],
        hex::encode(sealed::attest_binding(&default_binding, &transport))
    );
}
