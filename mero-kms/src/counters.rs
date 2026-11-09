//! Rollback counters: what mero-kms remembers of each node's store.
//!
//! A host can restart a node on an older copy of its disk, and sealing hides a
//! copy's content but not its age. So the node raises a counter in its sealed
//! store and here, about once a second, and refuses to start on a store whose
//! counter is below the one kept here (merod's `rollback` module).
//!
//! Per cluster key path (`{prefix}/{profile}/{peerId}`, the disk identity one
//! cluster's nodes share) this keeps:
//!
//! * `epoch`, how many rollbacks were forced (`/rollback/reset`), and
//! * per node id, an [`Entry`] `(generation, mark)`, ordered as a pair. A raise
//!   only ever moves it up; a reset sets it to `(new epoch, the store's mark)`,
//!   which is larger as a pair. So two views merge by taking the maximum, and
//!   replicas never have to agree on an order.
//!
//! Counters live in the replicas' memory, like the root. A write is answered
//! once a majority of the `MERO_KMS_REPLICAS` replicas hold it, and a read
//! merges a majority's views, so every read meets every acknowledged write.
//! Replicas MAC every counter message with a key derived from the root
//! ([`TdxBackend::counters_key`]), so only replicas of this cluster count, and
//! each answers with a random replica id of its own, so one replica behind two
//! URLs counts once.
//!
//! A replica that joins holds nothing, so it answers no counter request until
//! it has merged the views of a majority of ready replicas ([`sync_until_ready`]).
//! While a cluster is brought up there is no such majority yet: the bootstrap
//! replica starts ready and in **genesis**, and a joiner whose every ready
//! answer is a genesis replica with no counters becomes ready in genesis too.
//! Genesis ends for good once the cluster is **formed** (one round heard every
//! replica ready, which a write needs first), and after [`GENESIS_WINDOW`] in
//! any case.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::hmac;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::backend::TdxBackend;
use crate::handlers::errors::ServiceError;

/// Clusters one replica keeps counters for.
pub(crate) const MAX_COUNTER_CLUSTERS: usize = 10_000;
/// Node ids one cluster keeps counters for.
pub(crate) const MAX_COUNTER_NODES_PER_CLUSTER: usize = 1024;
/// Most replicas `MERO_KMS_REPLICAS` may name.
pub(crate) const MAX_REPLICAS: usize = 15;
/// How long one replica waits for another's answer.
pub(crate) const PEER_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest counter answer a replica reads from another (a whole map, on sync).
pub(crate) const MAX_COUNTER_ANSWER_BYTES: usize = 64 * 1024 * 1024;
/// How long after the root was made a joiner may still become ready in genesis.
pub(crate) const GENESIS_WINDOW: Duration = Duration::from_secs(10 * 60);

const READ_DOMAIN: &[u8] = b"mero-kms/counters/read/v1";
const MERGE_DOMAIN: &[u8] = b"mero-kms/counters/merge/v1";
const ANSWER_DOMAIN: &[u8] = b"mero-kms/counters/answer/v1";

/// One node's counter: a forced rollback raises `generation`, a checkpoint `mark`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub generation: u64,
    pub mark: u64,
}

/// One cluster's counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterCounters {
    pub epoch: u64,
    pub nodes: BTreeMap<u64, Entry>,
}

impl ClusterCounters {
    /// Take the larger of each value. Refused, untouched, past the node limit.
    pub(crate) fn merge(&mut self, other: &Self) -> Result<(), ServiceError> {
        let new = other
            .nodes
            .keys()
            .filter(|node| !self.nodes.contains_key(node))
            .count();
        if self.nodes.len() + new > MAX_COUNTER_NODES_PER_CLUSTER {
            return Err(ServiceError::CounterLimit(format!(
                "a cluster keeps counters for at most {MAX_COUNTER_NODES_PER_CLUSTER} nodes"
            )));
        }
        self.epoch = self.epoch.max(other.epoch);
        for (node, entry) in &other.nodes {
            let mine = self.nodes.entry(*node).or_default();
            *mine = (*mine).max(*entry);
        }
        Ok(())
    }
}

type CounterMap = BTreeMap<String, ClusterCounters>;

/// Merge `from` into `into`, refusing a new cluster past the limit.
fn merge_map(into: &mut CounterMap, from: &CounterMap) -> Result<(), ServiceError> {
    for (path, counters) in from {
        merge_cluster(into, path, counters)?;
    }
    Ok(())
}

fn merge_cluster(
    into: &mut CounterMap,
    path: &str,
    counters: &ClusterCounters,
) -> Result<ClusterCounters, ServiceError> {
    if !into.contains_key(path) && into.len() >= MAX_COUNTER_CLUSTERS {
        return Err(ServiceError::CounterLimit(format!(
            "a replica keeps counters for at most {MAX_COUNTER_CLUSTERS} clusters"
        )));
    }
    let mine = into.entry(path.to_owned()).or_default();
    mine.merge(counters)?;
    Ok(mine.clone())
}

/// The HKDF info of a node's rollback session key: `keyPath \n nodeId \n
/// hex(sessionId)`. The core client never derives it (the key reaches it
/// sealed); it is here so any replica recomputes the same key.
pub(crate) fn session_key_info(key_path: &str, node_id: u64, session_id: &[u8; 16]) -> String {
    format!("{key_path}\n{node_id}\n{}", hex::encode(session_id))
}

struct Inner {
    map: CounterMap,
    /// Holds every acknowledged write: bootstrapped, or synced from a majority.
    ready: bool,
    /// Some round heard every replica ready; genesis is over for good.
    formed: bool,
    /// Until when a joiner may take this replica's empty view as the cluster's.
    genesis_until: Option<Instant>,
}

impl Inner {
    fn genesis_left(&self) -> Option<Duration> {
        if self.formed || !self.ready {
            return None;
        }
        self.genesis_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
            .filter(|left| !left.is_zero())
    }

    fn learn_formed(&mut self) {
        if !self.formed {
            self.formed = true;
            self.genesis_until = None;
        }
    }
}

/// This replica's counters, and the replicas it reaches.
pub(crate) struct Counters {
    replica_id: [u8; 16],
    replicas: usize,
    peers: Vec<String>,
    client: reqwest::Client,
    inner: Mutex<Inner>,
}

/// A counter message between replicas: `body` is JSON, MACed as it is.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Signed {
    body: String,
    mac_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadBody {
    nonce_b64: String,
    /// One cluster's counters, or (a joiner's sync) all of them.
    key_path: Option<String>,
    formed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MergeBody {
    nonce_b64: String,
    key_path: String,
    counters: ClusterCounters,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AnswerBody {
    nonce_b64: String,
    replica_id_b64: String,
    ready: bool,
    formed: bool,
    /// Seconds of genesis left, while this replica may vouch for an empty cluster.
    genesis_secs: Option<u64>,
    counters: CounterMap,
}

fn mac(key: &[u8], domain: &[u8], body: &[u8]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(domain);
    ctx.update(body);
    ctx.sign()
}

fn sign(key: &[u8], domain: &[u8], body: &impl Serialize) -> Result<Signed, ServiceError> {
    let body = serde_json::to_string(body)
        .map_err(|e| ServiceError::KeyDerivationFailed(format!("counter message: {e}")))?;
    let tag = mac(key, domain, body.as_bytes());
    Ok(Signed {
        mac_b64: BASE64.encode(tag.as_ref()),
        body,
    })
}

fn open<T: for<'de> Deserialize<'de>>(
    key: &[u8],
    domain: &[u8],
    signed: &Signed,
) -> Result<T, ServiceError> {
    let tag = BASE64
        .decode(&signed.mac_b64)
        .map_err(|e| ServiceError::InvalidBase64(e.to_string()))?;
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut message = domain.to_vec();
    message.extend_from_slice(signed.body.as_bytes());
    hmac::verify(&hmac_key, &message, &tag)
        .map_err(|_| ServiceError::InvalidMac("counter message".to_owned()))?;
    serde_json::from_str(&signed.body)
        .map_err(|e| ServiceError::InvalidAttestationRequest(format!("counter message: {e}")))
}

/// A peer's verified answer.
struct Answer {
    ready: bool,
    formed: bool,
    genesis_secs: Option<u64>,
    counters: CounterMap,
}

impl Counters {
    /// `replicas` is `MERO_KMS_REPLICAS`; `peers` the other replicas' base URLs.
    pub(crate) fn new(replicas: usize, peers: Vec<String>) -> Self {
        Self {
            replica_id: rand::random(),
            replicas: replicas.max(1),
            peers,
            client: reqwest::Client::builder()
                .timeout(PEER_TIMEOUT)
                .build()
                // SAFETY: a client with only a timeout set always builds.
                .expect("a reqwest client with a timeout always builds"),
            inner: Mutex::new(Inner {
                map: CounterMap::new(),
                ready: false,
                formed: false,
                genesis_until: None,
            }),
        }
    }

    /// The replica that made the root: nothing was ever written, so it holds
    /// every write there is. A single-replica cluster is formed at once.
    pub(crate) fn bootstrap(&self) {
        let mut inner = self.lock();
        inner.ready = true;
        inner.genesis_until = Some(Instant::now() + GENESIS_WINDOW);
        if self.replicas == 1 {
            inner.learn_formed();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a panic mid-merge; the map is still a valid
        // view (merges only raise), so keep serving it.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn majority(&self) -> usize {
        self.replicas / 2 + 1
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.lock().ready
    }

    fn require_ready(&self) -> Result<(), ServiceError> {
        if self.is_ready() {
            return Ok(());
        }
        Err(ServiceError::CountersUnavailable(
            "this replica has not synced its counters yet".to_owned(),
        ))
    }

    /// Answer a peer's read: one cluster's counters, or all of them.
    pub(crate) fn answer_read(
        &self,
        backend: &TdxBackend,
        signed: &Signed,
    ) -> Result<Signed, ServiceError> {
        let key = backend.counters_key()?;
        let body: ReadBody = open(&*key, READ_DOMAIN, signed)?;
        let mut inner = self.lock();
        if body.formed {
            inner.learn_formed();
        }
        let counters = match &body.key_path {
            Some(path) => inner
                .map
                .get(path)
                .map(|c| CounterMap::from([(path.clone(), c.clone())]))
                .unwrap_or_default(),
            None => inner.map.clone(),
        };
        let answer = self.answer_body(&inner, body.nonce_b64, counters);
        drop(inner);
        sign(&*key, ANSWER_DOMAIN, &answer)
    }

    /// Merge a peer's write and answer with the cluster's counters as now held.
    /// A replica not yet synced takes it too: it then holds this write.
    pub(crate) fn answer_merge(
        &self,
        backend: &TdxBackend,
        signed: &Signed,
    ) -> Result<Signed, ServiceError> {
        let key = backend.counters_key()?;
        let body: MergeBody = open(&*key, MERGE_DOMAIN, signed)?;
        let mut inner = self.lock();
        // A write is sent only once the cluster formed.
        inner.learn_formed();
        let merged = merge_cluster(&mut inner.map, &body.key_path, &body.counters)?;
        let answer = self.answer_body(
            &inner,
            body.nonce_b64,
            CounterMap::from([(body.key_path, merged)]),
        );
        drop(inner);
        sign(&*key, ANSWER_DOMAIN, &answer)
    }

    fn answer_body(&self, inner: &Inner, nonce_b64: String, counters: CounterMap) -> AnswerBody {
        AnswerBody {
            nonce_b64,
            replica_id_b64: BASE64.encode(self.replica_id),
            ready: inner.ready,
            formed: inner.formed,
            genesis_secs: inner.genesis_left().map(|left| left.as_secs().max(1)),
            counters,
        }
    }

    /// Send `signed` to every peer at `path` and collect the verified answers
    /// to `nonce`, one per replica id, never this replica's own.
    async fn round(
        &self,
        backend: &TdxBackend,
        path: &str,
        nonce_b64: &str,
        signed: &Signed,
    ) -> Result<Vec<Answer>, ServiceError> {
        let key = backend.counters_key()?;
        let calls = self.peers.iter().map(|peer| {
            let url = format!("{}/{path}", peer.trim_end_matches('/'));
            let client = self.client.clone();
            let signed = signed.clone();
            async move {
                let response = client.post(&url).json(&signed).send().await.ok()?;
                if !response.status().is_success() {
                    return None;
                }
                let bytes = response.bytes().await.ok()?;
                if bytes.len() > MAX_COUNTER_ANSWER_BYTES {
                    return None;
                }
                serde_json::from_slice::<Signed>(&bytes).ok()
            }
        });
        let replies = futures_join_all(calls).await;
        let mut seen = HashSet::from([self.replica_id]);
        let mut answers = Vec::new();
        for reply in replies.into_iter().flatten() {
            let body: AnswerBody = match open(&*key, ANSWER_DOMAIN, &reply) {
                Ok(body) => body,
                Err(e) => {
                    warn!("Ignored a counter answer: {e}");
                    continue;
                }
            };
            if body.nonce_b64 != nonce_b64 {
                warn!("Ignored a counter answer to another request");
                continue;
            }
            let Ok(Ok(replica_id)) = BASE64
                .decode(&body.replica_id_b64)
                .map(<[u8; 16]>::try_from)
            else {
                continue;
            };
            if !seen.insert(replica_id) {
                continue;
            }
            answers.push(Answer {
                ready: body.ready,
                formed: body.formed,
                genesis_secs: body.genesis_secs,
                counters: body.counters,
            });
        }
        Ok(answers)
    }

    fn read_request(
        &self,
        backend: &TdxBackend,
        key_path: Option<&str>,
    ) -> Result<(String, Signed), ServiceError> {
        let nonce_b64 = BASE64.encode(rand::random::<[u8; 32]>());
        let formed = self.lock().formed;
        let body = ReadBody {
            nonce_b64: nonce_b64.clone(),
            key_path: key_path.map(str::to_owned),
            formed,
        };
        Ok((
            nonce_b64,
            sign(&*backend.counters_key()?, READ_DOMAIN, &body)?,
        ))
    }

    /// One cluster's counters, merged from a majority of ready replicas
    /// (this one included). Refused until the cluster has formed.
    pub(crate) async fn read(
        &self,
        backend: &TdxBackend,
        key_path: &str,
    ) -> Result<ClusterCounters, ServiceError> {
        self.require_ready()?;
        let mut view = self.lock().map.get(key_path).cloned().unwrap_or_default();
        if self.replicas == 1 {
            return Ok(view);
        }
        let (nonce_b64, signed) = self.read_request(backend, Some(key_path))?;
        let answers = self
            .round(backend, "cluster/counters/read", &nonce_b64, &signed)
            .await?;
        let ready: Vec<&Answer> = answers.iter().filter(|a| a.ready).collect();
        {
            let mut inner = self.lock();
            if ready.len() + 1 >= self.replicas || answers.iter().any(|a| a.formed) {
                inner.learn_formed();
            }
            if !inner.formed {
                return Err(ServiceError::CountersUnavailable(format!(
                    "the counters are not formed yet: {} of {} replicas ready",
                    ready.len() + 1,
                    self.replicas
                )));
            }
        }
        if ready.len() + 1 < self.majority() {
            return Err(ServiceError::CountersUnavailable(format!(
                "{} of {} replicas answered; a read needs {}",
                ready.len() + 1,
                self.replicas,
                self.majority()
            )));
        }
        for answer in ready {
            if let Some(theirs) = answer.counters.get(key_path) {
                view.merge(theirs)?;
            }
        }
        // Keep what the majority knew: a later read here starts from it.
        let _ = merge_cluster(&mut self.lock().map, key_path, &view)?;
        Ok(view)
    }

    /// Merge `update` into one cluster's counters on a majority of replicas
    /// (this one included) and answer with the counters they then hold.
    pub(crate) async fn write(
        &self,
        backend: &TdxBackend,
        key_path: &str,
        update: &ClusterCounters,
    ) -> Result<ClusterCounters, ServiceError> {
        self.require_ready()?;
        if !self.lock().formed {
            // A read forms the cluster or says why it cannot.
            let _ = self.read(backend, key_path).await?;
        }
        let mut view = merge_cluster(&mut self.lock().map, key_path, update)?;
        if self.replicas == 1 {
            return Ok(view);
        }
        let nonce_b64 = BASE64.encode(rand::random::<[u8; 32]>());
        let body = MergeBody {
            nonce_b64: nonce_b64.clone(),
            key_path: key_path.to_owned(),
            counters: update.clone(),
        };
        let signed = sign(&*backend.counters_key()?, MERGE_DOMAIN, &body)?;
        let answers = self
            .round(backend, "cluster/counters/merge", &nonce_b64, &signed)
            .await?;
        if answers.len() + 1 < self.majority() {
            return Err(ServiceError::CountersUnavailable(format!(
                "{} of {} replicas took the write; it needs {}",
                answers.len() + 1,
                self.replicas,
                self.majority()
            )));
        }
        for answer in &answers {
            if let Some(theirs) = answer.counters.get(key_path) {
                view.merge(theirs)?;
            }
        }
        let _ = merge_cluster(&mut self.lock().map, key_path, &view)?;
        Ok(view)
    }

    /// Raise `node`'s entry to at least `entry`; answer the cluster's counters.
    pub(crate) async fn raise(
        &self,
        backend: &TdxBackend,
        key_path: &str,
        node: u64,
        entry: Entry,
    ) -> Result<ClusterCounters, ServiceError> {
        let update = ClusterCounters {
            epoch: 0,
            nodes: BTreeMap::from([(node, entry)]),
        };
        self.write(backend, key_path, &update).await
    }

    /// Force `node`'s entry down to `mark`: one epoch up, entry `(epoch, mark)`.
    pub(crate) async fn reset(
        &self,
        backend: &TdxBackend,
        key_path: &str,
        node: u64,
        mark: u64,
    ) -> Result<ClusterCounters, ServiceError> {
        let current = self.read(backend, key_path).await?;
        let epoch = current.epoch.checked_add(1).ok_or_else(|| {
            ServiceError::CounterLimit("the cluster's epoch is at its maximum".to_owned())
        })?;
        let update = ClusterCounters {
            epoch,
            nodes: BTreeMap::from([(
                node,
                Entry {
                    generation: epoch,
                    mark,
                },
            )]),
        };
        self.write(backend, key_path, &update).await
    }

    /// One attempt to sync a replica that holds the root but no counters.
    /// `Ok(true)` once it is ready.
    pub(crate) async fn sync_once(&self, backend: &TdxBackend) -> Result<bool, ServiceError> {
        if self.is_ready() {
            return Ok(true);
        }
        if self.replicas == 1 {
            self.bootstrap();
            return Ok(true);
        }
        let (nonce_b64, signed) = self.read_request(backend, None)?;
        let answers = self
            .round(backend, "cluster/counters/read", &nonce_b64, &signed)
            .await?;
        let ready: Vec<&Answer> = answers.iter().filter(|a| a.ready).collect();
        let mut inner = self.lock();
        if ready.len() >= self.majority() {
            for answer in &ready {
                merge_map(&mut inner.map, &answer.counters)?;
            }
            inner.ready = true;
            if answers.iter().any(|a| a.formed) {
                inner.learn_formed();
            }
            info!(
                from = ready.len(),
                clusters = inner.map.len(),
                "Synced the counters from a majority"
            );
            return Ok(true);
        }
        // Bring-up: every ready replica heard is in genesis and holds nothing.
        let genesis = ready.iter().all(|a| {
            a.genesis_secs.is_some() && !a.formed && a.counters.values().all(|c| c.nodes.is_empty())
        });
        if !ready.is_empty() && genesis && !answers.iter().any(|a| a.formed) {
            let left = ready
                .iter()
                .filter_map(|a| a.genesis_secs)
                .min()
                .unwrap_or(0);
            inner.ready = true;
            inner.genesis_until = Some(Instant::now() + Duration::from_secs(left));
            info!(
                from = ready.len(),
                "Joined the counters of a cluster still being brought up"
            );
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn is_formed(&self) -> bool {
        self.lock().formed
    }
}

/// Join `calls` concurrently (no `futures` dependency for one helper).
async fn futures_join_all<F, T>(calls: impl Iterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = calls.map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(value) = handle.await {
            out.push(value);
        }
    }
    out
}

/// Sync until ready, pausing `retry` between attempts. Runs after the root
/// arrives; until it returns this replica answers counter requests with 503.
pub(crate) async fn sync_until_ready(
    counters: Arc<Counters>,
    backend: Arc<TdxBackend>,
    retry: Duration,
) {
    loop {
        match counters.sync_once(&backend).await {
            Ok(true) => return,
            Ok(false) => info!("Waiting for a majority of ready replicas to sync the counters"),
            Err(e) => warn!("Counter sync failed: {e}"),
        }
        tokio::time::sleep(retry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(generation: u64, mark: u64) -> Entry {
        Entry { generation, mark }
    }

    #[test]
    fn entries_order_as_pairs() {
        assert!(entry(1, 0) > entry(0, 99));
        assert!(entry(0, 5) > entry(0, 4));
    }

    #[test]
    fn a_merge_takes_the_larger_of_each_value() {
        let mut a = ClusterCounters {
            epoch: 1,
            nodes: BTreeMap::from([(1, entry(0, 9)), (2, entry(1, 1))]),
        };
        let b = ClusterCounters {
            epoch: 2,
            nodes: BTreeMap::from([(1, entry(0, 4)), (2, entry(2, 0)), (3, entry(0, 1))]),
        };
        a.merge(&b).unwrap();
        assert_eq!(a.epoch, 2);
        assert_eq!(a.nodes[&1], entry(0, 9), "a lower mark never wins");
        assert_eq!(a.nodes[&2], entry(2, 0), "a reset's generation wins");
        assert_eq!(a.nodes[&3], entry(0, 1));
    }

    #[test]
    fn the_node_limit_is_kept_and_a_refused_merge_changes_nothing() {
        let mut full = ClusterCounters::default();
        for node in 0..MAX_COUNTER_NODES_PER_CLUSTER as u64 {
            let _ = full.nodes.insert(node, entry(0, 1));
        }
        let before = full.clone();
        let one_more = ClusterCounters {
            epoch: 9,
            nodes: BTreeMap::from([(u64::MAX, entry(0, 1))]),
        };
        assert!(matches!(
            full.merge(&one_more),
            Err(ServiceError::CounterLimit(_))
        ));
        assert_eq!(full, before);
    }

    #[test]
    fn the_cluster_limit_is_kept() {
        let mut map = CounterMap::new();
        for i in 0..MAX_COUNTER_CLUSTERS {
            let _ = merge_cluster(&mut map, &i.to_string(), &ClusterCounters::default()).unwrap();
        }
        assert!(merge_cluster(&mut map, "new", &ClusterCounters::default()).is_err());
        assert!(merge_cluster(&mut map, "0", &ClusterCounters::default()).is_ok());
    }

    #[test]
    fn a_message_under_another_key_or_domain_is_refused() {
        let body = ReadBody {
            nonce_b64: "n".to_owned(),
            key_path: None,
            formed: false,
        };
        let signed = sign(&[1; 32], READ_DOMAIN, &body).unwrap();
        assert!(open::<ReadBody>(&[1; 32], READ_DOMAIN, &signed).is_ok());
        assert!(matches!(
            open::<ReadBody>(&[2; 32], READ_DOMAIN, &signed),
            Err(ServiceError::InvalidMac(_))
        ));
        assert!(open::<ReadBody>(&[1; 32], MERGE_DOMAIN, &signed).is_err());
        let tampered = Signed {
            body: signed.body.replace("\"n\"", "\"m\""),
            mac_b64: signed.mac_b64.clone(),
        };
        assert!(open::<ReadBody>(&[1; 32], READ_DOMAIN, &tampered).is_err());
    }

    #[test]
    fn a_joiner_is_not_ready_and_a_bootstrap_replica_is() {
        let joiner = Counters::new(3, Vec::new());
        assert!(!joiner.is_ready());
        let first = Counters::new(3, Vec::new());
        first.bootstrap();
        assert!(first.is_ready());
        assert!(!first.is_formed(), "three replicas: not formed alone");
        let single = Counters::new(1, Vec::new());
        single.bootstrap();
        assert!(single.is_formed());
    }
}
