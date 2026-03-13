use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub peer_id: String,
    pub expires_at: u64,
}

#[derive(Debug)]
pub enum ChallengeStoreError {
    InvalidRedisUrl(String),
    LockPoisoned,
    Clock(String),
    Serialize(String),
    RedisConnection(String),
    RedisOperation(String),
    NotFoundOrExpired,
    PeerMismatch,
    Expired,
}

impl Display for ChallengeStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRedisUrl(msg) => write!(f, "invalid redis url: {}", msg),
            Self::LockPoisoned => write!(f, "challenge store lock poisoned"),
            Self::Clock(msg) => write!(f, "system clock error: {}", msg),
            Self::Serialize(msg) => write!(f, "challenge serialization error: {}", msg),
            Self::RedisConnection(msg) => write!(f, "redis connection failed: {}", msg),
            Self::RedisOperation(msg) => write!(f, "redis operation failed: {}", msg),
            Self::NotFoundOrExpired => write!(f, "challenge not found or expired"),
            Self::PeerMismatch => write!(f, "challenge peer mismatch"),
            Self::Expired => write!(f, "challenge has expired"),
        }
    }
}

impl std::error::Error for ChallengeStoreError {}

#[derive(Clone)]
pub enum ChallengeStore {
    InMemory(Arc<Mutex<HashMap<String, PendingChallenge>>>),
    Redis(redis::Client),
}

impl ChallengeStore {
    pub fn from_redis_url(redis_url: Option<&str>) -> Result<Self, ChallengeStoreError> {
        if let Some(url) = redis_url {
            let client = redis::Client::open(url)
                .map_err(|e| ChallengeStoreError::InvalidRedisUrl(e.to_string()))?;
            Ok(Self::Redis(client))
        } else {
            Ok(Self::InMemory(Arc::new(Mutex::new(HashMap::new()))))
        }
    }

    pub async fn insert(
        &self,
        challenge_id: String,
        challenge: PendingChallenge,
        ttl_secs: u64,
    ) -> Result<(), ChallengeStoreError> {
        match self {
            Self::InMemory(store) => {
                let now = unix_now_secs()?;
                let mut guard = store
                    .lock()
                    .map_err(|_| ChallengeStoreError::LockPoisoned)?;
                prune_expired_challenges(&mut guard, now);
                guard.insert(challenge_id, challenge);
                Ok(())
            }
            Self::Redis(client) => {
                let key = redis_challenge_key(&challenge_id);
                let payload = serde_json::to_string(&challenge)
                    .map_err(|e| ChallengeStoreError::Serialize(e.to_string()))?;
                let mut conn = client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(|e| ChallengeStoreError::RedisConnection(e.to_string()))?;
                conn.set_ex::<_, _, ()>(key, payload, ttl_secs)
                    .await
                    .map_err(|e| ChallengeStoreError::RedisOperation(e.to_string()))?;
                Ok(())
            }
        }
    }

    pub async fn consume(
        &self,
        challenge_id: &str,
        peer_id: &str,
    ) -> Result<[u8; 32], ChallengeStoreError> {
        let now = unix_now_secs()?;
        match self {
            Self::InMemory(store) => {
                let mut guard = store
                    .lock()
                    .map_err(|_| ChallengeStoreError::LockPoisoned)?;
                prune_expired_challenges(&mut guard, now);
                let challenge = guard
                    .remove(challenge_id)
                    .ok_or(ChallengeStoreError::NotFoundOrExpired)?;
                validate_challenge(&challenge, peer_id, now)
            }
            Self::Redis(client) => {
                let key = redis_challenge_key(challenge_id);
                let mut conn = client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(|e| ChallengeStoreError::RedisConnection(e.to_string()))?;
                let payload: Option<String> = redis::Script::new(
                    "local v=redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); end; return v",
                )
                .key(key)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| ChallengeStoreError::RedisOperation(e.to_string()))?;
                let payload = payload.ok_or(ChallengeStoreError::NotFoundOrExpired)?;
                let challenge: PendingChallenge = serde_json::from_str(&payload)
                    .map_err(|e| ChallengeStoreError::Serialize(e.to_string()))?;
                validate_challenge(&challenge, peer_id, now)
            }
        }
    }
}

fn unix_now_secs() -> Result<u64, ChallengeStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ChallengeStoreError::Clock(e.to_string()))
}

fn prune_expired_challenges(store: &mut HashMap<String, PendingChallenge>, now: u64) {
    store.retain(|_, challenge| challenge.expires_at > now);
}

fn validate_challenge(
    challenge: &PendingChallenge,
    peer_id: &str,
    now: u64,
) -> Result<[u8; 32], ChallengeStoreError> {
    if challenge.peer_id != peer_id {
        return Err(ChallengeStoreError::PeerMismatch);
    }
    if challenge.expires_at <= now {
        return Err(ChallengeStoreError::Expired);
    }
    Ok(challenge.nonce)
}

fn redis_challenge_key(challenge_id: &str) -> String {
    format!("mero-kms-phala:challenge:{}", challenge_id)
}
