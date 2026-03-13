use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
    CapacityExceeded,
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
            Self::CapacityExceeded => write!(f, "challenge store capacity exceeded"),
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
        max_pending_challenges: usize,
    ) -> Result<(), ChallengeStoreError> {
        let now = unix_now_secs()?;
        match self {
            Self::InMemory(store) => {
                let mut guard = store
                    .lock()
                    .map_err(|_| ChallengeStoreError::LockPoisoned)?;
                prune_expired_challenges(&mut guard, now);
                if guard.len() >= max_pending_challenges {
                    return Err(ChallengeStoreError::CapacityExceeded);
                }
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
                let pending_after_insert: i64 = redis::Script::new(
                    r#"
                    local challenge_key = KEYS[1]
                    local index_key = KEYS[2]
                    local payload = ARGV[1]
                    local ttl = tonumber(ARGV[2])
                    local expires_at = tonumber(ARGV[3])
                    local now = tonumber(ARGV[4])
                    local max_pending = tonumber(ARGV[5])
                    redis.call('ZREMRANGEBYSCORE', index_key, '-inf', now)
                    local pending = redis.call('ZCARD', index_key)
                    if pending >= max_pending then
                      return -1
                    end
                    redis.call('SET', challenge_key, payload, 'EX', ttl)
                    redis.call('ZADD', index_key, expires_at, challenge_key)
                    return pending + 1
                    "#,
                )
                .key(key)
                .key(redis_challenge_index_key())
                .arg(payload)
                .arg(ttl_secs)
                .arg(challenge.expires_at)
                .arg(now)
                .arg(max_pending_challenges as i64)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| ChallengeStoreError::RedisOperation(e.to_string()))?;
                if pending_after_insert < 0 {
                    return Err(ChallengeStoreError::CapacityExceeded);
                }
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
                    r#"
                    local challenge_key = KEYS[1]
                    local index_key = KEYS[2]
                    local now = tonumber(ARGV[1])
                    redis.call('ZREMRANGEBYSCORE', index_key, '-inf', now)
                    local v = redis.call('GET', challenge_key)
                    if v then
                      redis.call('DEL', challenge_key)
                      redis.call('ZREM', index_key, challenge_key)
                    end
                    return v
                    "#,
                )
                .key(key)
                .key(redis_challenge_index_key())
                .arg(now)
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

fn redis_challenge_index_key() -> &'static str {
    "mero-kms-phala:challenge:index"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_insert_respects_max_pending_capacity() {
        let store = ChallengeStore::from_redis_url(None).expect("store should initialize");
        let now = unix_now_secs().expect("clock should be available");
        let challenge = PendingChallenge {
            nonce: [1u8; 32],
            peer_id: "12D3KooWPeer".to_string(),
            expires_at: now + 60,
        };

        store
            .insert("challenge-1".to_string(), challenge.clone(), 60, 1)
            .await
            .expect("first challenge should fit");
        let err = store
            .insert("challenge-2".to_string(), challenge, 60, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, ChallengeStoreError::CapacityExceeded));
    }
}
