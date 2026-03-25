//! Challenge storage abstraction used by `/challenge` and `/get-key`.
//!
//! Supports in-memory mode for local/dev and Redis-backed mode for shared,
//! multi-instance deployments.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::unix_now_secs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub peer_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Error)]
pub enum ChallengeStoreError {
    #[error("invalid redis url: {0}")]
    InvalidRedisUrl(String),
    #[error("challenge store lock poisoned")]
    LockPoisoned,
    #[error("system clock error: {0}")]
    Clock(String),
    #[error("challenge serialization error: {0}")]
    Serialize(String),
    #[error("redis connection failed: {0}")]
    RedisConnection(String),
    #[error("redis operation failed: {0}")]
    RedisOperation(String),
    #[error("challenge store capacity exceeded")]
    CapacityExceeded,
    #[error("challenge not found or expired")]
    NotFoundOrExpired,
    #[error("challenge peer mismatch")]
    PeerMismatch,
    #[error("challenge has expired")]
    Expired,
}

/// Atomic insert with capacity check. Prunes expired entries from the sorted-set
/// index first, then checks pending count against `max_pending`. Returns the new
/// count on success or -1 if capacity is exceeded.
const REDIS_INSERT_SCRIPT: &str = r#"
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
"#;

/// Atomic consume (get + delete). Prunes expired entries, then fetches and
/// removes the challenge in a single round-trip to guarantee single-use semantics
/// even under concurrent requests.
const REDIS_CONSUME_SCRIPT: &str = r#"
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
"#;

#[derive(Clone)]
pub enum ChallengeStore {
    InMemory(Arc<Mutex<HashMap<String, PendingChallenge>>>),
    Redis(redis::Client),
}

impl ChallengeStore {
    /// Initialize storage backend from optional Redis URL.
    /// Falls back to in-memory storage when URL is absent.
    pub fn from_redis_url(redis_url: Option<&str>) -> Result<Self, ChallengeStoreError> {
        if let Some(url) = redis_url {
            let client = redis::Client::open(url)
                .map_err(|e| ChallengeStoreError::InvalidRedisUrl(e.to_string()))?;
            Ok(Self::Redis(client))
        } else {
            Ok(Self::InMemory(Arc::new(Mutex::new(HashMap::new()))))
        }
    }

    /// Insert a pending challenge with TTL/capacity enforcement.
    pub async fn insert(
        &self,
        challenge_id: String,
        challenge: PendingChallenge,
        ttl_secs: u64,
        max_pending_challenges: usize,
    ) -> Result<(), ChallengeStoreError> {
        let now = unix_now_secs().map_err(|e| ChallengeStoreError::Clock(e.to_string()))?;
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
                let pending_after_insert: i64 = redis::Script::new(REDIS_INSERT_SCRIPT)
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

    /// Consume and validate a challenge (single-use semantics).
    pub async fn consume(
        &self,
        challenge_id: &str,
        peer_id: &str,
    ) -> Result<[u8; 32], ChallengeStoreError> {
        let now = unix_now_secs().map_err(|e| ChallengeStoreError::Clock(e.to_string()))?;
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
                let payload: Option<String> = redis::Script::new(REDIS_CONSUME_SCRIPT)
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
