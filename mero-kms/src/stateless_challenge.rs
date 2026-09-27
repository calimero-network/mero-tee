//! `/challenge` for a TDX cluster: a challenge any replica can check.
//!
//! A cluster is several replicas behind one URL, and a node's `/challenge` and
//! `/get-key` may land on different ones. Keeping pending challenges would mean
//! either sticky routing (a replica restart mid-handshake fails that node's key
//! fetch) or a shared store every replica trusts. Neither is needed: the challenge carries its own
//! expiry, and its nonce is a MAC under a key every replica derives from the
//! cluster root.
//!
//! ```text
//! challengeId = hex(random[16] ‖ expires_at as u64 big-endian)       48 hex chars
//! nonce       = HMAC-SHA256(challenge_key, DOMAIN ‖ id bytes ‖ peer_id)
//! ```
//!
//! Nothing here checks that an ID is genuine, and nothing needs to. A forged ID
//! yields a nonce its forger cannot compute, and `/get-key` then fails on the
//! peer signature and the quote, both of which must carry the real nonce.
//!
//! Replay is refused per replica, by [`SpentChallenges`]. A captured request
//! replayed at a *different* replica within the TTL gets past this check, and
//! gains nothing from it: the response is sealed to the requesting node's key
//! (`MERO_KMS_REQUIRE_SEALED_KEY_RELEASE`), and the request is signed by it.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::random;
use ring::hmac;

use crate::backend::KEY_LEN;
use crate::handlers::errors::ServiceError;

const DOMAIN: &[u8] = b"mero-kms/tdx-challenge/v1\0";
const RANDOM_BYTES: usize = 16;
const ID_BYTES: usize = RANDOM_BYTES + 8;

/// Length of a hex-encoded stateless challenge ID.
pub(crate) const ID_HEX_LEN: usize = ID_BYTES * 2;

/// How far a challenge's expiry may sit past `now + ttl` and still be one this
/// cluster issued. Replicas are separate VMs, and one whose clock runs a little
/// behind the issuer's would otherwise refuse a challenge that is still fresh.
const CLOCK_SKEW_SECS: u64 = 30;

/// Issue a challenge for `peer_id`, valid until `expires_at`.
pub(crate) fn issue(key: &[u8; KEY_LEN], peer_id: &str, expires_at: u64) -> (String, [u8; 32]) {
    let mut id = [0u8; ID_BYTES];
    id[..RANDOM_BYTES].copy_from_slice(&random::<[u8; RANDOM_BYTES]>());
    id[RANDOM_BYTES..].copy_from_slice(&expires_at.to_be_bytes());
    (hex::encode(id), nonce(key, &id, peer_id))
}

/// Recover the nonce and expiry of `challenge_id` as issued to `peer_id`.
///
/// Refuses an ID that is malformed, expired, or expires later than any this
/// cluster would have issued at `now` with `ttl_secs`.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    challenge_id: &str,
    peer_id: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<([u8; 32], u64), ServiceError> {
    let id: [u8; ID_BYTES] = hex::decode(challenge_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ServiceError::InvalidChallenge(format!(
                "challenge ID must be {ID_HEX_LEN} hex characters"
            ))
        })?;
    let mut expiry = [0u8; 8];
    expiry.copy_from_slice(&id[RANDOM_BYTES..]);
    let expires_at = u64::from_be_bytes(expiry);
    if expires_at < now {
        return Err(ServiceError::InvalidChallenge(
            "Challenge validation failed: challenge expired".to_owned(),
        ));
    }
    if expires_at > now.saturating_add(ttl_secs).saturating_add(CLOCK_SKEW_SECS) {
        return Err(ServiceError::InvalidChallenge(
            "Challenge validation failed: challenge expires later than this KMS issues".to_owned(),
        ));
    }
    Ok((nonce(key, &id, peer_id), expires_at))
}

fn nonce(key: &[u8; KEY_LEN], id: &[u8; ID_BYTES], peer_id: &str) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(DOMAIN);
    // The ID is fixed-length, so the peer ID that follows it is unambiguous.
    ctx.update(id);
    ctx.update(peer_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// Challenge IDs this replica has already accepted at `/get-key`, each kept
/// until it expires.
#[derive(Default)]
pub(crate) struct SpentChallenges(Mutex<HashMap<String, u64>>);

impl SpentChallenges {
    /// Record `challenge_id` as used, or refuse it if it already was. Refuses
    /// with a rate limit once `capacity` unexpired IDs are held
    /// (`MAX_CONSUMED_CHALLENGES`).
    pub(crate) fn spend(
        &self,
        challenge_id: &str,
        expires_at: u64,
        now: u64,
        capacity: usize,
    ) -> Result<(), ServiceError> {
        let mut spent = self.0.lock().map_err(|_| {
            ServiceError::InvalidChallenge("spent-challenge lock poisoned".to_owned())
        })?;
        spent.retain(|_, expiry| *expiry >= now);
        if spent.contains_key(challenge_id) {
            return Err(ServiceError::InvalidChallenge(
                "Challenge validation failed: challenge already used".to_owned(),
            ));
        }
        if spent.len() >= capacity {
            return Err(ServiceError::RateLimited(
                "Too many recent key requests. Retry shortly.".to_owned(),
            ));
        }
        spent.insert(challenge_id.to_owned(), expires_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [9; KEY_LEN];
    const PEER: &str = "12D3KooWPeer";
    const NOW: u64 = 1_000_000;
    const TTL: u64 = 60;

    #[test]
    fn a_challenge_opens_to_the_nonce_it_was_issued_with() {
        let (id, issued) = issue(&KEY, PEER, NOW + TTL);
        assert_eq!(id.len(), ID_HEX_LEN);
        let (opened, expires_at) = open(&KEY, &id, PEER, NOW, TTL).unwrap();
        assert_eq!(opened, issued);
        assert_eq!(expires_at, NOW + TTL);
    }

    /// The property that makes a replica's challenge good on every other one.
    #[test]
    fn another_holder_of_the_key_opens_it_too() {
        let (id, issued) = issue(&KEY, PEER, NOW + TTL);
        let other_replica_key = KEY;
        assert_eq!(
            open(&other_replica_key, &id, PEER, NOW + 5, TTL).unwrap().0,
            issued
        );
    }

    #[test]
    fn the_nonce_is_bound_to_the_peer_the_key_and_the_expiry() {
        let (id, issued) = issue(&KEY, PEER, NOW + TTL);
        assert_ne!(
            open(&KEY, &id, "12D3KooWOther", NOW, TTL).unwrap().0,
            issued
        );
        assert_ne!(open(&[1; KEY_LEN], &id, PEER, NOW, TTL).unwrap().0, issued);

        // Moving the expiry changes the nonce, so a stretched challenge is a
        // different, unanswerable one.
        let mut bytes = hex::decode(&id).unwrap();
        bytes[ID_BYTES - 1] ^= 1;
        let stretched = hex::encode(bytes);
        assert_ne!(open(&KEY, &stretched, PEER, NOW, TTL).unwrap().0, issued);
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let (id, _) = issue(&KEY, PEER, NOW - 1);
        assert!(matches!(
            open(&KEY, &id, PEER, NOW, TTL),
            Err(ServiceError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn an_expiry_beyond_the_ttl_is_refused_and_small_skew_is_not() {
        let (skewed, _) = issue(&KEY, PEER, NOW + TTL + CLOCK_SKEW_SECS);
        assert!(open(&KEY, &skewed, PEER, NOW, TTL).is_ok());
        let (far, _) = issue(&KEY, PEER, NOW + TTL + CLOCK_SKEW_SECS + 1);
        assert!(matches!(
            open(&KEY, &far, PEER, NOW, TTL),
            Err(ServiceError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn a_malformed_id_is_refused() {
        for id in ["", "zz", &"a".repeat(32), &"a".repeat(ID_HEX_LEN + 2)] {
            assert!(matches!(
                open(&KEY, id, PEER, NOW, TTL),
                Err(ServiceError::InvalidChallenge(_))
            ));
        }
    }

    #[test]
    fn a_spent_challenge_is_refused_until_it_expires() {
        let spent = SpentChallenges::default();
        spent.spend("a", NOW + TTL, NOW, 10).unwrap();
        assert!(matches!(
            spent.spend("a", NOW + TTL, NOW + 1, 10),
            Err(ServiceError::InvalidChallenge(_))
        ));
        // Once expired it is pruned; `open` refuses it by then anyway.
        spent.spend("a", NOW + 2 * TTL, NOW + TTL + 1, 10).unwrap();
    }

    #[test]
    fn a_full_cache_rate_limits_and_frees_as_entries_expire() {
        let spent = SpentChallenges::default();
        spent.spend("a", NOW + 1, NOW, 1).unwrap();
        assert!(matches!(
            spent.spend("b", NOW + 1, NOW, 1),
            Err(ServiceError::RateLimited(_))
        ));
        spent.spend("b", NOW + 10, NOW + 2, 1).unwrap();
    }
}
