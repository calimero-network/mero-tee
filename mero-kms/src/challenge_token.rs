//! Stateless `/challenge` tokens.
//!
//! Every replica of a cluster answers behind one load-balanced URL, so the
//! replica that serves a node's `/get-key` is rarely the one that served its
//! `/challenge`, and replicas share no storage. The challenge therefore carries
//! everything needed to check it, authenticated with a key only the cluster
//! holds. The token is the `challengeId` merod already echoes back unchanged:
//! lowercase hex of [`TOKEN_LEN`] bytes,
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0 | 32 | `nonce`: random; the `nonceB64` the node's quote must carry |
//! | 32 | 8 | `expires_at`: unix seconds, big-endian |
//! | 40 | 32 | `tag`: HMAC-SHA256(`challenge_key`, [`TAG_DOMAIN`] ‖ `nonce` ‖ `expires_at` ‖ `peer_id`) |
//!
//! where `challenge_key` is HKDF-SHA256 of the cluster root at
//! [`crate::backend::CHALLENGE_KEY_PATH`]. The peer id is not in the token, only
//! under its tag, so a token verifies only for the peer that asked for it.
//!
//! Single use holds per replica: each replica remembers the nonces it consumed
//! until they expire ([`ReplayGuard`]). The same request sent to a second
//! replica within the TTL can pass its challenge check there, but it still
//! needs the node's signature and quote, and the key it releases is sealed to
//! the node's one-time key, which the replayer does not hold.

use std::collections::HashMap;
use std::sync::Mutex;

use ring::hmac;
use thiserror::Error;

/// Domain separator under every token's tag.
const TAG_DOMAIN: &[u8] = b"mero-kms/challenge-token/v1";

const NONCE_LEN: usize = 32;
const EXPIRY_LEN: usize = 8;
const TAG_LEN: usize = 32;

/// Length of a token in bytes, before hex encoding.
pub(crate) const TOKEN_LEN: usize = NONCE_LEN + EXPIRY_LEN + TAG_LEN;

/// Why a token was refused.
#[derive(Debug, Error)]
pub(crate) enum ChallengeError {
    #[error("challenge ID must be {} hex characters", TOKEN_LEN * 2)]
    Malformed,
    #[error("challenge was not issued by this cluster for this peer")]
    BadTag,
    #[error("challenge has expired")]
    Expired,
    #[error("challenge was already used")]
    Replayed,
    #[error("too many recently used challenges; retry shortly")]
    CapacityExceeded,
    #[error("challenge replay set lock poisoned")]
    LockPoisoned,
}

/// A freshly issued challenge.
pub(crate) struct Challenge {
    /// The `challengeId` to hand to the node.
    pub token: String,
    pub nonce: [u8; NONCE_LEN],
}

/// A token whose tag and expiry checked out.
#[derive(Debug)]
pub(crate) struct Verified {
    pub nonce: [u8; NONCE_LEN],
    pub expires_at: u64,
}

/// What a token's tag covers.
fn tagged_message(nonce: &[u8; NONCE_LEN], expires_at: u64, peer_id: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(TAG_DOMAIN.len() + NONCE_LEN + EXPIRY_LEN + peer_id.len());
    message.extend_from_slice(TAG_DOMAIN);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&expires_at.to_be_bytes());
    message.extend_from_slice(peer_id.as_bytes());
    message
}

/// Issue a challenge for `peer_id` that expires at `expires_at`.
pub(crate) fn issue(key: &hmac::Key, peer_id: &str, expires_at: u64) -> Challenge {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut token = Vec::with_capacity(TOKEN_LEN);
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&expires_at.to_be_bytes());
    token.extend_from_slice(hmac::sign(key, &tagged_message(&nonce, expires_at, peer_id)).as_ref());
    Challenge {
        token: hex::encode(token),
        nonce,
    }
}

/// Check that `token` was issued under `key` for `peer_id` and has not expired
/// at `now`. Does not consume it; see [`ReplayGuard::consume`].
pub(crate) fn verify(
    key: &hmac::Key,
    token: &str,
    peer_id: &str,
    now: u64,
) -> Result<Verified, ChallengeError> {
    if token.len() != TOKEN_LEN * 2 {
        return Err(ChallengeError::Malformed);
    }
    let raw = hex::decode(token).map_err(|_| ChallengeError::Malformed)?;
    let (nonce, rest) = raw.split_at(NONCE_LEN);
    let (expiry, tag_bytes) = rest.split_at(EXPIRY_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| ChallengeError::Malformed)?;
    let expires_at = u64::from_be_bytes(expiry.try_into().map_err(|_| ChallengeError::Malformed)?);

    // Constant-time comparison.
    hmac::verify(key, &tagged_message(&nonce, expires_at, peer_id), tag_bytes)
        .map_err(|_| ChallengeError::BadTag)?;

    if expires_at <= now {
        return Err(ChallengeError::Expired);
    }
    Ok(Verified { nonce, expires_at })
}

/// The nonces this replica consumed, each kept until its token expires.
pub(crate) struct ReplayGuard {
    consumed: Mutex<HashMap<[u8; NONCE_LEN], u64>>,
    capacity: usize,
}

impl ReplayGuard {
    /// Remember at most `capacity` unexpired consumed challenges. Past that,
    /// [`Self::consume`] refuses rather than forgets one early.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            consumed: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Mark `challenge` used. Fails if this replica already consumed it.
    pub(crate) fn consume(&self, challenge: &Verified, now: u64) -> Result<(), ChallengeError> {
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| ChallengeError::LockPoisoned)?;
        consumed.retain(|_, expires_at| *expires_at > now);
        if consumed.contains_key(&challenge.nonce) {
            return Err(ChallengeError::Replayed);
        }
        if consumed.len() >= self.capacity {
            return Err(ChallengeError::CapacityExceeded);
        }
        let _ = consumed.insert(challenge.nonce, challenge.expires_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{test_tdx_backend, Root, KEY_LEN};

    const PEER: &str = "12D3KooWPeer";
    const NOW: u64 = 1_800_000_000;

    /// The challenge key of a replica holding the root `[seed; 32]`.
    fn replica_key(seed: u8) -> hmac::Key {
        test_tdx_backend(Some(Root::from_bytes(&[seed; KEY_LEN]).unwrap()))
            .challenge_key()
            .unwrap()
    }

    #[test]
    fn a_token_issued_by_one_replica_verifies_on_another_of_the_same_cluster() {
        let challenge = issue(&replica_key(7), PEER, NOW + 60);
        assert_eq!(challenge.token.len(), TOKEN_LEN * 2);
        let verified = verify(&replica_key(7), &challenge.token, PEER, NOW).unwrap();
        assert_eq!(verified.nonce, challenge.nonce);
        assert_eq!(verified.expires_at, NOW + 60);
    }

    #[test]
    fn a_token_from_another_cluster_is_refused() {
        let challenge = issue(&replica_key(7), PEER, NOW + 60);
        assert!(matches!(
            verify(&replica_key(8), &challenge.token, PEER, NOW),
            Err(ChallengeError::BadTag)
        ));
    }

    #[test]
    fn a_token_verifies_only_for_its_peer() {
        let key = replica_key(7);
        let challenge = issue(&key, PEER, NOW + 60);
        assert!(matches!(
            verify(&key, &challenge.token, "12D3KooWOther", NOW),
            Err(ChallengeError::BadTag)
        ));
    }

    #[test]
    fn a_tampered_token_is_refused() {
        let key = replica_key(7);
        let challenge = issue(&key, PEER, NOW + 60);
        let raw = hex::decode(&challenge.token).unwrap();
        // One flipped bit in each field: the nonce, the expiry, the tag.
        for index in [0, NONCE_LEN + EXPIRY_LEN - 1, TOKEN_LEN - 1] {
            let mut tampered = raw.clone();
            tampered[index] ^= 1;
            assert!(
                matches!(
                    verify(&key, &hex::encode(tampered), PEER, NOW),
                    Err(ChallengeError::BadTag)
                ),
                "byte {index} was flipped but the token verified"
            );
        }
    }

    #[test]
    fn a_malformed_token_is_refused() {
        let key = replica_key(7);
        assert!(matches!(
            verify(&key, "abc", PEER, NOW),
            Err(ChallengeError::Malformed)
        ));
        assert!(matches!(
            verify(&key, &"z".repeat(TOKEN_LEN * 2), PEER, NOW),
            Err(ChallengeError::Malformed)
        ));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let key = replica_key(7);
        let challenge = issue(&key, PEER, NOW);
        assert!(matches!(
            verify(&key, &challenge.token, PEER, NOW),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn a_token_is_consumed_once_per_replica() {
        let key = replica_key(7);
        let challenge = issue(&key, PEER, NOW + 60);
        let verified = verify(&key, &challenge.token, PEER, NOW).unwrap();
        let replica = ReplayGuard::new(10);
        replica.consume(&verified, NOW).unwrap();
        assert!(matches!(
            replica.consume(&verified, NOW),
            Err(ChallengeError::Replayed)
        ));
    }

    #[test]
    fn the_replay_set_is_bounded_and_forgets_only_expired_entries() {
        let key = replica_key(7);
        let replica = ReplayGuard::new(1);
        let first = verify(&key, &issue(&key, PEER, NOW + 10).token, PEER, NOW).unwrap();
        let second = verify(&key, &issue(&key, PEER, NOW + 60).token, PEER, NOW).unwrap();
        replica.consume(&first, NOW).unwrap();
        assert!(matches!(
            replica.consume(&second, NOW),
            Err(ChallengeError::CapacityExceeded)
        ));
        // Once the first expires it no longer takes a slot.
        replica.consume(&second, NOW + 10).unwrap();
    }
}
