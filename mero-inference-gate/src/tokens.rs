//! Who may call `/v1`: bearer tokens whose SHA-256 the operator put in the
//! `access-token-sha256` metadata (inference-init copies it to a file).
//!
//! Tokens control who spends the GPU, not who reads prompts: TLS ends in the
//! TD, so the operator, who chooses them and sees their hashes, reads nothing
//! a client sends.

use std::collections::HashSet;

use crate::attest::sha256;

#[derive(Debug, Default, Clone)]
pub struct Tokens(HashSet<[u8; 32]>);

impl Tokens {
    /// Hex SHA-256 values separated by commas, spaces or newlines. A value
    /// that is not 32 bytes of hex is an error: a typo must not leave the
    /// gate open or silently shut.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut set = HashSet::new();
        for value in text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|v| !v.is_empty())
        {
            let bytes = hex::decode(value)
                .map_err(|_| format!("access token hash '{value}' is not hex"))?;
            let hash = <[u8; 32]>::try_from(bytes)
                .map_err(|_| format!("access token hash '{value}' is not 32 bytes"))?;
            set.insert(hash);
        }
        Ok(Self(set))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether an `Authorization` header value carries an accepted token.
    /// With no tokens, nothing is accepted.
    pub fn allows(&self, authorization: Option<&str>) -> bool {
        let Some(token) = authorization
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
        else {
            return false;
        };
        !token.is_empty() && self.0.contains(&sha256(token.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_listed_tokens() {
        let tokens = Tokens::parse(&format!(
            "{}, {}\n",
            hex::encode(sha256(b"one")),
            hex::encode(sha256(b"two"))
        ))
        .unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens.allows(Some("Bearer one")));
        assert!(tokens.allows(Some("Bearer two")));
        assert!(!tokens.allows(Some("Bearer three")));
        assert!(!tokens.allows(Some("one")));
        assert!(!tokens.allows(None));
    }

    #[test]
    fn no_tokens_accepts_nothing() {
        let tokens = Tokens::parse("").unwrap();
        assert!(tokens.is_empty());
        assert!(!tokens.allows(Some("Bearer ")));
        assert!(!tokens.allows(Some("Bearer anything")));
    }

    #[test]
    fn a_bad_hash_is_an_error() {
        assert!(Tokens::parse("abc").is_err());
        assert!(Tokens::parse(&"ab".repeat(31)).is_err());
    }
}
