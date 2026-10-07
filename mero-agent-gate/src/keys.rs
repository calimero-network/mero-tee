//! The gate's keys: an in-memory provisioning key per start, and the agent's
//! signing key, generated once in the TD and kept on the encrypted disk.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ed25519_dalek::SigningKey;
use eyre::{bail, Result as EyreResult, WrapErr};
use rand_core::{OsRng, RngCore, UnwrapErr};
use zeroize::Zeroizing;

use crate::protocol::{keypair_from_secret, PrivateKey};

/// The OS RNG, as the `RngCore` hpke takes. It panics if the OS has no
/// randomness to give, which inside a TD is not a state to carry on in.
pub fn os_rng() -> UnwrapErr<OsRng> {
    UnwrapErr(OsRng)
}

pub fn random_32() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    os_rng().fill_bytes(bytes.as_mut());
    bytes
}

/// The HPKE key secrets are sealed to. Made fresh at every start and held only
/// in memory: a message sealed to it opens in this process or nowhere.
pub struct ProvisioningKey {
    pub private: PrivateKey,
    pub public: [u8; 32],
}

impl ProvisioningKey {
    pub fn generate() -> Self {
        let (private, public) =
            keypair_from_secret(&random_32()).expect("any 32 bytes are an X25519 secret");
        Self { private, public }
    }
}

/// Load the agent's signing key from `path`, or create it there on the first
/// boot. The file holds the 32-byte Ed25519 seed, mode 0600.
///
/// Created with `create_new`, so two starts racing cannot each write a key and
/// leave the agent with one the gate never attested.
pub fn load_or_create_signing_key(path: &Path) -> EyreResult<SigningKey> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let seed: &[u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| eyre::eyre!("{} is not a 32-byte Ed25519 seed", path.display()))?;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                bail!(
                    "{} is mode {mode:o}; the signing key must be readable by its owner only",
                    path.display()
                );
            }
            Ok(SigningKey::from_bytes(seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let seed = random_32();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .wrap_err_with(|| format!("could not create {}", path.display()))?;
            file.write_all(seed.as_ref())?;
            file.sync_all()?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) => Err(e).wrap_err_with(|| format!("could not read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn the_signing_key_is_created_once_and_reloaded() {
        let dir = TempDir::new("signing");
        let path = dir.path().join("signing.ed25519");
        let first = load_or_create_signing_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let second = load_or_create_signing_key(&path).unwrap();
        assert_eq!(first.verifying_key(), second.verifying_key());
    }

    #[test]
    fn a_readable_signing_key_is_refused() {
        let dir = TempDir::new("signing-mode");
        let path = dir.path().join("signing.ed25519");
        load_or_create_signing_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_or_create_signing_key(&path).unwrap_err();
        assert!(err.to_string().contains("owner only"), "{err}");
    }

    #[test]
    fn each_start_has_its_own_provisioning_key() {
        assert_ne!(
            ProvisioningKey::generate().public,
            ProvisioningKey::generate().public
        );
    }
}
