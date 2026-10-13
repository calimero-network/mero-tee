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

/// Who besides the gate may read what it writes. The gate runs as root, because
/// a configfs-tsm quote needs root; the agent runs as its own user and reads
/// the signing key and secrets through its group. Nobody else reads them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Share {
    /// The agent's group; `None` keeps everything owner-only.
    pub gid: Option<u32>,
}

impl Share {
    /// The group named `name` in /etc/group.
    pub fn group(name: &str) -> EyreResult<Self> {
        let groups = std::fs::read_to_string("/etc/group").wrap_err("could not read /etc/group")?;
        let gid = groups
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let group = fields.next()?;
                let gid = fields.nth(1)?.parse::<u32>().ok()?;
                (group == name).then_some(gid)
            })
            .next()
            .ok_or_else(|| eyre::eyre!("no group '{name}' in /etc/group"))?;
        Ok(Self { gid: Some(gid) })
    }

    pub fn file_mode(self) -> u32 {
        if self.gid.is_some() {
            0o640
        } else {
            0o600
        }
    }

    pub fn dir_mode(self) -> u32 {
        if self.gid.is_some() {
            0o750
        } else {
            0o700
        }
    }

    /// Give `path` to the agent's group, if there is one.
    pub fn apply(self, path: &Path) -> std::io::Result<()> {
        match self.gid {
            Some(gid) => std::os::unix::fs::chown(path, None, Some(gid)),
            None => Ok(()),
        }
    }
}

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
/// boot. The file holds the 32-byte Ed25519 seed, readable by its owner and,
/// with a [`Share`] group, by the agent (0640); never by anyone else.
///
/// Created with `create_new`, so two starts racing cannot each write a key and
/// leave the agent with one the gate never attested.
pub fn load_or_create_signing_key(path: &Path, share: Share) -> EyreResult<SigningKey> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let seed: &[u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| eyre::eyre!("{} is not a 32-byte Ed25519 seed", path.display()))?;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            // Others nothing; the group at most reads.
            if mode & 0o037 != 0 {
                bail!(
                    "{} is mode {mode:o}; the signing key must be readable by its owner \
                     and the agent's group only",
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
                .mode(share.file_mode())
                .open(path)
                .wrap_err_with(|| format!("could not create {}", path.display()))?;
            share.apply(path)?;
            file.write_all(seed.as_ref())?;
            file.sync_all()?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) => Err(e).wrap_err_with(|| format!("could not read {}", path.display())),
    }
}

/// The owner of this agent, if it has been claimed: the X25519 public key in
/// `path` (32 raw bytes), on the encrypted disk.
pub fn load_owner(path: &Path) -> EyreResult<Option<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| eyre::eyre!("{} is not a 32-byte X25519 key", path.display()))?;
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).wrap_err_with(|| format!("could not read {}", path.display())),
    }
}

/// Record `owner` as this agent's owner, once. `create_new`, so a claim can
/// never be overwritten, not even by a second claim racing the first across a
/// restart; durable before the call returns, so a claim the owner was told
/// about survives a crash.
pub fn store_owner(path: &Path, share: Share, owner: &[u8; 32]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(share.file_mode())
        .open(path)?;
    share.apply(path)?;
    file.write_all(owner)?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn the_signing_key_is_created_once_and_reloaded() {
        let dir = TempDir::new("signing");
        let path = dir.path().join("signing.ed25519");
        let first = load_or_create_signing_key(&path, Share::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let second = load_or_create_signing_key(&path, Share::default()).unwrap();
        assert_eq!(first.verifying_key(), second.verifying_key());
    }

    #[test]
    fn a_shared_signing_key_is_group_readable_by_the_agent_only() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new("signing-share");
        // A group this process may give files to: the directory's own.
        let share = Share {
            gid: Some(std::fs::metadata(dir.path()).unwrap().gid()),
        };
        let path = dir.path().join("signing.ed25519");
        let first = load_or_create_signing_key(&path, share).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);
        assert_eq!(Some(meta.gid()), share.gid);
        let again = load_or_create_signing_key(&path, share).unwrap();
        assert_eq!(first.verifying_key(), again.verifying_key());
    }

    #[test]
    fn a_group_is_found_in_etc_group() {
        let share = Share::group("root").expect("every system has a root group");
        assert_eq!(share.gid, Some(0));
        assert!(Share::group("no-such-group-mero").is_err());
    }

    #[test]
    fn a_readable_signing_key_is_refused() {
        let dir = TempDir::new("signing-mode");
        let path = dir.path().join("signing.ed25519");
        load_or_create_signing_key(&path, Share::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_or_create_signing_key(&path, Share::default()).unwrap_err();
        assert!(err.to_string().contains("owner"), "{err}");
    }

    #[test]
    fn an_owner_is_stored_once_and_reloaded() {
        let dir = TempDir::new("owner");
        let path = dir.path().join("owner.x25519");
        assert_eq!(load_owner(&path).unwrap(), None);
        store_owner(&path, Share::default(), &[7; 32]).unwrap();
        assert_eq!(load_owner(&path).unwrap(), Some([7; 32]));
        let err = store_owner(&path, Share::default(), &[8; 32]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            load_owner(&path).unwrap(),
            Some([7; 32]),
            "a claim is never overwritten"
        );
    }

    #[test]
    fn each_start_has_its_own_provisioning_key() {
        assert_ne!(
            ProvisioningKey::generate().public,
            ProvisioningKey::generate().public
        );
    }
}
