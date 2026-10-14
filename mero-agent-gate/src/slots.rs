//! The agents a TD hosts, one per slot.
//!
//! The image bakes a fixed number of slots, each with its own Unix user and
//! group (`mero-agent-<n>`) and its own directory on the encrypted disk:
//!
//! ```text
//! agents/<n>/          root:mero-agent-<n> 0750
//!   id                 the agent id that claimed the slot; written last, so
//!                      a slot is claimed exactly when this file exists
//!   keys/owner.x25519  the owner's X25519 public key
//!   keys/signing.ed25519  the agent's Ed25519 seed
//!   secrets/<NAME>     what the owner provisioned
//!   state/             the agent's own files, writable by its user only
//! ```
//!
//! Keys and secrets are readable by the gate (root) and the slot's group, and
//! by no other agent. A slot without an `id` is free: whatever an interrupted
//! claim or release left in it is erased before anyone else gets it.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use eyre::{bail, Result as EyreResult, WrapErr};

use crate::keys::{load_or_create_signing_key, load_owner, store_owner, Share};
use crate::protocol::validate_agent_id;

/// Who holds a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub agent_id: String,
    pub owner: [u8; 32],
    pub signing_public: [u8; 32],
}

/// One agent's place on the TD.
#[derive(Debug)]
pub struct Slot {
    /// 1-based; the agent's user is `mero-agent-<number>`.
    pub number: u32,
    pub dir: PathBuf,
    /// The slot's group, which its agent reads keys and secrets through.
    pub share: Share,
    pub claim: Option<Claim>,
    /// Whether a bundle was written to it since this start.
    pub provisioned: bool,
}

impl Slot {
    pub fn keys_dir(&self) -> PathBuf {
        self.dir.join("keys")
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.dir.join("secrets")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }

    /// What the operator wrote (`/operator`): apart from the owner's
    /// `secrets/`, so neither can overwrite the other's.
    pub fn operator_dir(&self) -> PathBuf {
        self.dir.join("operator")
    }

    fn id_path(&self) -> PathBuf {
        self.dir.join("id")
    }

    fn owner_path(&self) -> PathBuf {
        self.keys_dir().join("owner.x25519")
    }

    fn signing_path(&self) -> PathBuf {
        self.keys_dir().join("signing.ed25519")
    }

    /// Open slot `number` at `dir`, making its directories if they are missing,
    /// and read who holds it. A slot an interrupted claim or release left
    /// without an `id` is erased: it is free.
    pub fn open(number: u32, dir: PathBuf, share: Share) -> EyreResult<Self> {
        let mut slot = Self {
            number,
            dir,
            share,
            claim: None,
            provisioned: false,
        };
        private_dir(&slot.dir, share)?;
        private_dir(&slot.keys_dir(), share)?;
        private_dir(&slot.secrets_dir(), share)?;
        private_dir(&slot.operator_dir(), share)?;
        // agent-init makes state/ and gives it to the slot's user; the gate
        // only ever empties it.
        std::fs::create_dir_all(slot.state_dir())
            .wrap_err_with(|| format!("{}", slot.state_dir().display()))?;

        match std::fs::read_to_string(slot.id_path()) {
            Ok(id) => {
                let agent_id = id.trim().to_owned();
                validate_agent_id(&agent_id).map_err(|e| eyre::eyre!("slot {number}: {e}"))?;
                let owner = load_owner(&slot.owner_path())?.ok_or_else(|| {
                    eyre::eyre!("slot {number} is claimed by '{agent_id}' but has no owner key")
                })?;
                if !slot.signing_path().exists() {
                    bail!("slot {number} is claimed by '{agent_id}' but has no signing key");
                }
                let signing = load_or_create_signing_key(&slot.signing_path(), share)?;
                slot.claim = Some(Claim {
                    agent_id,
                    owner,
                    signing_public: signing.verifying_key().to_bytes(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => slot.erase()?,
            Err(e) => {
                return Err(e).wrap_err_with(|| format!("{}", slot.id_path().display()));
            }
        }
        Ok(slot)
    }

    /// Erase everything in the slot but its directories: keys, secrets, state.
    fn erase(&self) -> EyreResult<()> {
        for dir in [
            self.keys_dir(),
            self.secrets_dir(),
            self.operator_dir(),
            self.state_dir(),
        ] {
            empty_dir(&dir)?;
        }
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// Claim this free slot for `agent_id` and `owner`: a fresh signing key,
    /// the owner, and last the `id`, each durable before the next, so a crash
    /// leaves either a free slot or a whole claim.
    pub fn claim(&mut self, agent_id: &str, owner: &[u8; 32]) -> EyreResult<Claim> {
        if let Some(claim) = &self.claim {
            bail!("slot {} is held by '{}'", self.number, claim.agent_id);
        }
        validate_agent_id(agent_id).map_err(|e| eyre::eyre!(e))?;
        self.erase()?;
        let signing = load_or_create_signing_key(&self.signing_path(), self.share)?;
        store_owner(&self.owner_path(), self.share, owner)
            .wrap_err_with(|| format!("{}", self.owner_path().display()))?;
        write_new(&self.id_path(), self.share, agent_id.as_bytes())?;
        let claim = Claim {
            agent_id: agent_id.to_owned(),
            owner: *owner,
            signing_public: signing.verifying_key().to_bytes(),
        };
        self.claim = Some(claim.clone());
        self.provisioned = false;
        Ok(claim)
    }

    /// Free the slot: the `id` goes first, so from then on it is free even if
    /// the rest is interrupted, and the next open or claim finishes erasing it.
    pub fn release(&mut self) -> EyreResult<()> {
        match std::fs::remove_file(self.id_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).wrap_err_with(|| format!("{}", self.id_path().display())),
        }
        sync_dir(&self.dir)?;
        self.claim = None;
        self.provisioned = false;
        self.erase()
    }
}

/// Open slots `1..=count` under `agents_dir`, each shared with the group
/// `<group_prefix><n>` (no group when the prefix is empty, as in tests). Two
/// slots claimed by one agent id is a corrupt disk, and refused.
pub fn open_slots(agents_dir: &Path, count: u32, group_prefix: &str) -> EyreResult<Vec<Slot>> {
    if count == 0 {
        bail!("an agent TD needs at least one slot");
    }
    std::fs::create_dir_all(agents_dir).wrap_err_with(|| format!("{}", agents_dir.display()))?;
    // Every slot's user passes through to its own directory; none lists the others.
    std::fs::set_permissions(agents_dir, std::fs::Permissions::from_mode(0o711))
        .wrap_err_with(|| format!("{}", agents_dir.display()))?;
    let mut slots: Vec<Slot> = Vec::new();
    for number in 1..=count {
        let share = if group_prefix.is_empty() {
            Share::default()
        } else {
            Share::group(&format!("{group_prefix}{number}"))?
        };
        let slot = Slot::open(number, agents_dir.join(number.to_string()), share)?;
        if let Some(claim) = &slot.claim {
            if let Some(other) = slots
                .iter()
                .find(|s| s.claim.as_ref().map(|c| &c.agent_id) == Some(&claim.agent_id))
            {
                bail!(
                    "slots {} and {number} are both claimed by '{}'",
                    other.number,
                    claim.agent_id
                );
            }
        }
        slots.push(slot);
    }
    Ok(slots)
}

/// A directory only the gate and `share`'s group may enter.
pub fn private_dir(path: &Path, share: Share) -> EyreResult<()> {
    std::fs::create_dir_all(path).wrap_err_with(|| format!("{}", path.display()))?;
    share
        .apply(path)
        .wrap_err_with(|| format!("{}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(share.dir_mode()))
        .wrap_err_with(|| format!("{}", path.display()))
}

/// Remove everything in `dir`, not `dir` itself. Symlinks are removed, never
/// followed.
fn empty_dir(dir: &Path) -> EyreResult<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).wrap_err_with(|| format!("{}", dir.display())),
    };
    for entry in entries {
        let entry = entry.wrap_err_with(|| format!("{}", dir.display()))?;
        let path = entry.path();
        let is_dir = entry
            .file_type()
            .wrap_err_with(|| format!("{}", path.display()))?
            .is_dir();
        if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .wrap_err_with(|| format!("could not erase {}", path.display()))?;
    }
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> EyreResult<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .wrap_err_with(|| format!("{}", dir.display()))
}

/// Write `bytes` to a new file at `path`, durably, directory included.
fn write_new(path: &Path, share: Share, bytes: &[u8]) -> EyreResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(share.file_mode())
        .open(path)
        .wrap_err_with(|| format!("could not create {}", path.display()))?;
    share.apply(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn slots(dir: &TempDir, count: u32) -> Vec<Slot> {
        open_slots(&dir.path().join("agents"), count, "").unwrap()
    }

    #[test]
    fn fresh_slots_are_free_and_private() {
        let dir = TempDir::new("slots-fresh");
        let slots = slots(&dir, 3);
        assert_eq!(slots.len(), 3);
        assert!(slots.iter().all(|s| s.claim.is_none()));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("agents")), 0o711);
        assert_eq!(mode(&slots[0].dir), 0o700);
        assert_eq!(mode(&slots[0].secrets_dir()), 0o700);
    }

    #[test]
    fn a_claim_survives_a_restart_with_its_keys() {
        let dir = TempDir::new("slots-claim");
        let mut first = slots(&dir, 2);
        let claim = first[1].claim("ana", &[7; 32]).unwrap();
        let again = slots(&dir, 2);
        assert_eq!(again[1].claim.as_ref(), Some(&claim));
        assert!(again[0].claim.is_none());
    }

    #[test]
    fn a_release_erases_everything_and_a_new_claim_gets_new_keys() {
        let dir = TempDir::new("slots-release");
        let mut slots = slots(&dir, 1);
        let before = slots[0].claim("ana", &[7; 32]).unwrap();
        std::fs::write(slots[0].secrets_dir().join("API_KEY"), "s3cret").unwrap();
        std::fs::create_dir_all(slots[0].state_dir().join("home/.mero")).unwrap();
        slots[0].release().unwrap();
        assert!(slots[0].claim.is_none());
        for sub in ["keys", "secrets", "state"] {
            assert_eq!(
                std::fs::read_dir(slots[0].dir.join(sub)).unwrap().count(),
                0,
                "{sub} left behind"
            );
        }
        let after = slots[0].claim("bob", &[8; 32]).unwrap();
        assert_ne!(before.signing_public, after.signing_public);
    }

    #[test]
    fn a_slot_left_half_claimed_is_free_and_erased() {
        let dir = TempDir::new("slots-half");
        let mut slots = slots(&dir, 1);
        slots[0].claim("ana", &[7; 32]).unwrap();
        std::fs::write(slots[0].secrets_dir().join("API_KEY"), "s3cret").unwrap();
        // A release cut short after removing the id.
        std::fs::remove_file(slots[0].dir.join("id")).unwrap();
        let reopened = open_slots(&dir.path().join("agents"), 1, "").unwrap();
        assert!(reopened[0].claim.is_none());
        assert!(!reopened[0].secrets_dir().join("API_KEY").exists());
        assert!(!reopened[0].keys_dir().join("owner.x25519").exists());
    }

    #[test]
    fn erasing_removes_a_symlink_not_its_target() {
        let dir = TempDir::new("slots-link");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), "x").unwrap();
        let mut slots = slots(&dir, 1);
        slots[0].claim("ana", &[7; 32]).unwrap();
        std::os::unix::fs::symlink(&outside, slots[0].state_dir().join("link")).unwrap();
        slots[0].release().unwrap();
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn one_agent_id_in_two_slots_is_refused() {
        let dir = TempDir::new("slots-dup");
        let mut slots = slots(&dir, 2);
        slots[0].claim("ana", &[7; 32]).unwrap();
        slots[1].claim("ana", &[8; 32]).unwrap();
        let err = open_slots(&dir.path().join("agents"), 2, "").unwrap_err();
        assert!(err.to_string().contains("both claimed"), "{err}");
    }

    #[test]
    fn a_held_slot_cannot_be_claimed_again() {
        let dir = TempDir::new("slots-held");
        let mut slots = slots(&dir, 1);
        slots[0].claim("ana", &[7; 32]).unwrap();
        assert!(slots[0].claim("bob", &[8; 32]).is_err());
    }
}
