//! Where key material and quotes come from.
//!
//! * [`Backend::Dstack`]: Phala's dstack guest agent derives keys from the
//!   dstack **app** key and produces quotes. Whoever controls the app's code can
//!   derive the same keys (mero-tee#338), which is why this backend is being
//!   retired.
//! * [`Backend::Tdx`]: a plain TDX VM with no dstack. Keys derive from a random
//!   **root** that exists only in this process's memory. The first replica of a
//!   cluster generates it; every other replica gets it from a peer whose quote
//!   carries exactly its own measurements (see `cluster`). Nothing ever writes it
//!   to disk, so nobody outside a genuine replica can hold it. Quotes come from
//!   the kernel's configfs-tsm interface.
//!
//! Both derive a node's key on the same path, `{namespace}/{profile}/{peerId}`,
//! and the transport key on [`sealed::TRANSPORT_KEY_PATH`].

use std::sync::{Arc, RwLock};

#[cfg(feature = "mock-attestation")]
use calimero_tee_attestation::generate_mock_attestation;
use calimero_tee_attestation::{generate_attestation, AttestationResult};
use dstack_sdk::dstack_client::DstackClient;
use eyre::{bail, Result as EyreResult};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use sha2::{Digest, Sha256};
use tracing::info;
use zeroize::Zeroizing;

use crate::handlers::errors::ServiceError;
use crate::measurement::is_debug_td;
use crate::sealed::{self, TransportKey};

/// Salt for every key derived from a TDX root. Distinct from anything dstack
/// uses, so a key never collides across backends.
const ROOT_DERIVE_SALT: &[u8] = b"mero-kms/tdx-root/derive/v1";

/// Report data for the quote a TDX replica takes of itself at startup, to learn
/// its own measurements.
const SELF_MEASUREMENT_DOMAIN: &[u8] = b"mero-kms/self-measurement/v1";

/// Length of the root and of every key derived from it.
pub(crate) const KEY_LEN: usize = 32;

/// Where key material and quotes come from; see the module docs.
#[derive(Clone)]
pub(crate) enum Backend {
    Dstack { socket_path: String },
    Tdx(Arc<TdxBackend>),
}

/// A quote this service produced about itself.
pub(crate) struct KmsQuote {
    pub quote: Vec<u8>,
    /// dstack's event log. Empty for a TDX replica: its RTMR3 carries the image's
    /// own boot measurement, not dstack events.
    pub event_log: serde_json::Value,
    pub vm_config: String,
}

impl Backend {
    pub(crate) fn dstack(socket_path: &str) -> Self {
        Self::Dstack {
            socket_path: socket_path.to_owned(),
        }
    }

    /// The hex key at `path`, the form merod expects.
    pub(crate) async fn derive_key_hex(
        &self,
        path: &str,
    ) -> Result<Zeroizing<String>, ServiceError> {
        match self {
            Self::Dstack { socket_path } => {
                let response = DstackClient::new(Some(socket_path))
                    .get_key(Some(path.to_owned()), None)
                    .await
                    .map_err(|e| ServiceError::KeyDerivationFailed(e.to_string()))?;
                Ok(Zeroizing::new(response.key))
            }
            Self::Tdx(tdx) => {
                let key = tdx.derive(path)?;
                Ok(Zeroizing::new(hex::encode(*key)))
            }
        }
    }

    /// This service's transport key. Every replica derives the same one, so for a
    /// TDX cluster its public half also names the cluster: two clusters with
    /// different roots never share it.
    pub(crate) async fn transport_key(&self) -> Result<TransportKey, ServiceError> {
        match self {
            Self::Dstack { .. } => {
                let key_hex = self.derive_key_hex(sealed::TRANSPORT_KEY_PATH).await?;
                let derived = Zeroizing::new(hex::decode(key_hex.as_str()).map_err(|e| {
                    ServiceError::KeyDerivationFailed(format!("dstack key hex: {e}"))
                })?);
                TransportKey::from_derived_bytes(&derived)
            }
            Self::Tdx(tdx) => {
                TransportKey::from_derived_bytes(&*tdx.derive(sealed::TRANSPORT_KEY_PATH)?)
            }
        }
    }

    /// A quote over `report_data`.
    pub(crate) async fn quote(&self, report_data: [u8; 64]) -> Result<KmsQuote, ServiceError> {
        match self {
            Self::Dstack { socket_path } => {
                let response = DstackClient::new(Some(socket_path))
                    .get_quote(report_data.to_vec())
                    .await
                    .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?;
                let quote = hex::decode(&response.quote).map_err(|e| {
                    ServiceError::AttestationVerificationFailed(format!(
                        "dstack returned invalid quote hex: {e}"
                    ))
                })?;
                let event_log = serde_json::from_str(&response.event_log).map_err(|e| {
                    ServiceError::AttestationVerificationFailed(format!(
                        "dstack returned invalid event log json: {e}"
                    ))
                })?;
                Ok(KmsQuote {
                    quote,
                    event_log,
                    vm_config: response.vm_config,
                })
            }
            Self::Tdx(tdx) => Ok(KmsQuote {
                quote: tdx.quote(report_data).await?.quote_bytes,
                event_log: serde_json::Value::Array(Vec::new()),
                vm_config: String::new(),
            }),
        }
    }
}

/// The five registers that identify a TDX image, as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Measurements {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

impl Measurements {
    pub(crate) fn of(body: &calimero_server_primitives::admin::QuoteBody) -> Self {
        Self {
            mrtd: body.mrtd.to_ascii_lowercase(),
            rtmr0: body.rtmr0.to_ascii_lowercase(),
            rtmr1: body.rtmr1.to_ascii_lowercase(),
            rtmr2: body.rtmr2.to_ascii_lowercase(),
            rtmr3: body.rtmr3.to_ascii_lowercase(),
        }
    }
}

/// The in-memory root. Zeroed on drop.
pub(crate) struct Root(Zeroizing<[u8; KEY_LEN]>);

impl Root {
    pub(crate) fn generate() -> Self {
        Self(Zeroizing::new(rand::random()))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ServiceError> {
        let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            ServiceError::InvalidAttestationRequest(format!("a root is {KEY_LEN} bytes"))
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// HKDF-SHA256 of the root, salted per backend, with `path` as the info.
    fn derive(&self, path: &str) -> Zeroizing<[u8; KEY_LEN]> {
        struct Len;
        impl KeyType for Len {
            fn len(&self) -> usize {
                KEY_LEN
            }
        }
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        Salt::new(HKDF_SHA256, ROOT_DERIVE_SALT)
            .extract(self.0.as_ref())
            .expand(&[path.as_bytes()], Len)
            // SAFETY: 32 bytes is far below HKDF-SHA256's 255 * 32 limit.
            .and_then(|okm| okm.fill(out.as_mut()))
            .expect("HKDF-SHA256 can always produce 32 bytes");
        out
    }
}

/// A TDX replica: its own measurements, and the root once it has one.
pub(crate) struct TdxBackend {
    root: RwLock<Option<Root>>,
    own: Measurements,
    #[cfg(feature = "mock-attestation")]
    mock: bool,
}

impl TdxBackend {
    /// Take a quote of this TD to learn its own measurements, and refuse to run
    /// in a TD that could not keep a root secret.
    pub(crate) async fn new(#[cfg(feature = "mock-attestation")] mock: bool) -> EyreResult<Self> {
        let mut backend = Self {
            root: RwLock::new(None),
            own: Measurements {
                mrtd: String::new(),
                rtmr0: String::new(),
                rtmr1: String::new(),
                rtmr2: String::new(),
                rtmr3: String::new(),
            },
            #[cfg(feature = "mock-attestation")]
            mock,
        };
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&Sha256::digest(SELF_MEASUREMENT_DOMAIN));
        let own = backend
            .quote(report_data)
            .await
            .map_err(|e| eyre::eyre!("could not take a quote of this TD: {e}"))?
            .quote;
        backend.own = Measurements::of(&own.body);
        if !backend.is_mock() {
            if is_debug_td(&own.body.tdattributes) {
                bail!(
                    "this is a debug TD, whose memory its host can read; refusing to hold a root"
                );
            }
            if backend.own.rtmr3.bytes().all(|c| c == b'0') {
                bail!(
                    "RTMR3 was never extended, so this TD's measurements do not cover its image; \
                     refusing to hold a root"
                );
            }
        }
        info!(
            mrtd = %backend.own.mrtd,
            rtmr0 = %backend.own.rtmr0,
            rtmr1 = %backend.own.rtmr1,
            rtmr2 = %backend.own.rtmr2,
            rtmr3 = %backend.own.rtmr3,
            "TDX replica measurements"
        );
        Ok(backend)
    }

    pub(crate) fn own(&self) -> &Measurements {
        &self.own
    }

    pub(crate) fn is_mock(&self) -> bool {
        #[cfg(feature = "mock-attestation")]
        return self.mock;
        #[cfg(not(feature = "mock-attestation"))]
        false
    }

    pub(crate) fn has_root(&self) -> bool {
        self.root.read().map(|root| root.is_some()).unwrap_or(false)
    }

    /// Install the root. A replica holds exactly one root for its lifetime: a
    /// second one would mean two clusters answering behind one URL.
    pub(crate) fn set_root(&self, root: Root) -> Result<(), ServiceError> {
        let mut slot = self
            .root
            .write()
            .map_err(|_| ServiceError::KeyDerivationFailed("root lock poisoned".to_owned()))?;
        if slot.is_some() {
            return Err(ServiceError::KeyDerivationFailed(
                "this replica already holds a root".to_owned(),
            ));
        }
        *slot = Some(root);
        Ok(())
    }

    /// Run `f` over the root, or fail with 503 while this replica has none yet.
    pub(crate) fn with_root<T>(
        &self,
        f: impl FnOnce(&Root) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let slot = self
            .root
            .read()
            .map_err(|_| ServiceError::KeyDerivationFailed("root lock poisoned".to_owned()))?;
        match slot.as_ref() {
            Some(root) => f(root),
            None => Err(ServiceError::PolicyNotReady(
                "this KMS replica has not joined its cluster yet".to_owned(),
            )),
        }
    }

    fn derive(&self, path: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, ServiceError> {
        self.with_root(|root| Ok(root.derive(path)))
    }

    pub(crate) async fn quote(
        &self,
        report_data: [u8; 64],
    ) -> Result<AttestationResult, ServiceError> {
        #[cfg(feature = "mock-attestation")]
        if self.mock {
            return Ok(generate_mock_attestation(report_data));
        }
        tokio::task::spawn_blocking(move || generate_attestation(report_data))
            .await
            .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))?
            .map_err(|e| ServiceError::AttestationVerificationFailed(e.to_string()))
    }
}

/// A mock-mode replica whose own registers are all zero, as a mock quote
/// reports them.
#[cfg(test)]
pub(crate) fn test_tdx_backend(root: Option<Root>) -> TdxBackend {
    test_tdx_backend_with_rtmr3(root, &"0".repeat(96))
}

/// A mock-mode replica that believes its RTMR3 is `rtmr3`, standing in for a
/// different image.
#[cfg(test)]
pub(crate) fn test_tdx_backend_with_rtmr3(root: Option<Root>, rtmr3: &str) -> TdxBackend {
    TdxBackend {
        root: RwLock::new(root),
        own: Measurements {
            mrtd: "0".repeat(96),
            rtmr0: "0".repeat(96),
            rtmr1: "0".repeat(96),
            rtmr2: "0".repeat(96),
            rtmr3: rtmr3.to_owned(),
        },
        #[cfg(feature = "mock-attestation")]
        mock: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_derives_the_same_key_on_the_same_path() {
        let root = Root::from_bytes(&[7; KEY_LEN]).unwrap();
        assert_eq!(
            *root.derive("merod/storage/locked-read-only/a"),
            *root.derive("merod/storage/locked-read-only/a")
        );
    }

    #[test]
    fn paths_and_roots_separate_keys() {
        let root = Root::from_bytes(&[7; KEY_LEN]).unwrap();
        let other = Root::from_bytes(&[8; KEY_LEN]).unwrap();
        let path = "merod/storage/locked-read-only/a";
        assert_ne!(
            *root.derive(path),
            *root.derive("merod/storage/locked-read-only/b")
        );
        assert_ne!(*root.derive(path), *root.derive("merod/storage/debug/a"));
        assert_ne!(*root.derive(path), *other.derive(path));
        assert_ne!(*root.derive(path), *root.derive(sealed::TRANSPORT_KEY_PATH));
    }

    /// Pinned so a change to the derivation, which would strand every disk of
    /// a running release, cannot slip in unnoticed.
    #[test]
    fn the_derivation_matches_its_vector() {
        let root = Root::from_bytes(&[7; KEY_LEN]).unwrap();
        assert_eq!(
            hex::encode(*root.derive("merod/storage/locked-read-only/12D3KooWPeer")),
            DERIVATION_VECTOR
        );
    }

    #[test]
    fn a_replica_without_a_root_is_not_ready() {
        let tdx = test_tdx_backend(None);
        assert!(matches!(
            tdx.derive("x"),
            Err(ServiceError::PolicyNotReady(_))
        ));
    }

    #[test]
    fn a_replica_takes_one_root_only() {
        let tdx = test_tdx_backend(None);
        tdx.set_root(Root::generate()).unwrap();
        assert!(tdx.set_root(Root::generate()).is_err());
        assert!(tdx.has_root());
    }

    #[test]
    fn a_root_is_exactly_32_bytes() {
        assert!(Root::from_bytes(&[0; 31]).is_err());
        assert!(Root::from_bytes(&[0; 33]).is_err());
    }

    // HKDF-SHA256(salt = "mero-kms/tdx-root/derive/v1", ikm = [7; 32],
    // info = the path), reproduced independently from RFC 5869 with Python's
    // `hmac` and `hashlib` (checked against the RFC's test case 1).
    const DERIVATION_VECTOR: &str =
        "0c96eabcba4b72bbd13b706aa478165d6bc71c46981d5316ffe14cccd8855f7f";
}
