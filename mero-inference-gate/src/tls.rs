//! The gate's TLS key: ECDSA P-256, generated in memory at every start and
//! never written. Its certificate is self-signed; clients trust the key a
//! verified quote names ([`TlsIdentity::spki_sha256`]), not a CA.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::attest::sha256;

pub struct TlsIdentity {
    pub config: Arc<ServerConfig>,
    /// SHA-256 of the certificate's SubjectPublicKeyInfo, DER.
    pub spki_sha256: [u8; 32],
}

impl TlsIdentity {
    pub fn generate() -> Result<Self, String> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let spki_sha256 = sha256(&key.public_key_der());
        let params = CertificateParams::new(vec!["mero-inference-gate".to_owned()])
            .map_err(|e| e.to_string())?;
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .map_err(|e| e.to_string())?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
            spki_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_start_has_its_own_key() {
        let a = TlsIdentity::generate().unwrap();
        let b = TlsIdentity::generate().unwrap();
        assert_ne!(a.spki_sha256, b.spki_sha256);
    }
}
