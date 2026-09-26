//! Sigstore verification of a release policy asset.
//!
//! `Release mero-kms` signs every policy it publishes with keyless cosign
//! (`<asset>.sig` plus a `<asset>.bundle.json` carrying the Fulcio certificate
//! and the Rekor entry). The KMS enforces that policy's `node_allowed_*` lists
//! when it decides whether to release a key, so it only trusts a policy whose
//! signature verifies against the release workflow's identity. This mirrors
//! merod's check of the KMS policy it consumes (`crates/merod/src/kms_policy.rs`
//! in calimero-network/core).

use base64::Engine;
use eyre::{bail, Result as EyreResult};
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::policy::{
    AllOf, GitHubWorkflowName, GitHubWorkflowRef, GitHubWorkflowRepository, GitHubWorkflowTrigger,
    OIDCIssuer, SingleX509ExtPolicy, VerificationPolicy as SigstoreVerificationPolicy,
};
use sigstore::bundle::verify::Verifier as SigstoreBundleVerifier;
use sigstore::cosign::bundle::SignedArtifactBundle;
use sigstore::crypto::{CosignVerificationKey, Signature as SigstoreSignature, SigningScheme};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

/// Suffix of the detached signature asset published beside each policy.
pub const SIGNATURE_ASSET_SUFFIX: &str = ".sig";
/// Suffix of the cosign bundle asset published beside each policy.
pub const BUNDLE_ASSET_SUFFIX: &str = ".bundle.json";

const SIGSTORE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const SIGSTORE_WORKFLOW_TRIGGER: &str = "push";
const SIGSTORE_WORKFLOW_NAME: &str = "Release mero-kms";
const SIGSTORE_WORKFLOW_REPOSITORY: &str = "calimero-network/mero-tee";
const SIGSTORE_WORKFLOW_REF: &str = "refs/heads/master";

/// Fetch the public-good Sigstore trust root (Fulcio CAs, Rekor keys) via TUF.
pub async fn load_trust_root() -> EyreResult<SigstoreTrustRoot> {
    SigstoreTrustRoot::new(None)
        .await
        .map_err(|e| eyre::eyre!("Failed to initialize Sigstore trust root: {}", e))
}

/// Verify `policy_body` against its detached signature and cosign bundle.
///
/// Checks, in order: the Rekor signed entry timestamp over the bundle, that the
/// detached signature is the one the bundle carries, that the signature covers
/// exactly these bytes under the bundle's certificate, and that the certificate
/// chains to Fulcio and was issued to the `Release mero-kms` workflow on
/// `master` of calimero-network/mero-tee.
pub async fn verify_policy_signature(
    trust_root: SigstoreTrustRoot,
    policy_body: &[u8],
    signature_body: &str,
    bundle_body: &str,
) -> EyreResult<()> {
    let rekor_pub_keys = rekor_public_keys(&trust_root)?;
    let signed_bundle = SignedArtifactBundle::new_verified(bundle_body, &rekor_pub_keys)
        .map_err(|e| eyre::eyre!("Invalid signed bundle: {}", e))?;

    let detached_signature = signature_body.trim();
    if detached_signature.is_empty() {
        bail!("Policy signature asset is empty");
    }
    if detached_signature != signed_bundle.base64_signature.trim() {
        bail!("Policy signature does not match the signature in its bundle");
    }

    let certificate_pem = decode_bundle_certificate_pem(&signed_bundle.cert)?;
    verify_blob_signature(
        policy_body,
        &signed_bundle.base64_signature,
        &certificate_pem,
    )?;

    let policy_bundle =
        build_policy_sigstore_bundle(policy_body, &signed_bundle, &certificate_pem)?;
    let oidc_issuer = OIDCIssuer::new(SIGSTORE_OIDC_ISSUER);
    let workflow_trigger = GitHubWorkflowTrigger::new(SIGSTORE_WORKFLOW_TRIGGER);
    let workflow_name = GitHubWorkflowName::new(SIGSTORE_WORKFLOW_NAME);
    let workflow_repository = GitHubWorkflowRepository::new(SIGSTORE_WORKFLOW_REPOSITORY);
    let workflow_ref = GitHubWorkflowRef::new(SIGSTORE_WORKFLOW_REF);
    let workflow_policy = AllOf::new([
        &oidc_issuer as &dyn SigstoreVerificationPolicy,
        &workflow_trigger,
        &workflow_name,
        &workflow_repository,
        &workflow_ref,
    ])
    .ok_or_else(|| eyre::eyre!("Failed to construct Sigstore verification policy"))?;

    let verifier = SigstoreBundleVerifier::new(Default::default(), trust_root)
        .map_err(|e| eyre::eyre!("Failed to create Sigstore verifier: {}", e))?;
    verifier
        .verify(policy_body, policy_bundle, &workflow_policy, true)
        .await
        .map_err(|e| eyre::eyre!("Sigstore bundle verification failed: {}", e))
}

fn rekor_public_keys(
    trust_root: &SigstoreTrustRoot,
) -> EyreResult<std::collections::BTreeMap<String, CosignVerificationKey>> {
    let mut keys = std::collections::BTreeMap::new();
    for (key_id, key_der) in trust_root
        .rekor_keys()
        .map_err(|e| eyre::eyre!("Failed to read Rekor keys from trust root: {}", e))?
    {
        match CosignVerificationKey::from_der(key_der, &SigningScheme::default()) {
            Ok(key) => {
                let _ = keys.insert(key_id, key);
            }
            Err(err) => {
                tracing::warn!(
                    rekor_key_id = %key_id,
                    error = %err,
                    "Skipping unsupported Rekor key from Sigstore trust root"
                );
            }
        }
    }
    if keys.is_empty() {
        bail!("Sigstore trust root did not provide a usable Rekor public key");
    }
    Ok(keys)
}

fn decode_bundle_certificate_pem(encoded_cert: &str) -> EyreResult<String> {
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded_cert.trim())
        .map_err(|e| eyre::eyre!("Bundle certificate is not valid base64: {}", e))?;
    String::from_utf8(cert_bytes)
        .map_err(|e| eyre::eyre!("Bundle certificate is not valid UTF-8 PEM: {}", e))
}

fn verify_blob_signature(
    policy_body: &[u8],
    signature_b64: &str,
    cert_pem: &str,
) -> EyreResult<()> {
    let certificate = Certificate::from_pem(cert_pem.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to parse policy signing certificate PEM: {}", e))?;
    let spki_der = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| eyre::eyre!("Failed to encode signing certificate key: {}", e))?;
    let verification_key = CosignVerificationKey::try_from_der(&spki_der).map_err(|e| {
        eyre::eyre!(
            "Failed to extract verification key from signing certificate: {}",
            e
        )
    })?;
    verification_key
        .verify_signature(
            SigstoreSignature::Base64Encoded(signature_b64.trim().as_bytes()),
            policy_body,
        )
        .map_err(|e| eyre::eyre!("Detached signature does not match policy body: {}", e))
}

/// Re-express a cosign `SignedArtifactBundle` as a Sigstore v0.1 bundle, which
/// is what the sigstore-rs verifier checks the certificate chain and identity of.
fn build_policy_sigstore_bundle(
    policy_body: &[u8],
    signed_bundle: &SignedArtifactBundle,
    certificate_pem: &str,
) -> EyreResult<sigstore::bundle::Bundle> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let signature_bytes = b64
        .decode(signed_bundle.base64_signature.trim())
        .map_err(|e| eyre::eyre!("Bundle signature is not valid base64: {}", e))?;
    let signed_entry_timestamp = b64
        .decode(signed_bundle.rekor_bundle.signed_entry_timestamp.trim())
        .map_err(|e| eyre::eyre!("Bundle signed entry timestamp is not valid base64: {}", e))?;
    let canonicalized_body = b64
        .decode(signed_bundle.rekor_bundle.payload.body.trim())
        .map_err(|e| eyre::eyre!("Bundle canonicalized body is not valid base64: {}", e))?;
    let canonicalized_body_json: serde_json::Value = serde_json::from_slice(&canonicalized_body)
        .map_err(|e| eyre::eyre!("Bundle canonicalized body is not valid JSON: {}", e))?;
    let kind = canonicalized_body_json
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("Bundle canonicalized body is missing kind"))?;
    let api_version = canonicalized_body_json
        .get("apiVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("Bundle canonicalized body is missing apiVersion"))?;
    let log_id = hex::decode(signed_bundle.rekor_bundle.payload.log_id.trim())
        .map_err(|e| eyre::eyre!("Bundle log ID is not valid hex: {}", e))?;

    let certificate = Certificate::from_pem(certificate_pem.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to parse bundle certificate PEM: {}", e))?;
    let cert_der = certificate
        .to_der()
        .map_err(|e| eyre::eyre!("Failed to encode bundle certificate DER: {}", e))?;
    let digest = Sha256::digest(policy_body);

    let bundle_json = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [{ "rawBytes": b64.encode(cert_der) }]
            },
            "tlogEntries": [{
                "logIndex": signed_bundle.rekor_bundle.payload.log_index,
                "logId": { "keyId": b64.encode(log_id) },
                "kindVersion": { "kind": kind, "version": api_version },
                "integratedTime": signed_bundle.rekor_bundle.payload.integrated_time,
                "inclusionPromise": {
                    "signedEntryTimestamp": b64.encode(signed_entry_timestamp),
                },
                "canonicalizedBody": b64.encode(canonicalized_body),
            }]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": b64.encode(digest),
            },
            "signature": b64.encode(signature_bytes),
        }
    });

    serde_json::from_value(bundle_json).map_err(|e| {
        eyre::eyre!(
            "Failed to construct Sigstore bundle from policy artifacts: {}",
            e
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A policy exactly as `Release mero-kms` published it for mero-kms-v2.3.71,
    // with its detached signature and cosign bundle, and the public-good
    // Sigstore trusted root (sigstore/root-signing `targets/trusted_root.json`)
    // so the whole chain verifies without reaching TUF.
    const POLICY: &[u8] =
        include_bytes!("../../testdata/kms-phala-attestation-policy.locked-read-only.json");
    const SIGNATURE: &str =
        include_str!("../../testdata/kms-phala-attestation-policy.locked-read-only.json.sig");
    const BUNDLE: &str = include_str!(
        "../../testdata/kms-phala-attestation-policy.locked-read-only.json.bundle.json"
    );
    const TRUSTED_ROOT: &[u8] = include_bytes!("../../testdata/sigstore-trusted-root.json");

    fn trust_root() -> SigstoreTrustRoot {
        SigstoreTrustRoot::from_trusted_root_json_unchecked(TRUSTED_ROOT)
            .expect("fixture trusted root parses")
    }

    #[tokio::test]
    async fn a_released_policy_verifies() {
        verify_policy_signature(trust_root(), POLICY, SIGNATURE, BUNDLE)
            .await
            .expect("the published policy should verify");
    }

    /// The attack in mero-tee#337: someone who can replace the release asset
    /// adds a measurement to `node_allowed_mrtd`, keeping the real signature.
    #[tokio::test]
    async fn a_policy_with_an_added_measurement_is_refused() {
        let mut policy: serde_json::Value =
            serde_json::from_slice(POLICY).expect("fixture is JSON");
        policy["policy"]["node_allowed_mrtd"]
            .as_array_mut()
            .expect("fixture has node_allowed_mrtd")
            .push(serde_json::Value::String("cd".repeat(48)));
        let tampered = serde_json::to_vec_pretty(&policy).expect("serializes");

        let err = verify_policy_signature(trust_root(), &tampered, SIGNATURE, BUNDLE)
            .await
            .expect_err("a tampered policy must not verify");
        assert!(
            err.to_string()
                .contains("Detached signature does not match policy body"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn a_signature_other_than_the_bundles_is_refused() {
        let err = verify_policy_signature(trust_root(), POLICY, "MEUCIQ==", BUNDLE)
            .await
            .expect_err("a mismatched detached signature must be refused");
        assert!(
            err.to_string()
                .contains("does not match the signature in its bundle"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn an_empty_signature_is_refused() {
        let err = verify_policy_signature(trust_root(), POLICY, "  \n", BUNDLE)
            .await
            .expect_err("an empty signature must be refused");
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn a_bundle_whose_rekor_entry_was_edited_is_refused() {
        let mut bundle: serde_json::Value = serde_json::from_str(BUNDLE).expect("bundle is JSON");
        let index = bundle["rekorBundle"]["Payload"]["logIndex"]
            .as_u64()
            .expect("bundle has a log index");
        bundle["rekorBundle"]["Payload"]["logIndex"] = serde_json::json!(index + 1);
        let edited = serde_json::to_string(&bundle).expect("serializes");

        let err = verify_policy_signature(trust_root(), POLICY, SIGNATURE, &edited)
            .await
            .expect_err("a bundle with a forged Rekor entry must be refused");
        assert!(
            err.to_string().contains("Invalid signed bundle"),
            "unexpected error: {err}"
        );
    }
}
