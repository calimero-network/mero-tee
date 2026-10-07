//! The provisioner's side: verify a gate's quote against the agent release's
//! published measurements, then seal secrets to the key that quote covers.
//!
//! This is also the check an account owner runs before authorizing the agent's
//! signing key as a device: [`attest_gate`] returns the signing key only once
//! the quote that commits to it has passed.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use calimero_tee_attestation::VerificationResult;
use serde::{Deserialize, Serialize};

use crate::keys::random_32;
use crate::protocol::{
    key_binding, seal_bundle, AttestRequest, AttestResponse, ProvisionRequest, ProvisionResponse,
    SecretsBundle,
};

/// The agent allowlist, in the shape `kms_agent_policy_file` and the release's
/// `agent-attestation-policy.<profile>.json` use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub allowed_tcb_statuses: Vec<String>,
    pub allowed_mrtd: Vec<String>,
    pub allowed_rtmr0: Vec<String>,
    pub allowed_rtmr1: Vec<String>,
    pub allowed_rtmr2: Vec<String>,
    pub allowed_rtmr3: Vec<String>,
}

fn normalize(value: &str) -> String {
    value.trim().trim_start_matches("0x").to_ascii_lowercase()
}

/// A debug TD's memory is readable by its host, so nothing it attests to is
/// private. Bit 0 of TDATTRIBUTES; an unreadable value counts as debug.
fn is_debug_td(tdattributes_hex: &str) -> bool {
    match hex::decode(tdattributes_hex.trim()) {
        Ok(bytes) if bytes.len() == 8 => bytes[0] & 1 == 1,
        _ => true,
    }
}

impl AgentPolicy {
    /// Every register in its list, the TCB status allowed, not a debug TD.
    /// An empty list rejects, as in mero-kms.
    pub fn check(&self, verification: &VerificationResult) -> Result<(), String> {
        let body = &verification.quote.body;
        if is_debug_td(&body.tdattributes) {
            return Err("the gate runs in a debug TD, whose memory its host can read".to_owned());
        }
        let status = verification
            .tcb_status
            .as_deref()
            .ok_or("the quote has no TCB status")?;
        if !self
            .allowed_tcb_statuses
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(status))
        {
            return Err(format!("TCB status '{status}' is not in the policy"));
        }
        let registers = [
            ("MRTD", &self.allowed_mrtd, &body.mrtd),
            ("RTMR0", &self.allowed_rtmr0, &body.rtmr0),
            ("RTMR1", &self.allowed_rtmr1, &body.rtmr1),
            ("RTMR2", &self.allowed_rtmr2, &body.rtmr2),
            ("RTMR3", &self.allowed_rtmr3, &body.rtmr3),
        ];
        for (label, allowed, actual) in registers {
            let actual = normalize(actual);
            if !allowed.iter().any(|value| normalize(value) == actual) {
                return Err(format!("{label} '{actual}' is not in the agent policy"));
            }
        }
        Ok(())
    }
}

/// A gate whose quote passed: the keys it committed to, and its registers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedGate {
    #[serde(serialize_with = "as_base64")]
    pub provisioning_public_key: [u8; 32],
    #[serde(serialize_with = "as_base64")]
    pub signing_public_key: [u8; 32],
    pub tcb_status: Option<String>,
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

fn as_base64<S: serde::Serializer>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64.encode(key))
}

fn decode_32(field: &str, value: &str) -> Result<[u8; 32], String> {
    BASE64
        .decode(value.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| format!("{field} is not 32 bytes of base64"))
}

/// Check a gate's `/attest` answer to `nonce`: the quote is genuine and fresh,
/// commits to the two keys the answer names, and the image is in `policy`.
///
/// `allow_mock` accepts a mock quote, and exists only in the
/// `mock-attestation` build.
pub async fn verify_attest_response(
    response: &AttestResponse,
    nonce: &[u8; 32],
    policy: &AgentPolicy,
    #[cfg(feature = "mock-attestation")] allow_mock: bool,
) -> Result<VerifiedGate, String> {
    let provisioning = decode_32(
        "provisioningPublicKeyB64",
        &response.provisioning_public_key_b64,
    )?;
    let signing = decode_32("signingPublicKeyB64", &response.signing_public_key_b64)?;
    let quote = BASE64
        .decode(response.quote_b64.trim())
        .map_err(|_| "quoteB64 is not base64".to_owned())?;
    let binding = key_binding(&provisioning, &signing);

    #[cfg(feature = "mock-attestation")]
    let verification = if calimero_tee_attestation::is_mock_quote(&quote) {
        if !allow_mock {
            return Err("the gate answered with a mock quote".to_owned());
        }
        calimero_tee_attestation::verify_mock_attestation(&quote, nonce, &binding)
    } else {
        calimero_tee_attestation::verify_attestation(&quote, nonce, &binding).await
    };
    #[cfg(not(feature = "mock-attestation"))]
    let verification = calimero_tee_attestation::verify_attestation(&quote, nonce, &binding).await;
    let verification = verification.map_err(|e| format!("quote verification failed: {e}"))?;

    if !verification.nonce_verified {
        return Err("the quote does not carry this request's nonce".to_owned());
    }
    if !verification.application_hash_verified {
        return Err("the quote does not commit to the keys the gate named".to_owned());
    }
    if !verification.quote_verified {
        return Err("the quote's signature did not verify".to_owned());
    }
    #[cfg(feature = "mock-attestation")]
    let skip_policy = allow_mock && calimero_tee_attestation::is_mock_quote(&quote);
    #[cfg(not(feature = "mock-attestation"))]
    let skip_policy = false;
    if !skip_policy {
        policy.check(&verification)?;
    }

    let body = &verification.quote.body;
    Ok(VerifiedGate {
        provisioning_public_key: provisioning,
        signing_public_key: signing,
        tcb_status: verification.tcb_status.clone(),
        mrtd: normalize(&body.mrtd),
        rtmr0: normalize(&body.rtmr0),
        rtmr1: normalize(&body.rtmr1),
        rtmr2: normalize(&body.rtmr2),
        rtmr3: normalize(&body.rtmr3),
    })
}

/// Ask `gate_url` for a quote over a fresh nonce and verify it.
pub async fn attest_gate(
    client: &reqwest::Client,
    gate_url: &str,
    policy: &AgentPolicy,
    #[cfg(feature = "mock-attestation")] allow_mock: bool,
) -> Result<VerifiedGate, String> {
    let nonce = random_32();
    let response: AttestResponse = client
        .post(format!("{}/attest", gate_url.trim_end_matches('/')))
        .json(&AttestRequest {
            nonce_b64: BASE64.encode(*nonce),
        })
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("/attest: {e}"))?
        .json()
        .await
        .map_err(|e| format!("/attest: {e}"))?;
    verify_attest_response(
        &response,
        &nonce,
        policy,
        #[cfg(feature = "mock-attestation")]
        allow_mock,
    )
    .await
}

/// Seal `bundle` to a verified gate and post it.
pub async fn provision_gate(
    client: &reqwest::Client,
    gate_url: &str,
    gate: &VerifiedGate,
    provisioner_secret: Option<&[u8; 32]>,
    bundle: &SecretsBundle,
) -> Result<ProvisionResponse, String> {
    let (encapped, ciphertext) =
        seal_bundle(&gate.provisioning_public_key, provisioner_secret, bundle)?;
    let response = client
        .post(format!("{}/provision", gate_url.trim_end_matches('/')))
        .json(&ProvisionRequest {
            provisioning_public_key_b64: BASE64.encode(gate.provisioning_public_key),
            encapped_key_b64: BASE64.encode(encapped),
            ciphertext_b64: BASE64.encode(ciphertext),
        })
        .send()
        .await
        .map_err(|e| format!("/provision: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("/provision answered {status}: {body}"));
    }
    response
        .json()
        .await
        .map_err(|e| format!("/provision: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_of(value: &str) -> AgentPolicy {
        AgentPolicy {
            allowed_tcb_statuses: vec!["UpToDate".to_owned()],
            allowed_mrtd: vec![value.to_owned()],
            allowed_rtmr0: vec![value.to_owned()],
            allowed_rtmr1: vec![value.to_owned()],
            allowed_rtmr2: vec![value.to_owned()],
            allowed_rtmr3: vec![value.to_owned()],
        }
    }

    fn verification(tdattributes: &str) -> VerificationResult {
        let mut quote = crate::test_util::zero_quote();
        quote.body.tdattributes = tdattributes.to_owned();
        VerificationResult {
            quote_verified: true,
            nonce_verified: true,
            application_hash_verified: true,
            tcb_status: Some("UpToDate".to_owned()),
            advisory_ids: Vec::new(),
            quote,
        }
    }

    #[test]
    fn a_quote_in_the_policy_passes() {
        policy_of(&"0".repeat(96))
            .check(&verification(&"0".repeat(16)))
            .unwrap();
    }

    #[test]
    fn a_register_outside_the_policy_fails() {
        let mut policy = policy_of(&"0".repeat(96));
        policy.allowed_rtmr3 = vec!["a".repeat(96)];
        let err = policy.check(&verification(&"0".repeat(16))).unwrap_err();
        assert!(err.contains("RTMR3"), "{err}");
    }

    #[test]
    fn a_debug_td_fails_whatever_its_registers() {
        let err = policy_of(&"0".repeat(96))
            .check(&verification("0100000000000000"))
            .unwrap_err();
        assert!(err.contains("debug TD"), "{err}");
    }

    #[test]
    fn a_tcb_status_outside_the_policy_fails() {
        let mut v = verification(&"0".repeat(16));
        v.tcb_status = Some("OutOfDate".to_owned());
        assert!(policy_of(&"0".repeat(96)).check(&v).is_err());
    }
}
