import { useState } from 'react';
import { useVerification } from '../hooks/useVerification.js';
import { VerificationResults } from '../components/verification/VerificationResults.jsx';
import { MeroTeeVerifierForm } from '../components/forms/MeroTeeVerifierForm.jsx';
import { parseAttestation, extractComposeHashAndAppId } from '../utils/attestation.js';
import { findMatchingRelease } from '../services/compat.js';
import { fetchAttestationPolicy } from '../services/api.js';
import {
  buildPolicyComposeHashesByProfile,
  findPolicyComposeMatches,
  analyzeReleaseComposePublishing,
} from '../utils/composeHashPolicy.js';
import './VerificationPage.css';

const PROFILES = ['debug', 'debug-read-only', 'locked-read-only'];

async function fetchPoliciesForTag(tag) {
  const results = {};
  for (const profile of PROFILES) {
    try {
      const policy = await fetchAttestationPolicy(tag, profile);
      results[profile] = policy;
    } catch {
      results[profile] = null;
    }
  }
  return results;
}

export function MeroTeeVerificationPage() {
  const [pasteResult, setPasteResult] = useState(null);
  const { status, error, result, verify } = useVerification();

  const handleVerifyByUrl = (kmsUrl, releaseTag) => {
    setPasteResult(null);
    verify(kmsUrl, releaseTag || undefined);
  };

  const handleVerifyByPaste = async (jsonInput, releaseTag) => {
    setPasteResult(null);
    try {
      const { eventLog } = parseAttestation(jsonInput);
      const { composeHash, appId } = extractComposeHashAndAppId(eventLog);
      if (!composeHash) {
        setPasteResult({ error: 'No compose-hash found in event log.' });
        return;
      }
      const { tag, compatMap, matches } = await findMatchingRelease(
        composeHash,
        releaseTag?.trim() || undefined
      );
      const policiesByProfile = await fetchPoliciesForTag(tag);
      const policyComposeHashesByProfile = buildPolicyComposeHashesByProfile(policiesByProfile);
      const policyMatches = findPolicyComposeMatches(composeHash, policyComposeHashesByProfile);
      const releaseComposePublishing = analyzeReleaseComposePublishing(
        compatMap?.compatibility?.profiles || {},
        policyComposeHashesByProfile
      );
      setPasteResult({
        composeHash,
        appId,
        tagToUse: tag,
        matches,
        profiles: compatMap?.compatibility?.profiles || {},
        policyMatches,
        policyComposeHashesByProfile,
        releaseComposePublishing,
        eventCount: eventLog.length,
        ita_token_verified: null,
        quoteRtmrs: null,
        replayedRtmrs: null,
      });
    } catch (err) {
      setPasteResult({ error: err.message });
    }
  };

  return (
    <section className="verification-page">
      <h2>Mero TEE Verification</h2>
      <p className="hint">
        Verify mero-tee node attestations. Full verification (quote + event log + compose hash) via
        KMS URL.
      </p>
      <MeroTeeVerifierForm
        status={status}
        onVerifyByUrl={handleVerifyByUrl}
        onVerifyByPaste={handleVerifyByPaste}
      />
      <div className="coming-soon-note">
        <strong>Node verification (merod):</strong> Coming soon. For now, use{' '}
        <code>scripts/release/verify-node-image-gcp-release-assets.sh</code>
      </div>
      {status === 'loading' && <p className="result-warn">Verifying…</p>}
      {status === 'error' && <p className="result-err">{error}</p>}
      {status === 'success' && result && <VerificationResults result={result} />}
      {pasteResult && (
        <>
          {pasteResult.error ? (
            <p className="result-err">{pasteResult.error}</p>
          ) : (
            <VerificationResults result={pasteResult} />
          )}
        </>
      )}
    </section>
  );
}
