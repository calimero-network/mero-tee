import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { useNodeVerification } from '../hooks/useNodeVerification.js';
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
  const [searchParams] = useSearchParams();
  const nodeUrlParam = searchParams.get('node_url') || searchParams.get('nodeUrl');
  const [pasteResult, setPasteResult] = useState(null);
  const { status, error, result, verify } = useVerification();
  const {
    status: nodeStatus,
    error: nodeError,
    result: nodeResult,
    verify: verifyNode,
  } = useNodeVerification();

  useEffect(() => {
    if (nodeUrlParam) {
      verifyNode(nodeUrlParam);
    }
  }, [nodeUrlParam, verifyNode]);

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

  const handleVerifyNode = (nodeUrl) => {
    setPasteResult(null);
    verifyNode(nodeUrl);
  };

  const activeStatus = nodeStatus !== 'idle' ? nodeStatus : status;
  const activeError = nodeStatus !== 'idle' ? nodeError : error;
  const activeResult = nodeStatus === 'success' ? nodeResult : result;

  return (
    <section className="verification-page">
      <h2>Mero TEE Verification</h2>
      <p className="hint">
        Verify mero-tee node attestations (GCP TDX nodes) or KMS instances. Enter a node URL (e.g.{' '}
        <code>http://public-ip:80</code>) or KMS URL.
      </p>
      <MeroTeeVerifierForm
        status={status}
        onVerifyByUrl={handleVerifyByUrl}
        onVerifyByPaste={handleVerifyByPaste}
      />
      <div className="verifier-form" style={{ marginTop: '1.5rem' }}>
        <h3>Node (merod) verification</h3>
        <p className="hint">
          Verify a Calimero node at its admin API base URL. The node must be reachable (http://public-ip:80).
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const input = e.target.querySelector('input[type="url"]');
            if (input?.value?.trim()) handleVerifyNode(input.value.trim());
          }}
          className="verifier-form"
        >
          <div className="input-row">
            <input
              type="url"
              name="node_url"
              placeholder="http://34.65.123.45:80"
              disabled={nodeStatus === 'loading'}
              defaultValue={nodeUrlParam || ''}
            />
            <button type="submit" disabled={nodeStatus === 'loading'}>
              {nodeStatus === 'loading' ? 'Verifying…' : 'Verify node'}
            </button>
          </div>
        </form>
      </div>
      {(nodeStatus === 'loading' || status === 'loading') && (
        <p className="result-warn">Verifying…</p>
      )}
      {(activeError || nodeError || error) && (
        <p className="result-err">{activeError || nodeError || error}</p>
      )}
      {activeStatus === 'success' && activeResult && (
        <VerificationResults result={activeResult} />
      )}
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
