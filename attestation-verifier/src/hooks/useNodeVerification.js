/**
 * Hook for node (merod) attestation verification.
 * Nodes return TDX quotes only.
 * Policy comparison uses MRTD/RTMR0–3 parsed from the quote (same as published-mrtds.json);
 * the Intel Trust Authority JWT is verified by the API.
 *
 * `phase` follows the work for the progress view: `attest` (the API fetches a
 * quote for its own nonce and has Intel verify it, one request), `policy` (the
 * release's published measurements are loaded), `kms` (the KMS policy of each
 * KMS record the node's quote commits to is loaded), `compare`.
 *
 * A KMS record is the node's account of the KMS quote it accepted before
 * taking a key. It is checked here only when the API found the node's quote
 * commits to it, and then against the KMS policy this verifier loads itself
 * for the release and profile the record names -- not taken on the node's word.
 */

import { useState, useCallback } from 'react';
import { verifyNodeAttestation, fetchNodeReleases, fetchNodePolicy } from '../services/api.js';
import { findMatchingRelease } from '../services/compat.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromMerodAttest,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';

const IDLE = { status: 'idle', phase: null, error: null, result: null, request: null };

/** The node's KMS records, each against the published KMS policy of the release it names. */
async function checkKmsRecords(kmsEvidence) {
  const checks = [];
  for (const key of ['storage', 'disk']) {
    const record = kmsEvidence?.[key];
    if (!record) continue;
    const tag = `mero-kms-v${record.release}`;
    const measurements = {
      mrtd: record.mrtd,
      rtmr0: record.rtmr0,
      rtmr1: record.rtmr1,
      rtmr2: record.rtmr2,
      rtmr3: record.rtmr3,
    };
    try {
      const { policiesByProfile, matches } = await findMatchingRelease(measurements, tag);
      // The record names the profile whose policy accepted it; only that one counts.
      const allowed = record.profile ? matches.filter((p) => p === record.profile) : matches;
      checks.push({ key, record, tag, measurements, policiesByProfile, matches: allowed, error: null });
    } catch (e) {
      checks.push({ key, record, tag, measurements, policiesByProfile: {}, matches: [], error: e.message || 'Could not load the KMS policy' });
    }
  }
  return checks;
}

export function useNodeVerification() {
  const [state, setState] = useState(IDLE);

  const verify = useCallback(async (nodeUrl, releaseTag = null) => {
    const request = { nodeUrl, releaseTag: releaseTag?.trim() || null };
    const setPhase = (phase) => setState({ status: 'loading', phase, error: null, result: null, request });
    setPhase('attest');
    try {
      const data = await verifyNodeAttestation(nodeUrl);
      const {
        attestation, ita_claims, ita_token_verified, nonce_verified, transport_verified,
        kms_evidence: kmsEvidence = null, kms_evidence_bound: kmsEvidenceBound = null,
        kms_evidence_error: kmsEvidenceError = null,
      } = data;
      if (!attestation) throw new Error('No attestation in response');

      const fromITA = extractRTMRsFromClaims(ita_claims || {});
      const fromQuote = extractMeasurementsFromMerodAttest(attestation);
      const { quoteRtmrs, measurementSources, itaRtmrs } = mergeQuoteFirstMeasurements(
        fromQuote,
        fromITA
      );

      setPhase('policy');
      let tagToUse = request.releaseTag;
      let policyError = null;
      let policiesByProfile = {};
      try {
        // Only when no release was named: the newest mero-tee release.
        if (!tagToUse) tagToUse = (await fetchNodeReleases(1))[0];
        policiesByProfile = await fetchNodePolicy(tagToUse);
      } catch (e) {
        // Measurements are then reported as not checked, never as matching.
        policyError = e.message || 'Could not load the release measurements';
      }
      let kmsChecks = [];
      if (kmsEvidence && kmsEvidenceBound === true) {
        setPhase('kms');
        kmsChecks = await checkKmsRecords(kmsEvidence);
      }
      setPhase('compare');

      setState({
        status: 'success',
        phase: null,
        error: null,
        request,
        result: {
          kind: 'node',
          nodeUrl,
          checkedAt: new Date().toISOString(),
          attestation,
          ita_token: data.ita_token || null,
          ita_claims: ita_claims || null,
          ita_token_verified,
          nonce_verified,
          transport_verified,
          kmsEvidence,
          kmsEvidenceBound,
          kmsEvidenceError,
          kmsChecks,
          quoteRtmrs,
          itaRtmrs,
          measurementSources,
          tagToUse,
          policyError,
          policiesByProfile,
        },
      });
    } catch (e) {
      setState({
        status: 'error',
        phase: null,
        error: e.message || 'Verification failed',
        result: null,
        request,
      });
    }
  }, []);

  const reset = useCallback(() => setState(IDLE), []);

  return { ...state, verify, reset };
}
