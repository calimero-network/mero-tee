/**
 * Hook for node (merod) attestation verification.
 * Nodes return TDX quotes only.
 * Policy comparison uses MRTD/RTMR0–3 parsed from the quote (same as published-mrtds.json);
 * the Intel Trust Authority JWT is verified by the API.
 *
 * `phase` follows the work for the progress view: `attest` (the API fetches a
 * quote for its own nonce and has Intel verify it, one request), `policy` (the
 * release's published measurements are loaded), `compare`.
 */

import { useState, useCallback } from 'react';
import { verifyNodeAttestation, fetchNodeReleases, fetchNodePolicy } from '../services/api.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromMerodAttest,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';

const IDLE = { status: 'idle', phase: null, error: null, result: null, request: null };

export function useNodeVerification() {
  const [state, setState] = useState(IDLE);

  const verify = useCallback(async (nodeUrl, releaseTag = null) => {
    const request = { nodeUrl, releaseTag: releaseTag?.trim() || null };
    const setPhase = (phase) => setState({ status: 'loading', phase, error: null, result: null, request });
    setPhase('attest');
    try {
      const data = await verifyNodeAttestation(nodeUrl);
      const { attestation, ita_claims, ita_token_verified, nonce_verified, transport_verified } = data;
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
