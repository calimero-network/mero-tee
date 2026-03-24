/**
 * Hook for node (merod) attestation verification.
 * Nodes return TDX quotes only (no event_log/compose_hash).
 * Policy comparison uses MRTD/RTMR0–3 parsed from the quote (same as published-mrtds.json);
 * Intel Trust Authority JWT is verified separately (QuoteAttestationCard).
 */

import { useState, useCallback } from 'react';
import { verifyNodeAttestation, fetchNodeReleases, fetchNodePolicy } from '../services/api.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';

export function useNodeVerification() {
  const [state, setState] = useState({
    status: 'idle',
    error: null,
    result: null,
  });

  const verify = useCallback(async (nodeUrl, releaseTag = null) => {
    setState({ status: 'loading', error: null, result: null });
    try {
      const data = await verifyNodeAttestation(nodeUrl);
      const { attestation, ita_claims, ita_token_verified } = data;
      if (!attestation) throw new Error('No attestation in response');

      const quoteB64 = attestation.quoteB64 ?? attestation.quote_b64;
      const fromITA = extractRTMRsFromClaims(ita_claims || {});
      const fromQuote = quoteB64 ? extractMeasurementsFromQuoteB64(quoteB64) : null;
      const { quoteRtmrs, measurementSources, itaRtmrs } = mergeQuoteFirstMeasurements(
        fromQuote,
        fromITA
      );

      const latestTag = (await fetchNodeReleases(1))[0];
      const tagToUse = releaseTag?.trim() || latestTag;
      let policiesByProfile = {};
      try {
        policiesByProfile = await fetchNodePolicy(tagToUse);
      } catch {
        // Policy fetch failed; continue without expected values
      }

      setState({
        status: 'success',
        error: null,
        result: {
          attestation,
          ita_claims: ita_claims || null,
          ita_token_verified,
          quoteRtmrs,
          itaRtmrs,
          measurementSources,
          replayedRtmrs: {},
          composeHash: null,
          eventLog: [],
          eventCount: 0,
          tagToUse,
          policiesByProfile,
        },
      });
    } catch (e) {
      setState({
        status: 'error',
        error: e.message || 'Verification failed',
        result: null,
      });
    }
  }, []);

  const reset = useCallback(() => {
    setState({ status: 'idle', error: null, result: null });
  }, []);

  return { ...state, verify, reset };
}
