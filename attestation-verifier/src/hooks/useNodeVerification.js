/**
 * Hook for node (merod) attestation verification.
 * Nodes return TDX quotes only (no event_log/compose_hash).
 * Compares MRTD/RTMR0-2 against published-mrtds.json (like KMS verification).
 */

import { useState, useCallback } from 'react';
import { verifyNodeAttestation, fetchNodeReleases, fetchNodePolicy } from '../services/api.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
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
      const quoteRtmrs = {
        mrtd: fromITA.mrtd || fromQuote?.mrtd,
        rtmr0: fromITA.rtmr0 || fromQuote?.rtmr0,
        rtmr1: fromITA.rtmr1 || fromQuote?.rtmr1,
        rtmr2: fromITA.rtmr2 || fromQuote?.rtmr2,
        rtmr3: fromQuote?.rtmr3 ?? fromITA.rtmr3,
        tcb_status: fromITA.tcb_status,
      };
      const measurementSources = {
        mrtd: fromITA.mrtd ? 'ita' : fromQuote?.mrtd ? 'quote' : null,
        rtmr0: fromITA.rtmr0 ? 'ita' : fromQuote?.rtmr0 ? 'quote' : null,
        rtmr1: fromITA.rtmr1 ? 'ita' : fromQuote?.rtmr1 ? 'quote' : null,
        rtmr2: fromITA.rtmr2 ? 'ita' : fromQuote?.rtmr2 ? 'quote' : null,
        rtmr3: fromQuote?.rtmr3 ? 'quote' : fromITA.rtmr3 ? 'ita' : null,
      };

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
