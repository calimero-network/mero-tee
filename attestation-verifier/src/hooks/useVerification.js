/**
 * Hook for KMS attestation verification.
 * Encapsulates verification flow, state, and side effects.
 *
 * The input is a mero-kms `/attest` response pasted by the operator (the KMS listens
 * only inside its VPC). Intel Trust Authority verifies the quote; MRTD/RTMR0-3 parsed
 * from it are then matched against the KMS allowlists of the release policies.
 */

import { useState, useCallback } from 'react';
import { verifyKmsAttestation } from '../services/api.js';
import { findMatchingRelease } from '../services/compat.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';

export function useVerification() {
  const [state, setState] = useState({
    status: 'idle', // idle | loading | success | error
    error: null,
    result: null,
  });

  const verify = useCallback(async (attestJson, nonceB64 = null, releaseTag = null, selectedProfile = null) => {
    setState({ status: 'loading', error: null, result: null });
    try {
      let pasted;
      try {
        pasted = JSON.parse(attestJson);
      } catch {
        throw new Error('The /attest response is not valid JSON');
      }
      const data = await verifyKmsAttestation(pasted, nonceB64);
      const { attestation, ita_claims, ita_token_verified, nonce_verified } = data;
      if (!attestation) throw new Error('No attestation in response');

      // Policy comparison: MRTD/RTMR0–3 from parsed quote first (matches release policy); ITA JWT verified separately.
      const fromITA = extractRTMRsFromClaims(ita_claims || {});
      const quoteB64 = attestation.quoteB64 ?? attestation.quote_b64;
      const fromQuote = quoteB64 ? extractMeasurementsFromQuoteB64(quoteB64) : null;
      const { quoteRtmrs, measurementSources, itaRtmrs } = mergeQuoteFirstMeasurements(
        fromQuote,
        fromITA
      );

      const { tag, policiesByProfile, compatMap, matches: allMatches } = await findMatchingRelease(
        quoteRtmrs,
        releaseTag
      );
      const matches = selectedProfile
        ? allMatches.filter((p) => p === selectedProfile)
        : allMatches;

      setState({
        status: 'success',
        error: null,
        result: {
          attestation,
          ita_claims: ita_claims || null,
          ita_token_verified,
          nonce_verified,
          itaRtmrs,
          selectedProfile: selectedProfile || null,
          tagToUse: tag,
          matches,
          matchedImage: matches.length > 0
            ? compatMap?.compatibility?.profiles?.[matches[0]]?.kms_image ?? null
            : null,
          quoteRtmrs,
          measurementSources,
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
