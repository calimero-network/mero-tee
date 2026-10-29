/**
 * Hook for KMS attestation verification.
 *
 * The input is a mero-kms `/attest` response pasted by the operator (the KMS listens
 * only inside its VPC), or `{ url }` for a KMS attestation URL (`kms_attest_url`)
 * that the API asks for a quote over a nonce of its own. Intel Trust Authority
 * verifies the quote; MRTD/RTMR0-3 parsed from it are then matched against the KMS
 * allowlists of the release policies.
 *
 * `phase`: `attest` (the API call), `policy` (release policies), `compare`.
 */

import { useState, useCallback } from 'react';
import { verifyKmsAttestation, verifyKmsByUrl } from '../services/api.js';
import { findMatchingRelease } from '../services/compat.js';
import {
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';

const IDLE = { status: 'idle', phase: null, error: null, result: null, request: null };

export function useVerification() {
  const [state, setState] = useState(IDLE);

  const verify = useCallback(async (attestJson, nonceB64 = null, releaseTag = null, selectedProfile = null) => {
    const byUrl = Boolean(attestJson && typeof attestJson === 'object' && attestJson.url);
    const request = {
      attestUrl: byUrl ? attestJson.url : null,
      nonceGiven: Boolean(nonceB64),
      releaseTag: releaseTag || null,
      profile: selectedProfile || null,
    };
    const setPhase = (phase) => setState({ status: 'loading', phase, error: null, result: null, request });
    setPhase('attest');
    try {
      let data;
      if (byUrl) {
        data = await verifyKmsByUrl(attestJson.url);
      } else {
        let pasted;
        try {
          pasted = JSON.parse(attestJson);
        } catch {
          throw new Error('The /attest response is not valid JSON');
        }
        data = await verifyKmsAttestation(pasted, nonceB64);
      }
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

      setPhase('policy');
      let release = { tag: releaseTag || null, policiesByProfile: {}, compatMap: null, matches: [] };
      let policyError = null;
      try {
        release = await findMatchingRelease(quoteRtmrs, releaseTag);
      } catch (e) {
        // Measurements are then reported as not checked, never as matching.
        policyError = e.message || 'Could not load the release policies';
      }
      setPhase('compare');
      const { tag, policiesByProfile, compatMap, matches: allMatches } = release;
      const matches = selectedProfile
        ? allMatches.filter((p) => p === selectedProfile)
        : allMatches;

      setState({
        status: 'success',
        phase: null,
        error: null,
        request,
        result: {
          kind: 'kms',
          attestUrl: request.attestUrl,
          checkedAt: new Date().toISOString(),
          attestation,
          ita_token: data.ita_token || null,
          ita_claims: ita_claims || null,
          ita_token_verified,
          nonce_verified,
          itaRtmrs,
          selectedProfile: selectedProfile || null,
          tagToUse: tag,
          policyError,
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
