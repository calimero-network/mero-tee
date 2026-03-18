/**
 * Hook for KMS attestation verification.
 * Encapsulates verification flow, state, and side effects.
 */

import { useState, useCallback } from 'react';
import { verifyKmsAttestation, fetchKmsReleases, fetchAttestationPolicy } from '../services/api.js';
import { findMatchingRelease } from '../services/compat.js';
import {
  extractComposeHashAndAppId,
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
} from '../utils/attestation.js';
import { replayRTMR, replayRTMRWithSteps } from '../utils/crypto.js';

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

export function useVerification() {
  const [state, setState] = useState({
    status: 'idle', // idle | loading | success | error
    error: null,
    result: null,
  });

  const verify = useCallback(async (kmsUrl, releaseTag = null) => {
    setState({ status: 'loading', error: null, result: null });
    try {
      const data = await verifyKmsAttestation(kmsUrl);
      const { attestation, ita_claims, ita_token_verified } = data;
      if (!attestation) throw new Error('No attestation in response');

      const eventLog = attestation.event_log ?? attestation.eventLog;
      const events = Array.isArray(eventLog)
        ? eventLog
        : eventLog
          ? JSON.parse(eventLog)
          : [];

      const { composeHash, appId } = extractComposeHashAndAppId(events);
      const latestTag = (await fetchKmsReleases(1))[0];
      const { tag: tagToUse, compatMap, matches } = composeHash
        ? await findMatchingRelease(composeHash, releaseTag || undefined)
        : { tag: releaseTag || latestTag, compatMap: null, matches: [] };

      // Proper verification split: MRTD, RTMR0-2 from ITA; RTMR3 and compose from quote/event log
      const fromITA = extractRTMRsFromClaims(ita_claims || {});
      const quoteB64 = attestation.quoteB64 ?? attestation.quote_b64;
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
      const replayedRtmrs = {};
      let rtmr3ReplaySteps = null;
      for (let i = 0; i <= 3; i++) {
        try {
          if (i === 3) {
            const { finalRtmr, steps } = await replayRTMRWithSteps(events, 3);
            replayedRtmrs[3] = finalRtmr;
            rtmr3ReplaySteps = steps;
          } else {
            replayedRtmrs[i] = await replayRTMR(events, i);
          }
        } catch {
          replayedRtmrs[i] = null;
        }
      }

      const policiesByProfile = await fetchPoliciesForTag(tagToUse);

      setState({
        status: 'success',
        error: null,
        result: {
          attestation,
          ita_claims: ita_claims || null,
          ita_token_verified,
          composeHash,
          appId,
          tagToUse,
          compatMap,
          matches,
          profiles: compatMap?.compatibility?.profiles || {},
          quoteRtmrs,
          measurementSources,
          replayedRtmrs,
          policiesByProfile,
          eventCount: events.length,
          eventLog: events,
          rtmr3ReplaySteps,
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
