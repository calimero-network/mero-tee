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
} from '../utils/attestation.js';
import { replayRTMR } from '../utils/crypto.js';

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

      const quoteRtmrs = extractRTMRsFromClaims(ita_claims || {});
      const replayedRtmrs = {};
      for (let i = 0; i <= 3; i++) {
        try {
          replayedRtmrs[i] = await replayRTMR(events, i);
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
          replayedRtmrs,
          policiesByProfile,
          eventCount: events.length,
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
