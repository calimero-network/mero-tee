/**
 * Hook for KMS attestation verification.
 * Encapsulates verification flow, state, and side effects.
 */

import { useState, useCallback } from 'react';
import { verifyKmsAttestation, fetchKmsReleases, fetchAttestationPolicy, fetchCompatibilityMap } from '../services/api.js';
import { findMatchingRelease } from '../services/compat.js';
import {
  extractComposeHashAndAppId,
  extractRTMRsFromClaims,
  extractMeasurementsFromQuoteB64,
  mergeQuoteFirstMeasurements,
} from '../utils/attestation.js';
import { replayRTMR, replayRTMRWithSteps } from '../utils/crypto.js';
import {
  buildPolicyComposeHashesByProfile,
  findPolicyComposeMatches,
  analyzeReleaseComposePublishing,
} from '../utils/composeHashPolicy.js';

const PROFILES = ['debug', 'debug-read-only', 'locked-read-only'];
const logWarn = (...args) => {
  if (import.meta.env.DEV) {
    console.warn(...args);
  }
};

async function fetchPoliciesForTag(tag) {
  const results = {};
  for (const profile of PROFILES) {
    try {
      const policy = await fetchAttestationPolicy(tag, profile);
      results[profile] = policy;
    } catch (err) {
      logWarn(`[verifier] Failed to fetch policy for profile '${profile}' and tag '${tag}'`, err);
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

  const verify = useCallback(async (kmsUrl, releaseTag = null, selectedProfile = null) => {
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
      let tagToUse, compatMap, matches;
      if (releaseTag) {
        tagToUse = releaseTag;
        try {
          compatMap = await fetchCompatibilityMap(releaseTag);
        } catch (err) {
          logWarn(`[verifier] Failed to fetch compatibility map for tag '${releaseTag}'`, err);
          compatMap = null;
        }
        matches = [];
        if (composeHash && compatMap?.compatibility?.profiles) {
          for (const [profile, p] of Object.entries(compatMap.compatibility.profiles)) {
            const expected = (p.event_payload || '').toLowerCase();
            if (expected && expected === composeHash) matches.push(profile);
          }
        }
      } else if (composeHash) {
        ({ tag: tagToUse, compatMap, matches } = await findMatchingRelease(composeHash));
      } else {
        const latestTag = (await fetchKmsReleases(1))[0];
        tagToUse = latestTag;
        compatMap = null;
        matches = [];
      }
      // When selectedProfile is set, only consider it a match if composeHash matches that profile
      if (selectedProfile && compatMap?.compatibility?.profiles?.[selectedProfile]) {
        const expected = (compatMap.compatibility.profiles[selectedProfile].event_payload ?? '').toLowerCase();
        const matchForSelected = expected && composeHash === expected;
        matches = matchForSelected ? [selectedProfile] : [];
      }

      // Policy comparison: MRTD/RTMR0–3 from parsed quote first (matches release policy); ITA JWT verified separately.
      const fromITA = extractRTMRsFromClaims(ita_claims || {});
      const quoteB64 = attestation.quoteB64 ?? attestation.quote_b64;
      const fromQuote = quoteB64 ? extractMeasurementsFromQuoteB64(quoteB64) : null;
      const { quoteRtmrs, measurementSources, itaRtmrs } = mergeQuoteFirstMeasurements(
        fromQuote,
        fromITA
      );
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
        } catch (err) {
          logWarn(`[verifier] Failed to replay RTMR${i}`, err);
          replayedRtmrs[i] = null;
        }
      }

      const policiesByProfile = await fetchPoliciesForTag(tagToUse);
      const policyComposeHashesByProfile = buildPolicyComposeHashesByProfile(policiesByProfile);
      const policyMatches = composeHash
        ? findPolicyComposeMatches(composeHash, policyComposeHashesByProfile)
        : [];
      const releaseComposePublishing = analyzeReleaseComposePublishing(
        compatMap?.compatibility?.profiles || {},
        policyComposeHashesByProfile
      );

      setState({
        status: 'success',
        error: null,
        result: {
          attestation,
          ita_claims: ita_claims || null,
          ita_token_verified,
          itaRtmrs,
          composeHash,
          appId,
          tagToUse,
          compatMap,
          matches,
          selectedProfile: selectedProfile || null,
          profiles: compatMap?.compatibility?.profiles || {},
          policyMatches,
          policyComposeHashesByProfile,
          releaseComposePublishing,
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
