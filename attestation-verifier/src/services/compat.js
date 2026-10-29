/**
 * KMS release matching.
 * Single responsibility: find the mero-kms release and profile whose KMS allowlists
 * (kms_allowed_mrtd, kms_allowed_rtmr0..3 in kms-attestation-policy.<profile>.json)
 * contain a quote's measurements -- the same check merod makes before trusting a KMS.
 */

import { fetchKmsReleases, fetchAttestationPolicy, fetchCompatibilityMap } from './api.js';
import { PROFILES, fullyMatchingProfiles } from '../lib/registers.js';

/** Profiles whose KMS allowlists contain every one of MRTD and RTMR0-3. */
export function matchingProfiles(measurements, policiesByProfile) {
  return fullyMatchingProfiles(measurements, policiesByProfile, 'kms');
}

async function loadRelease(tag) {
  const policiesByProfile = {};
  for (const profile of PROFILES) {
    try {
      policiesByProfile[profile] = await fetchAttestationPolicy(tag, profile);
    } catch {
      policiesByProfile[profile] = null;
    }
  }
  let compatMap = null;
  try {
    compatMap = await fetchCompatibilityMap(tag);
  } catch {
    compatMap = null;
  }
  return { tag, policiesByProfile, compatMap };
}

/**
 * Check `primaryTag` only when given; otherwise the five most recent KMS releases,
 * newest first. Falls back to the first release checked when none matches.
 */
export async function findMatchingRelease(measurements, primaryTag = null) {
  const tagsToTry = primaryTag ? [primaryTag] : await fetchKmsReleases(5);
  let fallback = null;
  for (const tag of tagsToTry) {
    const release = await loadRelease(tag);
    if (!fallback) fallback = release;
    const matches = matchingProfiles(measurements, release.policiesByProfile);
    if (matches.length > 0) return { ...release, matches };
  }
  return { ...fallback, matches: [] };
}
