/**
 * KMS release matching.
 * Single responsibility: find the mero-kms release and profile whose KMS allowlists
 * (kms_allowed_mrtd, kms_allowed_rtmr0..3 in kms-attestation-policy.<profile>.json)
 * contain a quote's measurements -- the same check merod makes before trusting a KMS.
 */

import { fetchKmsReleases, fetchAttestationPolicy, fetchCompatibilityMap } from './api.js';

export const PROFILES = ['debug', 'debug-read-only', 'locked-read-only'];
const REGISTERS = ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];

function norm(v) {
  return typeof v === 'string' ? v.replace(/\s/g, '').toLowerCase() : '';
}

/** Profiles whose KMS allowlists contain every one of MRTD and RTMR0-3. */
export function matchingProfiles(measurements, policiesByProfile) {
  return PROFILES.filter((profile) => {
    const policy = policiesByProfile?.[profile];
    if (!policy) return false;
    return REGISTERS.every((reg) => {
      const value = norm(measurements?.[reg]);
      const list = policy[`kms_allowed_${reg}`];
      return value && Array.isArray(list) && list.some((a) => norm(a) === value);
    });
  });
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
