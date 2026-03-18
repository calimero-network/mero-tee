/**
 * Compatibility map service.
 * Single responsibility: find matching release for compose_hash.
 */

import { fetchKmsReleases, fetchCompatibilityMap } from './api.js';

export async function findMatchingRelease(composeHash, primaryTag = null) {
  const recent = await fetchKmsReleases(5);
  const tagsToTry = primaryTag
    ? [primaryTag, ...recent.filter((t) => t !== primaryTag)]
    : recent;
  let fallbackCompat = null;
  for (const tag of tagsToTry) {
    try {
      const compatMap = await fetchCompatibilityMap(tag);
      if (!fallbackCompat) fallbackCompat = { tag, compatMap };
      const profiles = compatMap?.compatibility?.profiles || {};
      const matches = [];
      for (const [profile, p] of Object.entries(profiles)) {
        const expected = (p.event_payload ?? '').toLowerCase();
        if (expected && expected === composeHash) matches.push(profile);
      }
      if (matches.length > 0) return { tag, compatMap, matches };
    } catch {
      continue;
    }
  }
  return {
    tag: fallbackCompat?.tag || recent[0],
    compatMap: fallbackCompat?.compatMap || null,
    matches: [],
  };
}
