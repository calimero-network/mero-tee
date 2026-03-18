import { isComposeHashHex } from './hex.js';

const DEFAULT_PROFILES = ['debug', 'debug-read-only', 'locked-read-only'];

function normalizeComposeHash(value) {
  if (typeof value !== 'string') return '';
  const normalized = value.trim().toLowerCase();
  return isComposeHashHex(normalized) ? normalized : '';
}

export function buildPolicyComposeHashesByProfile(
  policiesByProfile = {},
  profiles = DEFAULT_PROFILES
) {
  const out = {};
  for (const profile of profiles) {
    const list = policiesByProfile?.[profile]?.policy?.kms_allowed_event_payload;
    const hashes = Array.isArray(list)
      ? list.map((v) => normalizeComposeHash(v)).filter(Boolean)
      : [];
    out[profile] = Array.from(new Set(hashes));
  }
  return out;
}

export function findPolicyComposeMatches(composeHash, policyComposeHashesByProfile = {}) {
  const target = normalizeComposeHash(composeHash);
  if (!target) return [];
  return Object.entries(policyComposeHashesByProfile)
    .filter(([, hashes]) => Array.isArray(hashes) && hashes.includes(target))
    .map(([profile]) => profile);
}

export function analyzeReleaseComposePublishing(
  compatProfiles = {},
  policyComposeHashesByProfile = {}
) {
  const profileNames = Array.from(
    new Set([
      ...Object.keys(compatProfiles || {}),
      ...Object.keys(policyComposeHashesByProfile || {}),
      ...DEFAULT_PROFILES,
    ])
  );
  const details = {};
  const inconsistentProfiles = [];

  for (const profile of profileNames) {
    const compatHash = normalizeComposeHash(compatProfiles?.[profile]?.event_payload ?? '');
    const policyHashes = Array.from(
      new Set((policyComposeHashesByProfile?.[profile] || []).map(normalizeComposeHash).filter(Boolean))
    );
    const consistent =
      (compatHash && policyHashes.includes(compatHash)) ||
      (!compatHash && policyHashes.length === 0);
    details[profile] = { compatHash, policyHashes, consistent };
    if (!consistent) inconsistentProfiles.push(profile);
  }

  return {
    allConsistent: inconsistentProfiles.length === 0,
    inconsistentProfiles,
    details,
  };
}
