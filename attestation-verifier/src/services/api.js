/**
 * API client for attestation verifier backend.
 * Dependency inversion: depend on abstractions; fetch is injectable.
 */

const REPO = 'calimero-network/mero-tee';

function getApiBase() {
  if (typeof window !== 'undefined' && window.VERIFIER_API_BASE) {
    return window.VERIFIER_API_BASE;
  }
  return typeof window !== 'undefined' ? window.location.origin : '';
}

export async function verifyKmsAttestation(kmsUrl) {
  const base = getApiBase();
  const res = await fetch(`${base}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kms_url: kmsUrl }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function verifyNodeAttestation(nodeUrl) {
  const base = getApiBase();
  const res = await fetch(`${base}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_url: nodeUrl }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function fetchReleasesByPrefix(prefix, emptyMessage, limit = 10) {
  const perPage = 100;
  const maxPages = 3;
  const matching = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await fetch(
      `https://api.github.com/repos/${REPO}/releases?per_page=${perPage}&page=${page}`
    );
    if (!res.ok) break;
    const releases = await res.json();
    if (!releases.length) break;
    for (const r of releases) {
      if (r.tag_name && r.tag_name.startsWith(prefix)) {
        matching.push(r);
      }
    }
    if (matching.length >= limit) break;
  }
  if (matching.length === 0) throw new Error(emptyMessage);
  matching.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return matching.slice(0, limit).map((r) => r.tag_name);
}

export async function fetchKmsReleases(limit = 10) {
  return fetchReleasesByPrefix('mero-kms-v', 'No mero-kms releases found', limit);
}

export async function fetchNodeReleases(limit = 10) {
  return fetchReleasesByPrefix('mero-tee-v', 'No mero-tee node releases found', limit);
}

/**
 * Fetch node (mero-tee) measurement policy from published-mrtds.json.
 * Returns { profiles: { debug: {...}, "debug-read-only": {...}, "locked-read-only": {...} } }
 */
export async function fetchNodePolicy(tag) {
  const base = getApiBase();
  const url = `${base}/api/node-policy?tag=${encodeURIComponent(tag)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch node policy: ${res.status}`);
  const data = await res.json();
  return data?.profiles || {};
}

export async function fetchCompatibilityMap(tag) {
  const base = getApiBase();
  const url = base
    ? `${base}/api/compat-map?tag=${encodeURIComponent(tag)}`
    : `https://github.com/${REPO}/releases/download/${tag}/kms-phala-compatibility-map.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch compatibility map: ${res.status}`);
  return res.json();
}

/**
 * Fetch attestation policy (allowed MRTD/RTMR) for a release tag and profile.
 * Returns { policy: { allowed_mrtd, allowed_rtmr0, allowed_rtmr1, allowed_rtmr2, allowed_rtmr3 } }
 */
export async function fetchAttestationPolicy(tag, profile) {
  const base = getApiBase();
  const url = `${base}/api/policy?tag=${encodeURIComponent(tag)}&profile=${encodeURIComponent(profile)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch policy: ${res.status}`);
  const data = await res.json();
  return data?.policy || {};
}
