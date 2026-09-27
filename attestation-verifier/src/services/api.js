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

/**
 * Verify a pasted mero-kms `/attest` response. The KMS is reachable only inside its
 * VPC, so the operator fetches the response there; `nonceB64` is the nonce they sent.
 */
export async function verifyKmsAttestation(attestation, nonceB64 = null) {
  const base = getApiBase();
  const res = await fetch(`${base}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attestation, ...(nonceB64 ? { nonce_b64: nonceB64 } : {}) }),
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

export async function fetchKmsReleases(limit = 10) {
  const perPage = 100;
  const maxPages = 3;
  const kmsReleases = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await fetch(
      `https://api.github.com/repos/${REPO}/releases?per_page=${perPage}&page=${page}`
    );
    if (!res.ok) break;
    const releases = await res.json();
    if (!releases.length) break;
    for (const r of releases) {
      if (r.tag_name && r.tag_name.startsWith('mero-kms-v')) {
        kmsReleases.push(r);
      }
    }
    if (kmsReleases.length >= limit) break;
  }
  if (kmsReleases.length === 0) throw new Error('No mero-kms releases found');
  kmsReleases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return kmsReleases.slice(0, limit).map((r) => r.tag_name);
}

export async function fetchNodeReleases(limit = 10) {
  const perPage = 100;
  const maxPages = 3;
  const nodeReleases = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await fetch(
      `https://api.github.com/repos/${REPO}/releases?per_page=${perPage}&page=${page}`
    );
    if (!res.ok) break;
    const releases = await res.json();
    if (!releases.length) break;
    for (const r of releases) {
      if (r.tag_name && r.tag_name.startsWith('mero-tee-v')) {
        nodeReleases.push(r);
      }
    }
    if (nodeReleases.length >= limit) break;
  }
  if (nodeReleases.length === 0) throw new Error('No mero-tee node releases found');
  nodeReleases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return nodeReleases.slice(0, limit).map((r) => r.tag_name);
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
    : `https://github.com/${REPO}/releases/download/${tag}/kms-compatibility-map.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch compatibility map: ${res.status}`);
  return res.json();
}

/**
 * Fetch the KMS attestation policy for a release tag and profile.
 * Returns its `policy` object ({ kms_allowed_mrtd, kms_allowed_rtmr0..3, node_allowed_*, ... }).
 */
export async function fetchAttestationPolicy(tag, profile) {
  const base = getApiBase();
  const url = `${base}/api/policy?tag=${encodeURIComponent(tag)}&profile=${encodeURIComponent(profile)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch policy: ${res.status}`);
  const data = await res.json();
  return data?.policy || {};
}
