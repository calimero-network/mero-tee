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

export async function fetchKmsReleases(limit = 10) {
  const res = await fetch(
    `https://api.github.com/repos/${REPO}/releases?per_page=30`
  );
  if (!res.ok) throw new Error('Failed to fetch releases');
  const releases = await res.json();
  const kmsReleases = releases.filter(
    (r) => r.tag_name && r.tag_name.startsWith('mero-kms-v')
  );
  if (kmsReleases.length === 0) throw new Error('No mero-kms releases found');
  kmsReleases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return kmsReleases.slice(0, limit).map((r) => r.tag_name);
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
