/**
 * GET /api/node-policy?tag=mero-tee-v2.2.4
 * Proxies published-mrtds.json from GitHub releases (avoids CORS).
 * Returns { profiles: { debug: {...}, "debug-read-only": {...}, "locked-read-only": {...} } }
 */
const REPO = 'calimero-network/mero-tee';
const NODE_TAG_RE = /^mero-tee-v[\d.]+$/;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Cache-Control', 'public, max-age=300'); // 5 min

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const tag = (req.query?.tag || '').trim();
  if (!tag || !NODE_TAG_RE.test(tag)) {
    return res.status(400).json({ error: 'Valid node tag required (e.g. mero-tee-v2.2.4)' });
  }

  const url = `https://github.com/${REPO}/releases/download/${tag}/published-mrtds.json`;
  try {
    const resp = await fetch(url, { headers: { 'User-Agent': 'calimero-attestation-verifier/1.0' } });
    if (!resp.ok) {
      return res.status(resp.status).json({ error: `GitHub returned ${resp.status}` });
    }
    const data = await resp.json();
    const profiles = data?.profiles || {};
    return res.status(200).json({ profiles });
  } catch (e) {
    return res.status(502).json({ error: 'Failed to fetch node policy: ' + (e.message || 'unknown') });
  }
}
