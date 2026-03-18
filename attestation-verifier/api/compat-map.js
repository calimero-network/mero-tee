/**
 * GET /api/compat-map?tag=mero-kms-v2.1.73
 * Proxies kms-phala-compatibility-map.json from GitHub releases (avoids CORS).
 */
const REPO = 'calimero-network/mero-tee';
const TAG_RE = /^mero-kms-v[\d.]+$/;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Cache-Control', 'public, max-age=300'); // 5 min

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const tag = (req.query?.tag || '').trim();
  if (!tag || !TAG_RE.test(tag)) {
    return res.status(400).json({ error: 'Valid tag required (e.g. mero-kms-v2.1.73)' });
  }

  const url = `https://github.com/${REPO}/releases/download/${tag}/kms-phala-compatibility-map.json`;
  try {
    const resp = await fetch(url, { headers: { 'User-Agent': 'calimero-attestation-verifier/1.0' } });
    if (!resp.ok) {
      return res.status(resp.status).json({ error: `GitHub returned ${resp.status}` });
    }
    const data = await resp.json();
    return res.status(200).json(data);
  } catch (e) {
    return res.status(502).json({ error: 'Failed to fetch compatibility map: ' + (e.message || 'unknown') });
  }
}
