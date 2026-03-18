/**
 * POST /api/verify
 * Accepts either:
 *   - { kms_url } — backend fetches attestation from KMS, verifies via ITA, returns result
 *   - { attestation } — attestation JSON (for direct paste/script use)
 */
import crypto from 'node:crypto';

const ITA_URL = process.env.ITA_APPRAISAL_URL || 'https://api.trustauthority.intel.com/appraisal/v2/attest';

// SSRF protection: allowed host patterns (regex). Default: phala.network, localhost.
const KMS_ALLOWED_HOSTS = (process.env.KMS_ALLOWED_HOSTS || 'phala\\.network$|^localhost$|^127\\.0\\.0\\.1$')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function validateKmsUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid KMS URL');
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    throw new Error('KMS URL must use HTTPS (except localhost)');
  }
  const host = parsed.hostname.toLowerCase();
  const allowed = KMS_ALLOWED_HOSTS.some((re) => new RegExp(re, 'i').test(host));
  if (!allowed) {
    throw new Error('KMS URL host not in allowed list (phala.network, localhost). Set KMS_ALLOWED_HOSTS to override.');
  }
}

function verifyNonceInAttestation(attestation, nonceBytes) {
  const reportDataHex = attestation.reportDataHex ?? attestation.report_data_hex;
  if (!reportDataHex || typeof reportDataHex !== 'string') {
    throw new Error('Attestation missing reportDataHex (cannot verify nonce)');
  }
  const hex = reportDataHex.replace(/\s/g, '');
  if (hex.length < 64) {
    throw new Error('reportDataHex too short for nonce verification');
  }
  const reportDataNonce = Buffer.from(hex.slice(0, 64), 'hex');
  if (reportDataNonce.length !== 32) {
    throw new Error('Invalid reportDataHex format');
  }
  if (!reportDataNonce.equals(nonceBytes)) {
    throw new Error('Nonce mismatch: attestation not bound to this request (possible replay)');
  }
}

function extractQuote(attestation) {
  const candidates = [];
  function walk(obj, path = '') {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      obj.forEach((v, i) => walk(v, `${path}[${i}]`));
      return;
    }
    for (const [k, v] of Object.entries(obj)) {
      const p = path ? `${path}.${k}` : k;
      if (typeof v === 'string' && /quote/i.test(k)) {
        const cleaned = v.trim();
        if (cleaned.length > 100 && /^[A-Za-z0-9+/=_-]+$/.test(cleaned)) {
          candidates.push({ score: /quote/i.test(k) ? 10 : 5, value: cleaned });
        }
      }
      walk(v, p);
    }
  }
  walk(attestation);
  if (candidates.length === 0) throw new Error('No quote found in attestation');
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].value;
}

async function callITA(quoteB64, apiKey) {
  const payloads = [
    { tdx: { quote: quoteB64 } },
    { quote: quoteB64 },
  ];
  for (const payload of payloads) {
    const res = await fetch(ITA_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'x-api-key': apiKey,
        'api-key': apiKey,
      },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const body = await res.json();
      const token = findToken(body);
      if (token) return { body, token };
    }
  }
  throw new Error('ITA verification failed');
}

function findToken(obj) {
  if (typeof obj === 'string') {
    const s = obj.trim();
    if (s.split('.').length === 3) return s.replace(/^Bearer\s+/i, '').trim();
    return null;
  }
  if (obj && typeof obj === 'object') {
    for (const v of Object.values(obj)) {
      const t = findToken(v);
      if (t) return t;
    }
  }
  return null;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.ITA_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: 'ITA_API_KEY not configured' });
  }

  let attestation;
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const kmsUrl = (body?.kms_url || body?.kmsUrl || '').trim();

    if (kmsUrl) {
      validateKmsUrl(kmsUrl);
      const nonceBytes = crypto.randomBytes(32);
      const nonceB64 = nonceBytes.toString('base64');
      const attestRes = await fetch(`${kmsUrl.replace(/\/$/, '')}/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonceB64 }),
      });
      if (!attestRes.ok) {
        const errText = await attestRes.text();
        return res.status(502).json({ error: `KMS /attest failed: ${attestRes.status}. ${errText.slice(0, 200)}` });
      }
      attestation = await attestRes.json();
      verifyNonceInAttestation(attestation, nonceBytes);
    } else {
      attestation = body?.attestation ?? body;
      if (!attestation || typeof attestation !== 'object') {
        return res.status(400).json({ error: 'Provide kms_url or attestation in request body' });
      }
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid request: ' + (e.message || 'parse error') });
  }

  let quoteB64;
  try {
    quoteB64 = extractQuote(attestation);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  let itaBody, itaToken;
  try {
    const result = await callITA(quoteB64, apiKey);
    itaBody = result.body;
    itaToken = result.token;
  } catch (e) {
    return res.status(502).json({ error: 'ITA verification failed: ' + (e.message || 'unknown') });
  }

  return res.status(200).json({
    attestation,
    ita_response: itaBody,
    ita_token: itaToken,
  });
}
