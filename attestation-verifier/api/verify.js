/**
 * POST /api/verify
 * Accepts either:
 *   - { node_url } — backend fetches a fresh attestation from a merod node, verifies via ITA
 *   - { attestation, nonce_b64? } — a pasted attestation, e.g. a mero-kms `/attest` response.
 *     mero-kms replicas listen only inside their VPC, so this service cannot fetch from
 *     them: the operator calls `/attest` from inside the VPC and pastes the response. When
 *     `nonce_b64` (the nonce sent to `/attest`) is given, the quote must be bound to it.
 */
import crypto from 'node:crypto';
import * as jose from 'jose';

const ITA_URL = process.env.ITA_APPRAISAL_URL || 'https://api.trustauthority.intel.com/appraisal/v2/attest';
const ITA_JWKS_URL = 'https://portal.trustauthority.intel.com/certs';

// Node (merod) URLs: allow http for IPs and localhost. Pattern: ^\d+\.\d+\.\d+\.\d+$ for IPv4.
const NODE_ALLOWED_HOSTS = (process.env.NODE_ALLOWED_HOSTS || '^\\d+\\.\\d+\\.\\d+\\.\\d+$|^localhost$|^127\\.0\\.0\\.1$')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function validateNodeUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid node URL');
  }
  // Nodes typically use HTTP; allow for IPs and localhost
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Node URL must use HTTP or HTTPS');
  }
  const host = parsed.hostname.toLowerCase();
  const allowed = NODE_ALLOWED_HOSTS.some((re) => new RegExp(re).test(host));
  if (!allowed) {
    throw new Error('Node URL host not in allowed list (IP addresses, localhost). Set NODE_ALLOWED_HOSTS to override.');
  }
}

// TDX quote layout (Intel TDX DCAP): a 48-byte header, then the TD report body.
// A v5 quote adds a 6-byte body descriptor (type + size) before the body.
// report_data sits 384 bytes after MRTD (MRCONFIGID, MROWNER, MROWNERCONFIG
// and RTMR0-3 lie between them).
const MRTD_OFFSET = { 4: 184, 5: 190 };
const REPORT_DATA_FROM_MRTD = 384;

/**
 * report_data as the quote itself carries it: the bytes Intel Trust Authority
 * checks the signature over, not any field a node or a paste reports beside it.
 */
function quoteReportData(quoteB64) {
  const bytes = Buffer.from(quoteB64, 'base64');
  const version = bytes.length >= 2 ? bytes.readUInt16LE(0) : null;
  const mrtdOffset = MRTD_OFFSET[version];
  if (mrtdOffset == null) {
    throw new Error(`Unsupported TDX quote version ${version}`);
  }
  const start = mrtdOffset + REPORT_DATA_FROM_MRTD;
  if (bytes.length < start + 64) {
    throw new Error('Quote too short to carry report_data');
  }
  return bytes.subarray(start, start + 64);
}

function verifyNonceInQuote(quoteB64, nonceBytes) {
  if (!quoteReportData(quoteB64).subarray(0, 32).equals(nonceBytes)) {
    throw new Error('Nonce mismatch: quote not bound to this request (possible replay)');
  }
}

/** Merod: data.quoteB64; mero-kms `/attest`: top-level quoteB64. No tree walking / scoring. */
function extractQuote(attestation) {
  if (!attestation || typeof attestation !== 'object') {
    throw new Error('No attestation object');
  }
  const direct = attestation.quoteB64 ?? attestation.quote_b64;
  if (typeof direct === 'string' && direct.trim().length > 50) {
    return direct.trim();
  }
  const data = attestation.data;
  if (data && typeof data === 'object') {
    const q = data.quoteB64 ?? data.quote_b64;
    if (typeof q === 'string' && q.trim().length > 50) {
      return q.trim();
    }
  }
  throw new Error('Attestation missing quoteB64 (expected merod data.quoteB64 or top-level quote_b64)');
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
  let nonceVerified = null;
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const nodeUrl = (body?.node_url || body?.nodeUrl || '').trim();

    if (nodeUrl) {
      validateNodeUrl(nodeUrl);
      const nonceBytes = crypto.randomBytes(32);
      const nonceHex = nonceBytes.toString('hex');
      const base = nodeUrl.replace(/\/$/, '');
      const attestRes = await fetch(`${base}/admin-api/tee/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonce: nonceHex }),
      });
      if (!attestRes.ok) {
        const errText = await attestRes.text();
        return res.status(502).json({ error: `Node /admin-api/tee/attest failed: ${attestRes.status}. ${errText.slice(0, 200)}` });
      }
      const raw = await attestRes.json();
      const data = raw?.data ?? raw;
      const quoteB64 = data?.quote_b64 ?? data?.quoteB64;
      if (typeof quoteB64 !== 'string' || !quoteB64.trim()) {
        return res.status(400).json({ error: 'Node attest response missing quote_b64' });
      }
      // Only the quote is kept. Everything else the node returns beside it is
      // its own description of the quote, and is not what Intel verifies.
      attestation = { quoteB64: quoteB64.trim() };
      verifyNonceInQuote(attestation.quoteB64, nonceBytes);
      nonceVerified = true;
    } else {
      attestation = body?.attestation ?? body;
      if (!attestation || typeof attestation !== 'object') {
        return res.status(400).json({ error: 'Provide node_url, or attestation in request body' });
      }
      const nonceB64 = (body?.nonce_b64 || body?.nonceB64 || '').trim();
      if (nonceB64) {
        const nonceBytes = Buffer.from(nonceB64, 'base64');
        if (nonceBytes.length !== 32) {
          throw new Error('nonce_b64 must be 32 bytes, base64-encoded');
        }
        verifyNonceInQuote(extractQuote(attestation), nonceBytes);
        nonceVerified = true;
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

  let itaTokenVerified = false;
  let itaClaims = null;
  if (itaToken) {
    try {
      const JWKS = jose.createRemoteJWKSet(new URL(ITA_JWKS_URL));
      await jose.jwtVerify(itaToken.replace(/^Bearer\s+/i, '').trim(), JWKS, {
        issuer: 'https://portal.trustauthority.intel.com',
      });
      itaTokenVerified = true;
    } catch {
      /* signature verification failed */
    }
    try {
      const payload = jose.decodeJwt(itaToken.replace(/^Bearer\s+/i, '').trim());
      if (payload && typeof payload === 'object') itaClaims = payload;
    } catch {
      /* decode failed */
    }
  }

  return res.status(200).json({
    attestation,
    ita_response: itaBody,
    ita_token: itaToken,
    ita_token_verified: itaTokenVerified,
    ita_claims: itaClaims,
    nonce_verified: nonceVerified,
  });
}
