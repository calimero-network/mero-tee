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
import dns from 'node:dns/promises';
import net from 'node:net';
import { createSealedFetch, transportKeyBinding } from '@calimero-network/mero-js';
import * as jose from 'jose';

const ITA_URL = process.env.ITA_APPRAISAL_URL || 'https://api.trustauthority.intel.com/appraisal/v2/attest';
const ITA_JWKS_URL = 'https://portal.trustauthority.intel.com/certs';

// Node (merod) URLs: comma-separated host regexes. Default: a bare IPv4
// address. Whatever this allows, the address fetched must be a public one (see
// `isPublicAddress`) unless NODE_ALLOW_PRIVATE=1, which is for local
// development against a node on localhost or a private network.
const NODE_ALLOWED_HOSTS = (process.env.NODE_ALLOWED_HOSTS || '^\\d+\\.\\d+\\.\\d+\\.\\d+$')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const NODE_ALLOW_PRIVATE = process.env.NODE_ALLOW_PRIVATE === '1';
const NODE_FETCH_TIMEOUT_MS = 20_000;

// IPv4 ranges that are not the public internet: this host, private networks,
// CGNAT, loopback, link-local (cloud metadata), protocol assignments,
// benchmarking, documentation, multicast and reserved.
const NON_PUBLIC_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function v4ToInt(addr) {
  return addr.split('.').reduce((acc, octet) => (acc * 256) + Number(octet), 0);
}

function isPublicAddress(addr) {
  if (net.isIPv4(addr)) {
    const value = v4ToInt(addr);
    return !NON_PUBLIC_V4.some(([base, bits]) => {
      const size = 2 ** (32 - bits);
      const start = v4ToInt(base);
      return value >= start && value < start + size;
    });
  }
  if (net.isIPv6(addr)) {
    const a = addr.toLowerCase();
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPublicAddress(mapped[1]);
    // Loopback, unspecified, unique-local (fc00::/7), link-local (fe80::/10),
    // multicast, and the NAT64 / IPv4-compatible forms of the v4 ranges above.
    return !(a === '::1' || a === '::' || /^f[cd]/.test(a) || /^fe[89ab]/.test(a)
      || /^ff/.test(a) || a.startsWith('64:ff9b:') || a.startsWith('::'));
  }
  return false;
}

/**
 * The node URL, if its host is allowed and every address it names is public.
 * A hostname is resolved here and each address checked; the fetch resolves it
 * again, so an allowlist of hostnames is only as good as those names' DNS.
 */
async function checkNodeUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid node URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Node URL must use HTTP or HTTPS');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Node URL must not carry credentials');
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!NODE_ALLOWED_HOSTS.some((re) => new RegExp(re).test(host))) {
    throw new Error('Node URL host not in allowed list. Set NODE_ALLOWED_HOSTS to override.');
  }
  if (NODE_ALLOW_PRIVATE) return parsed;
  const addresses = net.isIP(host)
    ? [host]
    : (await dns.lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
  if (addresses.length === 0 || !addresses.every(isPublicAddress)) {
    throw new Error('Node URL must name a public address');
  }
  return parsed;
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

/**
 * The node's transport key, if its quote commits to it: report_data[32..64]
 * must be core's `attest_transport_binding(zeros, key)`. `null` when the node
 * reports no key (it predates sealed transport).
 */
async function boundTransportKey(quoteB64, transportKeyHex) {
  if (typeof transportKeyHex !== 'string' || !transportKeyHex) return null;
  const key = Buffer.from(transportKeyHex, 'hex');
  if (key.length !== 32) throw new Error('Node reported a malformed transportPublicKey');
  const expected = Buffer.from(await transportKeyBinding(new Uint8Array(32), key));
  if (!quoteReportData(quoteB64).subarray(32, 64).equals(expected)) {
    throw new Error('Quote does not commit to the transport key the node reported');
  }
  return key;
}

/**
 * Whether whoever answers at `base` holds the attested transport key: one
 * sealed request, whose handshake only the holder of the key can complete.
 *
 * A quote proves some attested TD holds the key, and a nonce proves the quote
 * is fresh, but neither says the URL IS that TD: a server there can forward
 * the attest call to a genuine node and answer with its quote. Completing a
 * handshake to the attested key over this URL is what does. `null` when the
 * node serves no sealed transport (only relay nodes do), so this cannot be
 * told either way.
 */
async function answersAsTheAttestedKey(base, key) {
  const guardedFetch = (input, init = {}) =>
    fetch(input, { ...init, redirect: 'manual', signal: AbortSignal.timeout(NODE_FETCH_TIMEOUT_MS) });
  const sealed = createSealedFetch({ baseUrl: base, transportPublicKey: key, fetch: guardedFetch });
  try {
    const response = await sealed(`${base}/admin-api/health`);
    return response.ok;
  } catch (e) {
    // No sealed endpoint at all (404/405 at the handshake) is "cannot tell";
    // anything else -- a handshake that fails against the attested key -- is no.
    if (e?.status === 404 || e?.status === 405) return null;
    return false;
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
  let transportVerified = null;
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const nodeUrl = (body?.node_url || body?.nodeUrl || '').trim();

    if (nodeUrl) {
      const node = await checkNodeUrl(nodeUrl);
      const nonceBytes = crypto.randomBytes(32);
      const nonceHex = nonceBytes.toString('hex');
      const base = `${node.origin}${node.pathname.replace(/\/$/, '')}`;
      const attest = (body) =>
        fetch(`${base}/admin-api/tee/attest`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          // A redirect would lead to a host that was never checked.
          redirect: 'manual',
          signal: AbortSignal.timeout(NODE_FETCH_TIMEOUT_MS),
        });
      let attestRes;
      try {
        attestRes = await attest({ nonce: nonceHex, bindTransportKey: true });
        // A merod from before sealed transport refuses the unknown field; ask
        // it again without, and report the transport check as undecided.
        if (attestRes.status === 400) {
          attestRes = await attest({ nonce: nonceHex });
        }
      } catch {
        return res.status(502).json({ error: 'Node /admin-api/tee/attest did not answer' });
      }
      if (!attestRes.ok) {
        // The status only: the body is the node's, and is not echoed.
        return res.status(502).json({ error: `Node /admin-api/tee/attest failed: ${attestRes.status}` });
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
      const transportKey = await boundTransportKey(attestation.quoteB64, data?.transportPublicKey);
      transportVerified = transportKey ? await answersAsTheAttestedKey(base, transportKey) : null;
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
    transport_verified: transportVerified,
  });
}
