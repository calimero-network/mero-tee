/**
 * POST /api/verify
 * Accepts either:
 *   - { node_url } — backend fetches a fresh attestation from a merod node, verifies via ITA.
 *     merod 1.0 answers `GET /attestation?nonce=&purpose=kms` (and reports, bound into its
 *     quote, what it verified of the KMS its keys came from); an older merod answers
 *     `POST /admin-api/tee/attest`, which is asked when the first is not served.
 *   - { attestation, nonce_b64? } — a pasted attestation, e.g. a mero-kms `/attest` response.
 *     mero-kms replicas listen only inside their VPC, so this service cannot fetch from
 *     them: the operator calls `/attest` from inside the VPC and pastes the response. When
 *     `nonce_b64` (the nonce sent to `/attest`) is given, the quote must be bound to it.
 *   - { attestation, nonce_b64?, agent: true } — a pasted mero-agent-gate `/attest`
 *     response (docs/design/private-agents.md): additionally, report_data[32..64] must
 *     commit to the agent id and the provisioning, signing and owner keys the
 *     response names.
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
// Bare IPv4 addresses, and the Calimero fleet's node names: mdma names every
// node `<name>.relay.cloud.calimero.network` (staging:
// `<name>.relay.staging.cloud.calimero.network`) and the manager and cloud
// console link each one here. Every host must still resolve to public
// addresses only (below).
const DEFAULT_NODE_ALLOWED_HOSTS = [
  '^\\d+\\.\\d+\\.\\d+\\.\\d+$',
  '^[a-z0-9-]+\\.relay\\.cloud\\.calimero\\.network$',
  '^[a-z0-9-]+\\.relay\\.staging\\.cloud\\.calimero\\.network$',
].join(',');
const NODE_ALLOWED_HOSTS = (process.env.NODE_ALLOWED_HOSTS || DEFAULT_NODE_ALLOWED_HOSTS)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const NODE_ALLOW_PRIVATE = process.env.NODE_ALLOW_PRIVATE === '1';
// Where a KMS attestation may be fetched from (`kms_attest_url`): mdma's
// manager, which can reach the replicas this service cannot. It relays a
// replica's `/attest` for a nonce chosen HERE, so it cannot answer with an old
// or invented quote: Intel verifies the quote and the nonce is checked in it.
const KMS_ATTEST_ALLOWED_HOSTS = (
  process.env.KMS_ATTEST_ALLOWED_HOSTS ||
  '^manager\\.cloud\\.calimero\\.network$,^manager\\.staging\\.cloud\\.calimero\\.network$'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
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
/** A `kms_attest_url`: https, on an allowed host, resolving to public addresses. */
async function checkKmsAttestUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid KMS attestation URL');
  }
  if (parsed.protocol !== 'https:') throw new Error('KMS attestation URL must use HTTPS');
  if (parsed.username || parsed.password) throw new Error('KMS attestation URL must not carry credentials');
  const host = parsed.hostname.toLowerCase();
  if (!KMS_ATTEST_ALLOWED_HOSTS.some((re) => new RegExp(re).test(host))) {
    throw new Error('KMS attestation URL host not in allowed list. Set KMS_ATTEST_ALLOWED_HOSTS to override.');
  }
  const addresses = (await dns.lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
  if (addresses.length === 0 || !addresses.every(isPublicAddress)) {
    throw new Error('KMS attestation URL must name a public address');
  }
  return parsed;
}

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

// mero-agent-gate's report-data binding (mero-agent-gate/src/protocol.rs).
const AGENT_ATTEST_DOMAIN = Buffer.from('mero-agent-gate/attest/v3');
const NO_KEY = Buffer.alloc(32);
const AGENT_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;

function decodeKey32(field, value) {
  const bytes = typeof value === 'string' ? Buffer.from(value.trim(), 'base64') : Buffer.alloc(0);
  if (bytes.length !== 32) throw new Error(`${field} must be 32 bytes of base64`);
  return bytes;
}

/**
 * The agent and keys a mero-agent-gate quote commits to: report_data[32..64]
 * must be SHA-256(domain ‖ provisioning key ‖ len(agent id) ‖ agent id ‖
 * signing key ‖ owner key). An agent TD hosts several agents; the agent id
 * names which one, and is empty for a quote of the TD alone. The signing and
 * owner keys are 32 zero bytes while the agent is unclaimed. Returns them only
 * if the quote commits to them.
 */
function verifyAgentKeys(attestation) {
  const provisioning = decodeKey32('provisioningPublicKeyB64', attestation.provisioningPublicKeyB64);
  const agentId = attestation.agentId == null ? '' : String(attestation.agentId);
  if (agentId !== '' && !AGENT_ID.test(agentId)) {
    throw new Error('agentId must match [a-z0-9][a-z0-9-]{0,62}');
  }
  const signing = attestation.signingPublicKeyB64 == null
    ? null
    : decodeKey32('signingPublicKeyB64', attestation.signingPublicKeyB64);
  const owner = attestation.ownerPublicKeyB64 == null
    ? null
    : decodeKey32('ownerPublicKeyB64', attestation.ownerPublicKeyB64);
  if ((signing == null) !== (owner == null)) {
    throw new Error('A claimed agent has both a signing key and an owner; the gate named one');
  }
  const id = Buffer.from(agentId, 'utf8');
  const expected = crypto.createHash('sha256')
    .update(AGENT_ATTEST_DOMAIN).update(provisioning)
    .update(Buffer.from([id.length])).update(id)
    .update(signing ?? NO_KEY).update(owner ?? NO_KEY).digest();
  if (!quoteReportData(extractQuote(attestation)).subarray(32, 64).equals(expected)) {
    throw new Error('Quote does not commit to the agent and keys the gate named');
  }
  return {
    provisioningPublicKeyB64: provisioning.toString('base64'),
    agentId: agentId || null,
    signingPublicKeyB64: signing ? signing.toString('base64') : null,
    ownerPublicKeyB64: owner ? owner.toString('base64') : null,
  };
}

function verifyNonceInQuote(quoteB64, nonceBytes) {
  if (!quoteReportData(quoteB64).subarray(0, 32).equals(nonceBytes)) {
    throw new Error('Nonce mismatch: quote not bound to this request (possible replay)');
  }
}

/**
 * The node's transport key, if its quote commits to it: report_data[32..64]
 * must be core's `attest_transport_binding(zeros, key)`, or, when the node
 * reported what it verified of its KMS, core's `kms_evidence_binding` around
 * it. `null` key when the node reports none (it predates sealed transport).
 *
 * `kmsBound` says what became of a KMS record: `true` when the quote commits
 * to it (so it is as trustworthy as the node's own code), `false` when the
 * quote commits to the transport key alone (the record came from somewhere
 * else: a relay, the host), `null` when there is no record to judge.
 */
async function boundTransportKey(quoteB64, transportKeyHex, kms) {
  if (typeof transportKeyHex !== 'string' || !transportKeyHex) return { key: null, kmsBound: null };
  const key = Buffer.from(transportKeyHex, 'hex');
  if (key.length !== 32) throw new Error('Node reported a malformed transportPublicKey');
  const inner = Buffer.from(await transportKeyBinding(new Uint8Array(32), key));
  const actual = quoteReportData(quoteB64).subarray(32, 64);
  if (kms && actual.equals(kmsEvidenceBinding(inner, kms))) return { key, kmsBound: true };
  if (!actual.equals(inner)) {
    throw new Error('Quote does not commit to the transport key the node reported');
  }
  return { key, kmsBound: kms ? false : null };
}

// core's `calimero_client::attest::kms_evidence_binding` (crates/client/src/attest.rs).
const KMS_BINDING_DOMAIN = Buffer.from('calimero.tee-attest.kms-evidence.v1');
// A record is a few hundred bytes; a node's answer holds two at most.
const MAX_KMS_EVIDENCE_BYTES = 16 * 1024;
const KMS_RECORD_FIELDS = {
  kmsHost: 'host',
  release: 'release',
  profile: 'profile',
  mrtd: 'register',
  rtmr0: 'register',
  rtmr1: 'register',
  rtmr2: 'register',
  rtmr3: 'register',
  tcbStatus: 'text',
  quoteSha256: 'digest',
  verifiedAt: 'time',
  mock: 'flag',
};
const KMS_FIELD_OK = {
  host: (v) => typeof v === 'string' && /^[A-Za-z0-9.\-:[\]]{1,255}$/.test(v),
  release: (v) => typeof v === 'string' && /^\d+\.\d+\.\d+[0-9A-Za-z.+-]{0,32}$/.test(v),
  profile: (v) => typeof v === 'string' && /^[a-z0-9-]{1,64}$/.test(v),
  register: (v) => typeof v === 'string' && /^[0-9a-f]{96}$/.test(v),
  text: (v) => typeof v === 'string' && v.length <= 64,
  digest: (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v),
  time: (v) => Number.isSafeInteger(v) && v >= 0,
  flag: (v) => typeof v === 'boolean',
};
const KMS_REQUIRED = ['kmsHost', 'release', 'mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3', 'quoteSha256', 'verifiedAt'];

/**
 * The node's KMS record (`{ storage?, disk? }`), if it has the shape core
 * writes; `null` when the node sent none. Anything else is refused here,
 * before it is hashed or shown, so a record is either core's or nothing.
 */
export function kmsRecordOf(kms) {
  if (kms == null) return null;
  if (typeof kms !== 'object' || Array.isArray(kms)) throw new Error('Node reported a malformed kms record');
  if (JSON.stringify(kms).length > MAX_KMS_EVIDENCE_BYTES) throw new Error('Node reported an oversized kms record');
  const keys = Object.keys(kms);
  if (keys.length === 0 || !keys.every((k) => k === 'storage' || k === 'disk')) {
    throw new Error('Node reported a malformed kms record');
  }
  for (const k of keys) {
    const record = kms[k];
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Node reported a malformed kms record');
    for (const [field, value] of Object.entries(record)) {
      const kind = KMS_RECORD_FIELDS[field];
      if (!kind || !KMS_FIELD_OK[kind](value)) throw new Error(`Node reported a malformed kms record (${k}.${field})`);
    }
    if (!KMS_REQUIRED.every((f) => f in record)) throw new Error(`Node reported an incomplete kms record (${k})`);
  }
  return kms;
}

/** RFC 8785 (JCS) for JSON values: keys sorted by UTF-16 code units, ES number and string forms. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** SHA-256(domain ‖ inner ‖ SHA-256(JCS(kms))), as core binds the record. */
export function kmsEvidenceBinding(inner, kms) {
  const digest = crypto.createHash('sha256').update(canonicalJson(kms), 'utf8').digest();
  return crypto.createHash('sha256').update(KMS_BINDING_DOMAIN).update(inner).update(digest).digest();
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
async function answersAsTheAttestedKey(base, key, healthPath) {
  const guardedFetch = (input, init = {}) =>
    fetch(input, { ...init, redirect: 'manual', signal: AbortSignal.timeout(NODE_FETCH_TIMEOUT_MS) });
  const sealed = createSealedFetch({ baseUrl: base, transportPublicKey: key, fetch: guardedFetch });
  try {
    const response = await sealed(`${base}${healthPath}`);
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
  let agentKeys = null;
  // Node mode only: what the node verified of its KMS, and whether the quote
  // commits to it (see `boundTransportKey`). Both null: not reported.
  let kmsEvidence = null;
  let kmsEvidenceBound = null;
  let kmsEvidenceError = null;
  let nodeApi = null;
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const nodeUrl = (body?.node_url || body?.nodeUrl || '').trim();
    const kmsAttestUrl = (body?.kms_attest_url || '').trim();

    if (kmsAttestUrl) {
      const target = await checkKmsAttestUrl(kmsAttestUrl);
      const nonceBytes = crypto.randomBytes(32);
      let attestRes;
      try {
        attestRes = await fetch(target.href, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nonceB64: nonceBytes.toString('base64') }),
          redirect: 'manual',
          signal: AbortSignal.timeout(NODE_FETCH_TIMEOUT_MS),
        });
      } catch {
        return res.status(502).json({ error: 'The KMS attestation URL did not answer' });
      }
      if (!attestRes.ok) {
        return res.status(502).json({ error: `The KMS attestation URL failed: ${attestRes.status}` });
      }
      const raw = await attestRes.json();
      // Only the quote is kept, as for a node: the rest is the relay's word.
      attestation = { quoteB64: extractQuote(raw) };
      verifyNonceInQuote(attestation.quoteB64, nonceBytes);
      nonceVerified = true;
    } else if (nodeUrl) {
      const node = await checkNodeUrl(nodeUrl);
      const nonceBytes = crypto.randomBytes(32);
      const nonceHex = nonceBytes.toString('hex');
      const base = `${node.origin}${node.pathname.replace(/\/$/, '')}`;
      const attestV2 = () =>
        fetch(`${base}/attestation?nonce=${nonceHex}&purpose=kms`, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(NODE_FETCH_TIMEOUT_MS),
        });
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
      let raw = null;
      try {
        // merod 1.0 first. A node that answers it with anything but a quote
        // document (404, a page of HTML) is an older merod, asked the way it
        // always was; a 5xx is merod 1.0 failing, and is reported as such.
        attestRes = await attestV2();
        nodeApi = 'v2';
        if (attestRes.ok) {
          raw = await attestRes.json().catch(() => null);
        }
        const isDoc = raw && typeof raw === 'object' && typeof raw.quote === 'string';
        if (!isDoc && attestRes.status < 500) {
          nodeApi = 'v1';
          raw = null;
          attestRes = await attest({ nonce: nonceHex, bindTransportKey: true });
          // A merod from before sealed transport refuses the unknown field; ask
          // it again without, and report the transport check as undecided.
          if (attestRes.status === 400) {
            attestRes = await attest({ nonce: nonceHex });
          }
        }
      } catch {
        return res.status(502).json({ error: 'Node attestation endpoint did not answer' });
      }
      const endpoint = nodeApi === 'v2' ? '/attestation' : '/admin-api/tee/attest';
      if (!attestRes.ok) {
        // The status only: the body is the node's, and is not echoed.
        return res.status(502).json({ error: `Node ${endpoint} failed: ${attestRes.status}` });
      }
      if (raw == null) raw = await attestRes.json();
      const data = nodeApi === 'v2' ? raw : (raw?.data ?? raw);
      const quoteB64 = nodeApi === 'v2' ? data?.quote : (data?.quote_b64 ?? data?.quoteB64);
      if (typeof quoteB64 !== 'string' || !quoteB64.trim()) {
        return res.status(400).json({ error: `Node ${endpoint} response missing its quote` });
      }
      // Only the quote is kept. Everything else the node returns beside it is
      // its own description of the quote, and is not what Intel verifies --
      // except a KMS record the quote is found to commit to, below.
      attestation = { quoteB64: quoteB64.trim() };
      verifyNonceInQuote(attestation.quoteB64, nonceBytes);
      nonceVerified = true;
      // A record not in core's shape is dropped and said so, rather than
      // failing the node: the node's own checks below stand on the quote.
      let kms = null;
      try {
        kms = nodeApi === 'v2' ? kmsRecordOf(data?.kms) : null;
      } catch (e) {
        kmsEvidenceError = e.message;
      }
      const transportKeyHex = nodeApi === 'v2' ? data?.transportKey : data?.transportPublicKey;
      const { key: transportKey, kmsBound } = await boundTransportKey(attestation.quoteB64, transportKeyHex, kms);
      transportVerified = transportKey
        ? await answersAsTheAttestedKey(base, transportKey, nodeApi === 'v2' ? '/health' : '/admin-api/health')
        : null;
      kmsEvidence = kms;
      kmsEvidenceBound = kmsBound;
    } else {
      attestation = body?.attestation ?? body;
      if (!attestation || typeof attestation !== 'object') {
        return res.status(400).json({ error: 'Provide node_url, kms_attest_url, or attestation in request body' });
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
      if (body?.agent === true) {
        agentKeys = verifyAgentKeys(attestation);
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
    ...(nodeApi ? {
      node_api: nodeApi,
      kms_evidence: kmsEvidence,
      kms_evidence_bound: kmsEvidenceBound,
      ...(kmsEvidenceError ? { kms_evidence_error: kmsEvidenceError } : {}),
    } : {}),
    ...(agentKeys ? { agent_keys_verified: true, agent_keys: agentKeys } : {}),
  });
}
