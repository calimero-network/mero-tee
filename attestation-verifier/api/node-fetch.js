/**
 * The fetch this API reaches a node with.
 *
 * mdma orders the certificate of every node in its staging deployment from
 * Let's Encrypt's STAGING CA (to keep debug nodes off the production issuance
 * budget), whose roots are in no public trust store. Fetched with the public
 * roots alone, every staging node failed the TLS handshake, which read as "the
 * machine did not answer". For a staging relay host only
 * (`<name>.relay.staging.cloud.calimero.network`, or `NODE_STAGING_CA_HOSTS`),
 * this trusts the public roots plus the staging ones, as mdma itself does
 * (`mdma_common.node_tls`); every other host gets the plain `fetch`, public
 * roots only.
 *
 * The verdict does not rest on TLS: Intel verifies the quote, the nonce makes
 * it fresh, and the sealed handshake proves the URL holds the attested key.
 * TLS only carries the bytes.
 */
import https from 'node:https';
import tls from 'node:tls';
import { LE_STAGING_ROOTS } from './le-staging-roots.js';

const STAGING_CA_HOSTS = (process.env.NODE_STAGING_CA_HOSTS || '^[a-z0-9-]+\\.relay\\.staging\\.cloud\\.calimero\\.network$')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

export function usesStagingCa(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  return parsed.protocol === 'https:' && STAGING_CA_HOSTS.some((re) => new RegExp(re).test(host));
}

let stagingAgent = null;
function agent() {
  stagingAgent ??= new https.Agent({ ca: [...tls.rootCertificates, ...LE_STAGING_ROOTS], keepAlive: true });
  return stagingAgent;
}

function bodyBytes(body) {
  if (body == null) return null;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  throw new TypeError('nodeFetch: unsupported body type');
}

/** `fetch` over `node:https` with the staging roots; never follows a redirect. */
function stagingFetch(url, init = {}) {
  const body = bodyBytes(init.body);
  const headers = new Headers(init.headers || {});
  if (body) headers.set('content-length', String(body.length));
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      { method: init.method || 'GET', headers: Object.fromEntries(headers), agent: agent(), signal: init.signal },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('error', reject);
        res.on('end', () => {
          const out = new Headers();
          for (const [k, v] of Object.entries(res.headers)) {
            for (const one of Array.isArray(v) ? v : [v]) if (one != null) out.append(k, String(one));
          }
          const status = res.statusCode || 502;
          const empty = status === 204 || status === 304 || (init.method || 'GET') === 'HEAD';
          resolve(new Response(empty ? null : Buffer.concat(chunks), { status, statusText: res.statusMessage, headers: out }));
        });
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** `fetch(url, init)` to a node: with the staging roots for a staging host, else the plain fetch. */
export function nodeFetch(url, init = {}) {
  const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
  return usesStagingCa(href) ? stagingFetch(href, init) : fetch(url, init);
}

/**
 * Why a fetch to a node threw, in words: a timeout, an untrusted certificate
 * (with Node's code), or the network error. Never the node's own text.
 */
export function fetchFailure(e) {
  const cause = e?.cause ?? e;
  const code = cause?.code || e?.code || '';
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError' || cause?.name === 'TimeoutError') return 'timed out';
  if (/CERT|SELF_SIGNED|ISSUER|UNABLE_TO_VERIFY|ERR_TLS/i.test(code)) return `TLS certificate not trusted (${code})`;
  if (code) return code;
  return cause?.message || e?.message || 'unknown error';
}
