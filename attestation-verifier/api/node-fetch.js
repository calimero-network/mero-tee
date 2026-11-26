/**
 * The fetch this API reaches a node with, and why one failed.
 *
 * Every node, production and staging, holds a publicly trusted certificate, so
 * a node is fetched with the public roots alone.
 *
 * The verdict does not rest on TLS: Intel verifies the quote, the nonce makes
 * it fresh, and the sealed handshake proves the URL holds the attested key.
 * TLS only carries the bytes.
 */

/** `fetch(url, init)` to a node, with the public roots. */
export function nodeFetch(url, init = {}) {
  return fetch(url, init);
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
