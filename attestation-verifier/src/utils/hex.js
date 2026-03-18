/**
 * Hex encoding/decoding utilities.
 * Single responsibility: hex manipulation only.
 */

const RTMR_HEX_RE = /^[a-fA-F0-9]{96}$/;
const COMPOSE_HASH_RE = /^[a-fA-F0-9]{64}$/;

export function hexToBytes(hex) {
  const h = String(hex).replace(/\s/g, '');
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

export function truncateHex(h, len = 16) {
  if (!h || typeof h !== 'string') return '—';
  const s = h.replace(/\s/g, '');
  if (s.length <= len * 2) return s;
  return s.slice(0, len) + '…' + s.slice(-len);
}

export function isRtmrHex(h) {
  return h && typeof h === 'string' && RTMR_HEX_RE.test(h.trim());
}

export function isComposeHashHex(h) {
  return h && typeof h === 'string' && COMPOSE_HASH_RE.test(h.trim());
}

export { RTMR_HEX_RE, COMPOSE_HASH_RE };
