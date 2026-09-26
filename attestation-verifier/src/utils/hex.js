/**
 * Hex encoding/decoding utilities.
 * Single responsibility: hex manipulation only.
 */

const RTMR_HEX_RE = /^[a-fA-F0-9]{96}$/;

export function truncateHex(h, len = 16) {
  if (!h || typeof h !== 'string') return '—';
  const s = h.replace(/\s/g, '');
  if (s.length <= len * 2) return s;
  return s.slice(0, len) + '…' + s.slice(-len);
}

export function isRtmrHex(h) {
  return h && typeof h === 'string' && RTMR_HEX_RE.test(h.trim());
}

export { RTMR_HEX_RE };
