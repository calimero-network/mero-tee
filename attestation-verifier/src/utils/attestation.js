/**
 * Attestation parsing and extraction utilities.
 * Single responsibility: parse attestation payloads, extract compose_hash, RTMRs, MRTD from quote.
 */

import { RTMR_HEX_RE, COMPOSE_HASH_RE } from './hex.js';

// TDX quote binary layout (Intel TDX DCAP)
const QUOTE_HEADER_LEN = 48;
const MRTD_LEN = 48;
const MRTD_OFFSET_V4 = 184;
const MRTD_OFFSET_V5 = 190;
const RTMR0_OFFSET_FROM_MRTD = 192;

/** Extract MRTD and RTMR0-3 (48-byte hex each) from raw TDX quote base64. */
export function extractMeasurementsFromQuoteB64(quoteB64) {
  const out = { mrtd: null, rtmr0: null, rtmr1: null, rtmr2: null, rtmr3: null };
  if (!quoteB64 || typeof quoteB64 !== 'string') return out;
  const b64 = quoteB64.trim();
  let bytes;
  try {
    bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch {
    return out;
  }
  if (bytes.length < QUOTE_HEADER_LEN + MRTD_LEN) return out;
  const version = bytes[0] | (bytes[1] << 8);
  const mrtdOffset = version === 4 ? MRTD_OFFSET_V4 : version === 5 ? MRTD_OFFSET_V5 : null;
  if (mrtdOffset == null || mrtdOffset + MRTD_LEN > bytes.length) return out;
  out.mrtd = Array.from(bytes.slice(mrtdOffset, mrtdOffset + MRTD_LEN))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const rtmr0Offset = mrtdOffset + RTMR0_OFFSET_FROM_MRTD;
  if (rtmr0Offset + MRTD_LEN * 4 > bytes.length) return out;
  for (let i = 0; i < 4; i++) {
    const off = rtmr0Offset + i * MRTD_LEN;
    out[`rtmr${i}`] = Array.from(bytes.slice(off, off + MRTD_LEN))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return out;
}

export function extractComposeHashAndAppId(eventLog) {
  let composeHash = null;
  let appId = null;
  const events = Array.isArray(eventLog) ? eventLog : [];
  for (const event of events) {
    if (event.imr !== 3) continue;
    const name = event.event || '';
    // Match crypto.js buildEventDigestInput: use same payload source for consistency
    const hasEventPayload = 'event_payload' in event;
    const hasEventPayloadCamel = 'eventPayload' in event;
    let payload = event.event_payload ?? event.eventPayload ?? '';
    if (typeof payload === 'string') payload = payload.trim();

    if (name === 'compose-hash' || name === 'app-id') {
      const source = hasEventPayload ? 'event_payload' : hasEventPayloadCamel ? 'eventPayload' : 'none';
      const payloadPreview = typeof payload === 'string' ? payload.slice(0, 24) + (payload.length > 24 ? '...' : '') : payload;
      console.log(`[attestation] ${name}: source=${source} event_payload=${JSON.stringify(event.event_payload)} eventPayload=${JSON.stringify(event.eventPayload)} -> payload=${JSON.stringify(payloadPreview)}`);
    }

    if (name === 'compose-hash' && payload && COMPOSE_HASH_RE.test(payload)) {
      composeHash = payload.toLowerCase();
    } else if (name === 'app-id' && payload) {
      appId = typeof payload === 'string' ? payload : String(payload);
    }
  }
  return { composeHash, appId };
}

/** Extract RTMR0-3 and MRTD from ITA claims (nested JSON). */
export function extractRTMRsFromClaims(claims) {
  const result = {
    rtmr0: null,
    rtmr1: null,
    rtmr2: null,
    rtmr3: null,
    mrtd: null,
    tcb_status: null,
  };
  if (!claims || typeof claims !== 'object') return result;

  function walk(obj) {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      obj.forEach((v) => walk(v));
      return;
    }
    for (const [k, v] of Object.entries(obj)) {
      const key = k.toLowerCase();
      if (typeof v === 'string') {
        const norm = v.trim().toLowerCase();
        if (RTMR_HEX_RE.test(norm) && /rtmr|rt_mr/.test(key)) {
          if (key.includes('rtmr3') || key.includes('rt_mr3')) result.rtmr3 = norm;
          else if (key.includes('rtmr2') || key.includes('rt_mr2')) result.rtmr2 = norm;
          else if (key.includes('rtmr1') || key.includes('rt_mr1')) result.rtmr1 = norm;
          else if (key.includes('rtmr0') || key.includes('rt_mr0')) result.rtmr0 = norm;
        } else if (key.includes('mrtd') && (/^[a-f0-9]{96}$/.test(norm) || /^[a-f0-9]{64}$/.test(norm))) {
          result.mrtd = norm; // TDX MRTD is 48 bytes (96 hex); some sources use 64
        }
      } else if (key === 'attester_tcb_status' && typeof v === 'string') {
        result.tcb_status = v;
      }
      walk(v);
    }
  }
  walk(claims);
  return result;
}

/**
 * Prefer measurements parsed from the TDX quote for policy comparison (matches
 * published-mrtds.json and CI extract_tdx_policy_candidates). Fall back to ITA
 * JWT claims when the quote cannot be parsed. ITA signature is verified separately.
 */
export function mergeQuoteFirstMeasurements(fromQuote, fromITA) {
  const ita = fromITA || {};
  const q = fromQuote || {};
  return {
    quoteRtmrs: {
      mrtd: q.mrtd ?? ita.mrtd,
      rtmr0: q.rtmr0 ?? ita.rtmr0,
      rtmr1: q.rtmr1 ?? ita.rtmr1,
      rtmr2: q.rtmr2 ?? ita.rtmr2,
      rtmr3: q.rtmr3 ?? ita.rtmr3,
      tcb_status: ita.tcb_status ?? null,
    },
    measurementSources: {
      mrtd: q.mrtd ? 'quote' : ita.mrtd ? 'ita' : null,
      rtmr0: q.rtmr0 ? 'quote' : ita.rtmr0 ? 'ita' : null,
      rtmr1: q.rtmr1 ? 'quote' : ita.rtmr1 ? 'ita' : null,
      rtmr2: q.rtmr2 ? 'quote' : ita.rtmr2 ? 'ita' : null,
      rtmr3: q.rtmr3 ? 'quote' : ita.rtmr3 ? 'ita' : null,
    },
    itaRtmrs: {
      mrtd: ita.mrtd || null,
      rtmr0: ita.rtmr0 || null,
      rtmr1: ita.rtmr1 || null,
      rtmr2: ita.rtmr2 || null,
      rtmr3: ita.rtmr3 || null,
    },
  };
}
