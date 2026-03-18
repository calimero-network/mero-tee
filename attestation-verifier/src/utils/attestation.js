/**
 * Attestation parsing and extraction utilities.
 * Single responsibility: parse attestation payloads, extract compose_hash, RTMRs.
 */

import { RTMR_HEX_RE, COMPOSE_HASH_RE } from './hex.js';

export function parseAttestation(input) {
  let data;
  try {
    data = typeof input === 'string' ? JSON.parse(input) : input;
  } catch (e) {
    throw new Error('Invalid JSON: ' + e.message);
  }
  const eventLog = data.event_log ?? data.eventLog;
  if (!eventLog) throw new Error('Attestation response missing event_log');
  return {
    data,
    eventLog: Array.isArray(eventLog) ? eventLog : JSON.parse(eventLog),
  };
}

export function extractComposeHashAndAppId(eventLog) {
  let composeHash = null;
  let appId = null;
  const events = Array.isArray(eventLog) ? eventLog : [];
  for (const event of events) {
    if (event.imr !== 3) continue;
    const name = event.event || '';
    let payload = event.event_payload;
    if (typeof payload === 'string') payload = payload.trim();
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
        } else if (key.includes('mrtd') && /^[a-f0-9]{64}$/.test(norm)) {
          result.mrtd = norm;
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
