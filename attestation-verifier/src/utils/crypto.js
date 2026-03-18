/**
 * Cryptographic utilities for attestation.
 * Single responsibility: SHA384 and RTMR replay.
 */

import { hexToBytes } from './hex.js';

const INIT_MR = '0'.repeat(96);

export async function sha384Hex(data) {
  const buf = typeof data === 'string' ? hexToBytes(data) : data;
  const hash = await crypto.subtle.digest('SHA-384', buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function buildEventDigestInput(event) {
  const eventType = event.event_type ?? event.eventType ?? 0;
  const eventName = (event.event || '').toString();
  const hasEventPayload = 'event_payload' in event;
  const hasEventPayloadCamel = 'eventPayload' in event;
  let payload = event.event_payload ?? event.eventPayload ?? '';
  if (typeof payload === 'string') payload = payload.trim();

  if (eventName === 'compose-hash') {
    const source = hasEventPayload ? 'event_payload' : hasEventPayloadCamel ? 'eventPayload' : 'none';
    console.log(`[crypto] compose-hash digest input: source=${source} event_payload=${JSON.stringify(event.event_payload)} eventPayload=${JSON.stringify(event.eventPayload)}`);
  }
  let payloadBytes;
  if (typeof payload === 'string' && /^[a-fA-F0-9]+$/.test(payload)) {
    payloadBytes = hexToBytes(payload);
  } else {
    payloadBytes = new TextEncoder().encode(payload || '');
  }
  const buf = new Uint8Array(4 + 1 + eventName.length + 1 + payloadBytes.length);
  const view = new DataView(buf.buffer);
  view.setUint32(0, eventType, true);
  let off = 4;
  buf[off++] = 0x3a;
  buf.set(new TextEncoder().encode(eventName), off);
  off += eventName.length;
  buf[off++] = 0x3a;
  buf.set(payloadBytes, off);
  return buf;
}

export async function computeEventDigestHex(event) {
  const buf = buildEventDigestInput(event);
  return sha384Hex(buf);
}

/** Replay RTMR from event log. Returns 96-char hex. */
export async function replayRTMR(events, imr) {
  const { finalRtmr } = await replayRTMRWithSteps(events, imr);
  return finalRtmr;
}

/**
 * Replay RTMR with step-by-step verification.
 * Formula: RTMR_new = SHA384(RTMR_old || SHA384(event_type:event:payload))
 * Returns { finalRtmr, steps } for UI verification.
 */
export async function replayRTMRWithSteps(events, imr) {
  const steps = [];
  let mr = hexToBytes(INIT_MR);
  const imrEvents = events.filter((e) => e.imr === imr);
  for (const event of imrEvents) {
    const digestComputed = await computeEventDigestHex(event);
    const digestStored = (event.digest || '').trim().toLowerCase();
    const digestMatch =
      digestStored && digestComputed
        ? digestComputed.toLowerCase() === digestStored
        : null;
    let content = hexToBytes(digestComputed);
    if (content.length < 48) {
      const padded = new Uint8Array(48);
      padded.set(content);
      content = padded;
    }
    const rtmrBefore = Array.from(mr)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const combined = new Uint8Array(mr.length + content.length);
    combined.set(mr);
    combined.set(content, mr.length);
    mr = new Uint8Array(await crypto.subtle.digest('SHA-384', combined));
    const rtmrAfter = Array.from(mr)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    steps.push({
      event: event.event || event.event_type,
      payload: event.event_payload ?? event.eventPayload,
      digestComputed,
      digestStored: digestStored || null,
      digestMatch,
      rtmrBefore,
      rtmrAfter,
    });
  }
  const finalRtmr = Array.from(mr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return { finalRtmr, steps };
}
