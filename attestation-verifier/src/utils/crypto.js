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
  let payload = event.event_payload ?? event.eventPayload ?? '';
  if (typeof payload === 'string') payload = payload.trim();
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
  let mr = hexToBytes(INIT_MR);
  for (const event of events) {
    if (event.imr !== imr) continue;
    const digestHex = await computeEventDigestHex(event);
    let content = hexToBytes(digestHex);
    if (content.length < 48) {
      const padded = new Uint8Array(48);
      padded.set(content);
      content = padded;
    }
    const combined = new Uint8Array(mr.length + content.length);
    combined.set(mr);
    combined.set(content, mr.length);
    mr = new Uint8Array(await crypto.subtle.digest('SHA-384', combined));
  }
  return Array.from(mr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
