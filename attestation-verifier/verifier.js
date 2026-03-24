/**
 * Calimero Attestation Verifier
 * Extracts compose_hash from KMS attestation response and compares with release policy.
 * Supports: paste/fetch mode, or load by KMS URL (backend fetches + ITA).
 * ITA token signature verified server-side (Intel JWKS); no CORS in browser.
 */

const COMPOSE_HASH_RE = /^[a-fA-F0-9]{64}$/;
const RTMR_HEX_RE = /^[a-fA-F0-9]{96}$/;
const INIT_MR = '0'.repeat(96);
const REPO = 'calimero-network/mero-tee';
const API_BASE = (typeof window !== 'undefined' && window.VERIFIER_API_BASE) || '';

function $(sel) {
  return document.querySelector(sel);
}

function showResults(html, isError = false) {
  const el = $('#results');
  el.classList.remove('hidden');
  $('#results-content').innerHTML = html;
}

function showError(msg) {
  showResults(`<span class="result-err">${escapeHtml(msg)}</span>`, true);
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function extractComposeHashAndAppId(eventLog) {
  let composeHash = null;
  let appId = null;
  const events = Array.isArray(eventLog) ? eventLog : [];
  for (const event of events) {
    if (event.imr !== 3) continue;
    const name = event.event || '';
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
function extractRTMRsFromClaims(claims) {
  const result = { rtmr0: null, rtmr1: null, rtmr2: null, rtmr3: null, mrtd: null, tcb_status: null };
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

/** Compute SHA384 digest (hex). */
async function sha384Hex(data) {
  const buf = typeof data === 'string' ? hexToBytes(data) : data;
  const hash = await crypto.subtle.digest('SHA-384', buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const h = hex.replace(/\s/g, '');
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function computeEventDigest(event) {
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
  buf[off++] = 0x3a; // ':'
  buf.set(new TextEncoder().encode(eventName), off);
  off += eventName.length;
  buf[off++] = 0x3a;
  buf.set(payloadBytes, off);
  return buf;
}

async function digestForReplay(event) {
  return computeEventDigestHex(event);
}

async function computeEventDigestHex(event) {
  const buf = computeEventDigest(event);
  return sha384Hex(buf);
}

/** Replay RTMR from event log. Returns 96-char hex. */
async function replayRTMR(events, imr) {
  let mr = hexToBytes(INIT_MR);
  for (const event of events) {
    if (event.imr !== imr) continue;
    const digestHex = await digestForReplay(event); // sha384(event_type:event:payload)
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

async function fetchKmsReleases(limit = 10) {
  const perPage = 100;
  const maxPages = 3;
  const kmsReleases = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=${perPage}&page=${page}`);
    if (!res.ok) break;
    const releases = await res.json();
    if (!releases.length) break;
    for (const r of releases) {
      if (r.tag_name && r.tag_name.startsWith('mero-kms-v')) kmsReleases.push(r);
    }
    if (kmsReleases.length >= limit) break;
  }
  if (kmsReleases.length === 0) throw new Error('No mero-kms releases found');
  kmsReleases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return kmsReleases.slice(0, limit).map(r => r.tag_name);
}

async function fetchLatestKmsTag() {
  const tags = await fetchKmsReleases(1);
  return tags[0];
}

async function fetchCompatibilityMap(tag) {
  const url = API_BASE
    ? `${API_BASE}/api/compat-map?tag=${encodeURIComponent(tag)}`
    : `https://github.com/${REPO}/releases/download/${tag}/kms-phala-compatibility-map.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch compatibility map: ${res.status}`);
  return res.json();
}

/** Find a release whose compatibility map contains composeHash. Tries primaryTag first, then recent releases. */
async function findMatchingRelease(composeHash, primaryTag = null) {
  const recent = await fetchKmsReleases(5);
  const tagsToTry = primaryTag ? [primaryTag, ...recent.filter(t => t !== primaryTag)] : recent;
  let fallbackCompat = null;
  for (const tag of tagsToTry) {
    try {
      const compatMap = await fetchCompatibilityMap(tag);
      if (!fallbackCompat) fallbackCompat = { tag, compatMap };
      const profiles = compatMap?.compatibility?.profiles || {};
      const matches = [];
      for (const [profile, p] of Object.entries(profiles)) {
        const expected = (p.event_payload || '').toLowerCase();
        if (expected && expected === composeHash) matches.push(profile);
      }
      if (matches.length > 0) return { tag, compatMap, matches };
    } catch {
      continue;
    }
  }
  return { tag: fallbackCompat?.tag || recent[0], compatMap: fallbackCompat?.compatMap || null, matches: [] };
}

function parseAttestation(input) {
  let data;
  try {
    data = typeof input === 'string' ? JSON.parse(input) : input;
  } catch (e) {
    throw new Error('Invalid JSON: ' + e.message);
  }
  const eventLog = data.event_log ?? data.eventLog;
  if (!eventLog) throw new Error('Attestation response missing event_log');
  return { data, eventLog: Array.isArray(eventLog) ? eventLog : JSON.parse(eventLog) };
}

function truncateHex(h, len = 16) {
  if (!h || typeof h !== 'string') return '—';
  const s = h.replace(/\s/g, '');
  if (s.length <= len * 2) return s;
  return s.slice(0, len) + '…' + s.slice(-len);
}

function renderResultsCard(title, content, status = null) {
  const statusClass = status === 'ok' ? 'card-ok' : status === 'err' ? 'card-err' : status === 'warn' ? 'card-warn' : '';
  return `<div class="result-card ${statusClass}">
    <h3 class="card-title">${escapeHtml(title)}</h3>
    <div class="card-body">${content}</div>
  </div>`;
}

async function verifyKms() {
  const jsonInput = $('#attest-json').value.trim();
  const urlInput = $('#kms-url').value.trim();

  let attestation;
  if (jsonInput) {
    try {
      const { data, eventLog } = parseAttestation(jsonInput);
      attestation = { data, eventLog };
    } catch (e) {
      showError(e.message);
      return;
    }
  } else if (urlInput) {
    const releaseTag = $('#release-tag')?.value?.trim() || new URLSearchParams(location.search).get('release_tag') || undefined;
    await loadByKmsUrl(urlInput, releaseTag);
    return;
  } else {
    showError('Enter a KMS URL or paste attestation JSON');
    return;
  }

  const { composeHash, appId } = extractComposeHashAndAppId(attestation.eventLog);
  if (!composeHash) {
    showResults(
      renderResultsCard('Compose hash', '<span class="result-warn">No compose-hash found in event log.</span><br>app_id: ' + (appId || 'n/a') + '<br>Event log has ' + attestation.eventLog.length + ' events. Expected imr==3 event with name "compose-hash" and 64-char hex payload.', 'warn')
    );
    return;
  }

  showResults('<span class="result-warn">Comparing with release policy...</span>');

  let compatMap;
  try {
    const tag = await fetchLatestKmsTag();
    compatMap = await fetchCompatibilityMap(tag);
  } catch (e) {
    showResults(
      renderResultsCard('Compose hash', 'compose_hash: ' + composeHash + '<br>app_id: ' + (appId || 'n/a') + '<br><span class="result-warn">Could not fetch compatibility map: ' + escapeHtml(e.message) + '</span>')
    );
    return;
  }

  const profiles = compatMap?.compatibility?.profiles || {};
  const matches = [];
  for (const [profile, p] of Object.entries(profiles)) {
    const expected = (p.event_payload || '').toLowerCase();
    if (expected && expected === composeHash) matches.push(profile);
  }

  let composeContent = '<div class="hash-row"><span class="label">Received:</span><code>' + composeHash + '</code></div>';
  composeContent += '<div class="hash-row"><span class="label">app_id:</span><code>' + (appId || 'n/a') + '</code></div>';
  if (matches.length > 0) {
    composeContent += '<span class="result-ok">✓ MATCH</span> — profile(s): ' + matches.join(', ');
  } else {
    composeContent += '<span class="result-err">✗ NO MATCH</span><br>Expected (from ' + (compatMap?.compatibility?.version || 'release') + '):<br>';
    for (const [profile, p] of Object.entries(profiles)) {
      const h = (p.event_payload || '').toLowerCase();
      composeContent += '<div class="hash-row"><span class="label">' + profile + ':</span><code>' + (h || '(empty)') + '</code></div>';
    }
  }
  showResults(renderResultsCard('Compose hash', composeContent, matches.length > 0 ? 'ok' : 'err'));
}

$('#verify-kms').addEventListener('click', () => {
  verifyKms().catch(e => showError(e.message));
});

$('#fetch-kms').addEventListener('click', async () => {
  const url = $('#kms-url').value.trim();
  if (!url) {
    showError('Enter a KMS URL first');
    return;
  }
  $('#attest-json').value = '';
  await verifyKms();
});

/** Load verification by KMS URL. Backend fetches attestation, calls ITA, verifies token, returns result. */
async function loadByKmsUrl(kmsUrl, releaseTag = null) {
  if (!API_BASE || !kmsUrl) return;
  showResults('<span class="result-warn">Verifying (backend fetches attestation from KMS, verifies quote via Intel Trust Authority)...</span>');
  try {
    const res = await fetch(`${API_BASE}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kms_url: kmsUrl }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const { attestation, ita_token, ita_claims, ita_token_verified } = data;
    if (!attestation) throw new Error('No attestation in response');
    const eventLog = attestation.event_log ?? attestation.eventLog;
    const events = Array.isArray(eventLog) ? eventLog : (eventLog ? JSON.parse(eventLog) : []);
    const { composeHash, appId } = extractComposeHashAndAppId(events);
    let tagToUse, compatMap, matches;
    if (releaseTag) {
      tagToUse = releaseTag;
      try { compatMap = await fetchCompatibilityMap(releaseTag); } catch { compatMap = null; }
      matches = [];
      if (composeHash && compatMap?.compatibility?.profiles) {
        for (const [profile, p] of Object.entries(compatMap.compatibility.profiles)) {
          const expected = (p.event_payload || '').toLowerCase();
          if (expected && expected === composeHash) matches.push(profile);
        }
      }
    } else if (composeHash) {
      ({ tag: tagToUse, compatMap, matches } = await findMatchingRelease(composeHash));
    } else {
      tagToUse = await fetchLatestKmsTag();
      compatMap = null;
      matches = [];
    }
    const profiles = compatMap?.compatibility?.profiles || {};

    const quoteRtmrs = extractRTMRsFromClaims(ita_claims || {});
    const replayedRtmrs = {};
    for (let i = 0; i <= 3; i++) {
      try {
        replayedRtmrs[i] = await replayRTMR(events, i);
      } catch {
        replayedRtmrs[i] = null;
      }
    }

    const cards = [];

    cards.push(renderResultsCard(
      'Quote attestation',
      (ita_token_verified
        ? '<span class="result-ok">✓ Verified</span> — Quote verified by Intel Trust Authority. JWT signature signed by Intel (JWKS).'
        : '<span class="result-err">✗ Token verification failed</span> — Could not verify JWT signature.'),
      ita_token_verified ? 'ok' : 'err'
    ));

    const rtmrContent = [];
    for (let i = 0; i <= 3; i++) {
      const fromQuote = quoteRtmrs[`rtmr${i}`] || null;
      const replayed = replayedRtmrs[i];
      const match = fromQuote && replayed && fromQuote === replayed;
      rtmrContent.push(`
        <div class="rtmr-row">
          <span class="rtmr-label">RTMR${i}</span>
          <div class="rtmr-values">
            <div><span class="label">Received (quote):</span> <code>${truncateHex(fromQuote, 12)}</code></div>
            <div><span class="label">Replayed (event log):</span> <code>${truncateHex(replayed, 12)}</code></div>
            ${fromQuote && replayed ? `<span class="${match ? 'result-ok' : 'result-err'}">${match ? '✓ Match' : '✗ Mismatch'}</span>` : ''}
          </div>
        </div>`);
    }
    if (quoteRtmrs.mrtd) {
      rtmrContent.push(`<div class="rtmr-row"><span class="rtmr-label">MRTD</span><code>${truncateHex(quoteRtmrs.mrtd, 12)}</code></div>`);
    }
    if (quoteRtmrs.tcb_status) {
      rtmrContent.push(`<div class="rtmr-row"><span class="rtmr-label">TCB status</span><code>${escapeHtml(quoteRtmrs.tcb_status)}</code></div>`);
    }
    cards.push(renderResultsCard('RTMR measurements', rtmrContent.join('')));

    const composeContent = [];
    composeContent.push('<div class="hash-row"><span class="label">Received:</span><code>' + (composeHash || 'n/a') + '</code></div>');
    composeContent.push('<div class="hash-row"><span class="label">app_id:</span><code>' + (appId || 'n/a') + '</code></div>');
    if (composeHash && matches.length > 0) {
      composeContent.push('<span class="result-ok">✓ MATCH</span> — compose_hash matches release policy for profile(s): ' + matches.join(', ') + ' (' + escapeHtml(tagToUse) + ')');
    } else if (composeHash) {
      composeContent.push('<span class="result-err">✗ NO MATCH</span> — compose_hash not found in primary or last 5 releases.');
      if (compatMap) {
        composeContent.push('<div class="expected-section"><span class="label">Expected (from ' + escapeHtml(tagToUse) + '):</span></div>');
        for (const [profile, p] of Object.entries(profiles)) {
          const h = (p.event_payload || '').toLowerCase();
          composeContent.push('<div class="hash-row"><span class="label">' + profile + ':</span><code>' + (h || '(empty)') + '</code></div>');
        }
      }
    }
    cards.push(renderResultsCard('Compose hash', composeContent.join('<br>'), composeHash && matches.length > 0 ? 'ok' : composeHash ? 'err' : null));

    const eventLogContent = '<div class="event-count">' + events.length + ' events in event log</div>';
    cards.push(renderResultsCard('Event log', eventLogContent));

    const html = '<div class="results-grid">' + cards.join('') + '</div>' +
      (tagToUse ? '<p class="results-footer">Checked against release: ' + escapeHtml(tagToUse) + (matches.length > 0 ? ' (matched)' : '') + '</p>' : '');
    showResults(html);
  } catch (e) {
    showError(e.message);
  }
}

(function init() {
  const params = new URLSearchParams(location.search);
  const kmsUrl = params.get('kms_url');
  const releaseTag = params.get('release_tag');
  if (kmsUrl) {
    $('#kms-url').value = kmsUrl;
    if (releaseTag && $('#release-tag')) $('#release-tag').value = releaseTag;
    loadByKmsUrl(kmsUrl, releaseTag || undefined);
  }
})();
