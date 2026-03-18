/**
 * Calimero Attestation Verifier
 * Extracts compose_hash from KMS attestation response and compares with release policy.
 * Supports: paste/fetch mode, or load by KMS URL (backend fetches + ITA).
 * ITA verification runs server-side; token signature verified client-side via Intel JWKS.
 */

import * as jose from 'https://esm.sh/jose@5';

const COMPOSE_HASH_RE = /^[a-fA-F0-9]{64}$/;
const ITA_JWKS_URL = 'https://portal.trustauthority.intel.com/certs';
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

async function fetchLatestKmsTag() {
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=30`);
  if (!res.ok) throw new Error('Failed to fetch releases');
  const releases = await res.json();
  const kmsReleases = releases.filter(r => r.tag_name && r.tag_name.startsWith('mero-kms-v'));
  if (kmsReleases.length === 0) throw new Error('No mero-kms releases found');
  kmsReleases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
  return kmsReleases[0].tag_name;
}

async function fetchCompatibilityMap(tag) {
  const url = `https://github.com/${REPO}/releases/download/${tag}/kms-phala-compatibility-map.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch compatibility map: ${res.status}`);
  return res.json();
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
    // Route via backend to avoid CORS (Phala KMS does not send CORS headers)
    await loadByKmsUrl(urlInput);
    return;
  } else {
    showError('Enter a KMS URL or paste attestation JSON');
    return;
  }

  const { composeHash, appId } = extractComposeHashAndAppId(attestation.eventLog);
  if (!composeHash) {
    showResults(
      '<span class="result-warn">No compose-hash found in event log.</span>\n\n' +
      'app_id: ' + (appId || 'n/a') + '\n\n' +
      'Event log has ' + attestation.eventLog.length + ' events. ' +
      'Expected imr==3 event with name "compose-hash" and 64-char hex payload.'
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
      '<span class="result-ok">Extracted values:</span>\n\n' +
      'compose_hash: ' + composeHash + '\n' +
      'app_id: ' + (appId || 'n/a') + '\n\n' +
      '<span class="result-warn">Could not fetch compatibility map: ' + escapeHtml(e.message) + '</span>'
    );
    return;
  }

  const profiles = compatMap?.compatibility?.profiles || {};
  const matches = [];
  for (const [profile, p] of Object.entries(profiles)) {
    const expected = (p.kms_compose_hash || '').toLowerCase();
    if (expected && expected === composeHash) {
      matches.push(profile);
    }
  }

  let html = '<span class="result-ok">Extracted:</span>\n\n';
  html += 'compose_hash: ' + composeHash + '\n';
  html += 'app_id: ' + (appId || 'n/a') + '\n\n';

  if (matches.length > 0) {
    html += '<span class="result-ok">✓ MATCH</span> — compose_hash matches release policy for profile(s): ' + matches.join(', ') + '\n';
  } else {
    html += '<span class="result-err">✗ NO MATCH</span> — compose_hash does not match any profile in the latest release.\n';
    html += 'Expected values from ' + (compatMap?.compatibility?.version || 'release') + ':\n';
    for (const [profile, p] of Object.entries(profiles)) {
      const h = (p.kms_compose_hash || '').toLowerCase();
      html += '  ' + profile + ': ' + (h || '(empty)') + '\n';
    }
  }

  showResults(html);
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

/** Verify ITA JWT signature against Intel JWKS. */
async function verifyitaToken(token) {
  if (!token || typeof token !== 'string') return { verified: false, error: 'No token' };
  const trimmed = token.replace(/^Bearer\s+/i, '').trim();
  if (trimmed.split('.').length !== 3) return { verified: false, error: 'Invalid JWT format' };
  try {
    const JWKS = jose.createRemoteJWKSet(new URL(ITA_JWKS_URL));
    await jose.jwtVerify(trimmed, JWKS, {
      issuer: 'https://portal.trustauthority.intel.com',
    });
    return { verified: true };
  } catch (e) {
    return { verified: false, error: e.message || 'Signature verification failed' };
  }
}

/** Load verification by KMS URL. Backend fetches attestation, calls ITA, returns result. */
async function loadByKmsUrl(kmsUrl) {
  if (!API_BASE || !kmsUrl) return;
  showResults('<span class="result-warn">Verifying (backend fetches attestation from KMS)...</span>');
  try {
    const res = await fetch(`${API_BASE}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kms_url: kmsUrl }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const { attestation, ita_token, ita_response } = data;
    if (!attestation) throw new Error('No attestation in response');
    const eventLog = attestation.event_log ?? attestation.eventLog;
    const events = Array.isArray(eventLog) ? eventLog : (eventLog ? JSON.parse(eventLog) : []);
    const { composeHash, appId } = extractComposeHashAndAppId(events);
    let compatMap;
    try {
      const tag = await fetchLatestKmsTag();
      compatMap = await fetchCompatibilityMap(tag);
    } catch (e) {
      compatMap = null;
    }
    const profiles = compatMap?.compatibility?.profiles || {};
    const matches = [];
    if (composeHash) {
      for (const [profile, p] of Object.entries(profiles)) {
        const expected = (p.kms_compose_hash || '').toLowerCase();
        if (expected && expected === composeHash) matches.push(profile);
      }
    }
    const tokenVerify = await verifyitaToken(ita_token);
    let html = '<span class="result-ok">ITA verified</span> — Quote verified by Intel Trust Authority.\n\n';
    if (tokenVerify.verified) {
      html += '<span class="result-ok">✓ Token signature verified</span> — JWT signed by Intel (JWKS).\n\n';
    } else {
      html += '<span class="result-err">✗ Token verification failed</span> — ' + escapeHtml(tokenVerify.error || 'unknown') + '\n\n';
    }
    html += 'compose_hash: ' + (composeHash || 'n/a') + '\n';
    html += 'app_id: ' + (appId || 'n/a') + '\n\n';
    if (composeHash && matches.length > 0) {
      html += '<span class="result-ok">✓ MATCH</span> — compose_hash matches release policy for: ' + matches.join(', ') + '\n\n';
    } else if (composeHash) {
      html += '<span class="result-err">✗ NO MATCH</span> — compose_hash does not match release policy.\n\n';
    }
    html += '<span class="result-ok">ITA attestation token:</span>\n';
    html += '<pre class="text-xs break-all mt-1" style="word-break:break-all;font-size:0.75rem;">' + escapeHtml((ita_token || '').slice(0, 200) + '...') + '</pre>';
    showResults(html);
  } catch (e) {
    showError(e.message);
  }
}

(function init() {
  const params = new URLSearchParams(location.search);
  const kmsUrl = params.get('kms_url');
  if (kmsUrl) {
    $('#kms-url').value = kmsUrl;
    loadByKmsUrl(kmsUrl);
  }
})();
