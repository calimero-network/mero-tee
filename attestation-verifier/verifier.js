/**
 * Calimero Attestation Verifier
 * Extracts compose_hash from KMS attestation response and compares with release policy.
 * Supports: paste/fetch mode, or load by KMS URL (backend fetches + ITA).
 * ITA token signature verified server-side (Intel JWKS); no CORS in browser.
 */

const COMPOSE_HASH_RE = /^[a-fA-F0-9]{64}$/;
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

async function fetchKmsReleases(limit = 10) {
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=30`);
  if (!res.ok) throw new Error('Failed to fetch releases');
  const releases = await res.json();
  const kmsReleases = releases.filter(r => r.tag_name && r.tag_name.startsWith('mero-kms-v'));
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
        const expected = (p.kms_compose_hash || '').toLowerCase();
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

/** Load verification by KMS URL. Backend fetches attestation, calls ITA, verifies token, returns result. */
async function loadByKmsUrl(kmsUrl, releaseTag = null) {
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
    const { attestation, ita_token, ita_response, ita_token_verified } = data;
    if (!attestation) throw new Error('No attestation in response');
    const eventLog = attestation.event_log ?? attestation.eventLog;
    const events = Array.isArray(eventLog) ? eventLog : (eventLog ? JSON.parse(eventLog) : []);
    const { composeHash, appId } = extractComposeHashAndAppId(events);
    const { tag: tagToUse, compatMap, matches } = composeHash
      ? await findMatchingRelease(composeHash, releaseTag || undefined)
      : { tag: releaseTag || (await fetchLatestKmsTag()), compatMap: null, matches: [] };
    const profiles = compatMap?.compatibility?.profiles || {};
    let html = '<span class="result-ok">ITA verified</span> — Quote verified by Intel Trust Authority.\n\n';
    if (ita_token_verified) {
      html += '<span class="result-ok">✓ Token signature verified</span> — JWT signed by Intel (JWKS).\n\n';
    } else {
      html += '<span class="result-err">✗ Token verification failed</span> — Could not verify JWT signature.\n\n';
    }
    html += 'compose_hash: ' + (composeHash || 'n/a') + '\n';
    html += 'app_id: ' + (appId || 'n/a') + '\n\n';
    if (composeHash && matches.length > 0) {
      html += '<span class="result-ok">✓ MATCH</span> — compose_hash matches release policy for: ' + matches.join(', ') + ' (' + escapeHtml(tagToUse) + ')\n\n';
    } else if (composeHash) {
      html += '<span class="result-err">✗ NO MATCH</span> — compose_hash not found in primary or last 5 releases.\n';
      if (compatMap) {
        html += 'Expected (from ' + escapeHtml(tagToUse) + '):\n';
        for (const [profile, p] of Object.entries(profiles)) {
          const h = (p.kms_compose_hash || '').toLowerCase();
          html += '  ' + profile + ': ' + (h || '(empty)') + '\n';
        }
      }
      html += '\n';
    }
    html += '<span class="result-ok">ITA attestation token:</span>\n';
    html += '<pre class="text-xs break-all mt-1" style="word-break:break-all;font-size:0.75rem;">' + escapeHtml((ita_token || '').slice(0, 200) + '...') + '</pre>\n';
    if (tagToUse) html += '<p class="text-slate-400 text-xs mt-2">Checked against: ' + escapeHtml(tagToUse) + (matches.length > 0 ? ' (matched)' : '') + '</p>';
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
