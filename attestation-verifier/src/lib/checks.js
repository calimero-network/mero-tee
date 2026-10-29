/**
 * The verdict and checklist a result page shows, derived from what the API and
 * the hooks report. Every row is a check this verifier actually makes:
 *
 *   intel      api/verify.js callITA: Intel Trust Authority appraised the quote
 *              and returned a token (no token, no 200 response).
 *   token      api/verify.js `ita_token_verified`: the token's signature against
 *              Intel's JWKS.
 *   nonce      api/verify.js `nonce_verified`: report_data[0..32] is the nonce
 *              (the API's own for a node or kms_attest_url; the operator's for a paste).
 *   identity   api/verify.js `transport_verified` (nodes): the quote commits to the
 *              node's transport key and this URL completed a sealed handshake with it.
 *   keys       api/verify.js `agent_keys_verified` (agents): report_data[32..64]
 *              commits to the agent id and keys the gate named.
 *   kms        (nodes) api/verify.js `kms_evidence_bound`: the node's quote commits
 *              to its record of the KMS quote it accepted before taking its keys;
 *              hooks/useNodeVerification.js then checks the record's MRTD and
 *              RTMR0-3 against kms_allowed_* of the release and profile it names.
 *              Not reported (an older node): not checked, never a failure.
 *   measure    hooks + lib/registers.js: MRTD and RTMR0-3 parsed from the quote are
 *              in the release's published lists (node: published-mrtds.json; KMS:
 *              kms_allowed_* of kms-attestation-policy.<profile>.json; agent: the
 *              pasted agent policy).
 *   tcb        Intel's `attester_tcb_status` claim, shown for reference only: no
 *              path here fails on it, so it is never a pass.
 *
 * Status of a row: pass | fail | skip (not checked, with the reason) | info |
 * notrun (an earlier step stopped the run).
 */

import {
  compareRegisters,
  fullyMatchingProfiles,
  closestProfile,
  hasAnyPolicy,
  itaDisagreements,
} from './registers.js';

export const REPO = 'calimero-network/mero-tee';

export function releaseUrl(tag) {
  return `https://github.com/${REPO}/releases/tag/${encodeURIComponent(tag)}`;
}

export function releaseAssetUrl(tag, asset) {
  return `https://github.com/${REPO}/releases/download/${encodeURIComponent(tag)}/${asset}`;
}

export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url || '';
  }
}

const TITLES = {
  intel: 'Genuine Intel TDX quote',
  token: 'Intel’s verdict is authentic',
  nonce: 'Fresh quote',
  identity: 'This URL is the attested machine',
  keys: 'Quote commits to the agent’s keys',
  kms: 'Keys from a verified KMS',
  measure: 'Software matches the release',
  tcb: 'Platform patch level (TCB)',
};

const MEANINGS = {
  intel:
    'Intel Trust Authority checked the quote’s signature chain: it was produced by genuine Intel TDX hardware for a trust domain.',
  token: 'The verdict Intel returned is signed by Intel’s published keys, so it was not forged on the way back.',
  nonce: {
    node: 'This verifier sent the node a random nonce, and the quote carries it: the quote was made for this check, not replayed from an earlier one.',
    kmsUrl: 'This verifier sent a random nonce through the relay, and the quote carries it: the relay could not answer with an old or invented quote.',
    paste: 'The nonce you sent to /attest is in the quote’s report data: the quote was made for your request.',
  },
  identity:
    'The quote commits to the node’s transport key, and the server at this URL completed a sealed handshake with that key, so it is the attested machine and not a relay forwarding another node’s quote.',
  keys: 'The quote’s report data commits to the agent id and the provisioning, signing and owner keys the gate named.',
  kms:
    'This node accepted keys only from a KMS whose quote matched the signed mero-kms release policy. Its own quote commits to the KMS it accepted, and this verifier checks that KMS’s measurements against the policy the release published.',
  measure:
    'MRTD and RTMR0–3 record the firmware, boot path, kernel, command line and image profile that booted. All five must equal values the release published.',
  tcb: 'Intel’s assessment of the platform’s firmware and microcode patch level. Shown for reference: this verifier does not fail on it.',
};

function row(id, status, extra = {}) {
  return { id, title: TITLES[id], meaning: MEANINGS[id], status, ...extra };
}

/** The measurement comparison: which profile, which registers, and its row. */
function measurementCheck({ quoteRtmrs, policiesByProfile, policyError, tagToUse, kind, selectedProfile, matches }) {
  const policyKind = kind === 'kms' ? 'kms' : 'node';
  const label = kind === 'kms' ? 'KMS allowlists of' : 'measurements published in';
  if (!tagToUse || policyError || !hasAnyPolicy(policiesByProfile)) {
    return {
      row: row('measure', 'skip', {
        title: tagToUse ? `Software matches release ${tagToUse}` : TITLES.measure,
        reason: `The release’s published measurements could not be loaded${policyError ? ` (${policyError})` : ''}, so the software was not checked.`,
      }),
      comparison: null,
    };
  }
  const full = kind === 'kms'
    ? matches
    : fullyMatchingProfiles(quoteRtmrs, policiesByProfile, policyKind);
  const profile = full[0]
    || (selectedProfile && policiesByProfile[selectedProfile] ? selectedProfile : null)
    || closestProfile(quoteRtmrs, policiesByProfile, policyKind);
  const registers = compareRegisters(quoteRtmrs, policiesByProfile[profile], policyKind);
  const pass = full.length > 0;
  const mismatched = registers.filter((r) => !r.match).map((r) => r.reg.toUpperCase());
  const scope = selectedProfile ? `the ${selectedProfile} profile` : 'any profile';
  return {
    comparison: { profile, registers, matched: pass, tag: tagToUse },
    row: row('measure', pass ? 'pass' : 'fail', {
      title: `Software matches release ${tagToUse}`,
      result: pass
        ? `Matches the ${label} ${tagToUse} for ${full.join(', ')}`
        : `${mismatched.join(', ')} ${mismatched.length === 1 ? 'is' : 'are'} not in the ${label} ${tagToUse} for ${scope}`,
      registers,
      profile,
    }),
  };
}

const KEY_LABEL = { storage: 'Storage key', disk: 'Data-disk key' };

/** Seconds since the epoch as `2026-10-29 10:00 UTC`. */
export function formatUnix(secs) {
  if (!Number.isFinite(secs)) return 'an unknown time';
  return `${new Date(secs * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** The KMS of one key (or of several that agree), as a sentence: release, profile, MRTD, TCB, time. */
function kmsSentence(check, label = KEY_LABEL[check.key]) {
  const r = check.record;
  const parts = [
    `mero-kms v${r.release}`,
    r.profile ? `profile ${r.profile}` : null,
    `MRTD ${r.mrtd.slice(0, 12)}…`,
    r.tcbStatus ? `TCB ${r.tcbStatus}` : null,
  ].filter(Boolean);
  return `${label}: from a KMS matching ${parts.join(', ')}, verified at ${formatUnix(r.verifiedAt)}`;
}

/** Both keys from one KMS image (release, profile, registers) read as one sentence. */
function kmsSummary(checks) {
  const same = (a, b) => ['release', 'profile', 'mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3', 'tcbStatus']
    .every((f) => a.record[f] === b.record[f]);
  if (checks.length === 2 && same(checks[0], checks[1])) {
    const latest = checks[0].record.verifiedAt >= checks[1].record.verifiedAt ? checks[0] : checks[1];
    return kmsSentence(latest, 'Storage and data-disk keys');
  }
  return checks.map((c) => kmsSentence(c)).join('. ');
}

/** The KMS a node took its keys from: reported, bound into its quote, and in the published policy. */
function kmsRow(result) {
  if (result.kmsEvidenceError) {
    return row('kms', 'skip', {
      reason: `The node sent a KMS record this verifier does not accept (${result.kmsEvidenceError}), so which KMS it used was not checked.`,
    });
  }
  if (!result.kmsEvidence) {
    return row('kms', 'skip', {
      reason: 'Not reported by this node. Nodes before merod 1.0, and nodes whose KMS is pinned by configuration rather than a signed release, do not report which KMS they verified.',
    });
  }
  if (result.kmsEvidenceBound !== true) {
    return row('kms', 'skip', {
      reason: 'Reported, not bound: the node’s quote does not commit to the KMS record sent with it, so the record could have been added on the way and is not trusted.',
      kms: [],
    });
  }
  const checks = (result.kmsChecks || []).map((c) => {
    const profile = c.record.profile || c.matches[0] || null;
    return {
      ...c,
      profile,
      registers: compareRegisters(c.measurements, profile ? c.policiesByProfile[profile] : null, 'kms'),
    };
  });
  const unloaded = checks.filter((c) => c.error || !hasAnyPolicy(c.policiesByProfile));
  if (unloaded.length) {
    return row('kms', 'skip', {
      reason: `The node’s quote commits to its KMS record, but the KMS policy of ${unloaded.map((c) => c.tag).join(', ')} could not be loaded${unloaded[0].error ? ` (${unloaded[0].error})` : ''}, so the KMS was not checked against it.`,
      kms: checks,
    });
  }
  const mismatched = checks.filter((c) => c.matches.length === 0);
  if (mismatched.length) {
    return row('kms', 'fail', {
      result: mismatched.map((c) => `${KEY_LABEL[c.key]}: the KMS the node accepted is not in the KMS policy of ${c.tag}${c.record.profile ? ` for ${c.record.profile}` : ''}`).join('. '),
      kms: checks,
    });
  }
  return row('kms', 'pass', { result: kmsSummary(checks), kms: checks });
}

function tcbRow(quoteRtmrs) {
  const tcb = quoteRtmrs?.tcb_status;
  if (!tcb) return null;
  return row('tcb', 'info', { result: `Intel reports ${tcb}` });
}

/** A node or KMS result (hooks' `result`) as verdict + rows. */
export function modelFromResult(result) {
  const kind = result.kind;
  const rows = [];
  rows.push(row('intel', 'pass', { result: 'Intel Trust Authority accepted the quote and issued a token' }));
  rows.push(row('token', result.ita_token_verified ? 'pass' : 'fail', {
    result: result.ita_token_verified
      ? 'Signature checked against Intel’s JWKS'
      : 'The token’s signature did not verify against Intel’s JWKS',
  }));

  const nonceMeaning = kind === 'node' ? MEANINGS.nonce.node : result.attestUrl ? MEANINGS.nonce.kmsUrl : MEANINGS.nonce.paste;
  if (result.nonce_verified === true) {
    rows.push(row('nonce', 'pass', { meaning: nonceMeaning, result: 'The quote’s report data carries the nonce' }));
  } else {
    rows.push(row('nonce', 'skip', {
      meaning: nonceMeaning,
      reason: 'No nonce was given with the pasted response, so the quote could be an old one.',
    }));
  }

  if (kind === 'node') {
    const t = result.transport_verified;
    if (t === true) {
      rows.push(row('identity', 'pass', { result: 'Sealed handshake with the attested key succeeded' }));
    } else if (t === false) {
      rows.push(row('identity', 'fail', {
        result: 'The server at this URL could not complete a sealed handshake with the key the quote commits to. The quote may come from another node, relayed through this URL.',
      }));
    } else {
      rows.push(row('identity', 'skip', {
        reason: 'This node serves no sealed transport, so the verifier cannot tell whether the server at this URL is the attested machine or relays another node’s quote.',
      }));
    }
  }

  if (kind === 'node') rows.push(kmsRow(result));

  const { row: measureRow, comparison } = measurementCheck({ ...result, kind });
  rows.push(measureRow);
  const tcb = tcbRow(result.quoteRtmrs);
  if (tcb) rows.push(tcb);

  const required = new Set(['intel', 'token', 'measure', ...(kind === 'node' ? ['nonce'] : [])]);
  return {
    ...verdictOf(rows, required),
    rows,
    comparison,
    itaDisagree: itaDisagreements(result.quoteRtmrs, result.itaRtmrs),
  };
}

/** An agent result (AgentVerificationPage) as verdict + rows. */
export function modelFromAgent(result) {
  const rows = [
    row('intel', 'pass', { result: 'Intel Trust Authority accepted the quote and issued a token' }),
    row('token', result.itaVerified ? 'pass' : 'fail', {
      result: result.itaVerified ? 'Signature checked against Intel’s JWKS' : 'The token’s signature did not verify against Intel’s JWKS',
    }),
    result.nonceVerified
      ? row('nonce', 'pass', { meaning: MEANINGS.nonce.paste, result: 'The quote’s report data carries the nonce' })
      : row('nonce', 'skip', {
        meaning: MEANINGS.nonce.paste,
        reason: 'No nonce was given. The agent’s key can only be trusted from a quote made for your request.',
      }),
    row('keys', result.keysVerified ? 'pass' : 'fail', {
      result: result.keysVerified ? 'The quote commits to the named agent and keys' : 'The quote does not commit to the named keys',
    }),
  ];
  const mismatched = result.registers.filter((r) => !r.match).map((r) => r.reg.toUpperCase());
  rows.push(row('measure', result.policyOk ? 'pass' : 'fail', {
    title: `Software matches the agent policy${result.profile ? ` (${result.profile})` : ''}`,
    meaning: MEANINGS.measure.replace('the release published', 'the agent policy you pasted allows'),
    result: result.policyOk
      ? 'All five registers are in the agent policy'
      : `${mismatched.join(', ')} ${mismatched.length === 1 ? 'is' : 'are'} not in the agent policy`,
    registers: result.registers,
    profile: result.profile,
  }));
  const required = new Set(['intel', 'token', 'nonce', 'keys', 'measure']);
  return {
    ...verdictOf(rows, required),
    rows,
    comparison: { profile: result.profile, registers: result.registers, matched: result.policyOk, tag: null },
    itaDisagree: [],
  };
}

function verdictOf(rows, required) {
  const failed = rows.filter((r) => r.status === 'fail');
  const skipped = rows.filter((r) => r.status === 'skip');
  const requiredSkipped = skipped.filter((r) => required.has(r.id));
  const passed = rows.filter((r) => r.status === 'pass');
  let verdict = 'pass';
  if (failed.length) verdict = 'fail';
  else if (requiredSkipped.length) verdict = 'incomplete';
  return {
    verdict,
    counts: { passed: passed.length, failed: failed.length, skipped: skipped.length },
    caveats: verdict === 'pass' ? skipped : [],
  };
}

/** The checks a flow makes, in order, as "not run" rows (an error stopped the run). */
export function plannedRows(kind, { paste = false } = {}) {
  const ids = kind === 'node'
    ? ['intel', 'token', 'nonce', 'identity', 'kms', 'measure']
    : kind === 'agent'
      ? ['intel', 'token', 'nonce', 'keys', 'measure']
      : ['intel', 'token', 'nonce', 'measure'];
  return ids.map((id) => row(id, 'notrun', {
    meaning: id === 'nonce'
      ? (kind === 'node' ? MEANINGS.nonce.node : kind === 'agent' || paste ? MEANINGS.nonce.paste : MEANINGS.nonce.kmsUrl)
      : MEANINGS[id],
  }));
}
