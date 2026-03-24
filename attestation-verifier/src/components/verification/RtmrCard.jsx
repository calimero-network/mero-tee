import { Card } from '../ui/Card.jsx';
import { truncateHex } from '../../utils/hex.js';

function normalizeHex(v) {
  if (!v || typeof v !== 'string') return null;
  return v.replace(/\s/g, '').toLowerCase();
}

function isInAllowlist(value, allowlist) {
  if (!value || !Array.isArray(allowlist)) return false;
  const norm = normalizeHex(value);
  if (!norm) return false;
  return allowlist.some((a) => normalizeHex(a) === norm);
}

const POLICY_KEYS = {
  rtmr0: ['kms_allowed_rtmr0', 'allowed_rtmr0'],
  rtmr1: ['kms_allowed_rtmr1', 'allowed_rtmr1'],
  rtmr2: ['kms_allowed_rtmr2', 'allowed_rtmr2'],
  rtmr3: ['kms_allowed_rtmr3', 'allowed_rtmr3'],
  mrtd: ['kms_allowed_mrtd', 'allowed_mrtd'],
};

function getAllowlist(policy, key) {
  if (!policy) return null;
  const aliases = POLICY_KEYS[key];
  if (!aliases) return null;
  for (const k of aliases) {
    const list = policy[k];
    if (Array.isArray(list)) return list;
  }
  return null;
}

function getProfilesWithValue(value, policiesByProfile, key) {
  if (!policiesByProfile || !value) return [];
  const profiles = [];
  for (const [profile, policy] of Object.entries(policiesByProfile)) {
    if (!policy) continue;
    const list = getAllowlist(policy, key);
    if (isInAllowlist(value, list)) profiles.push(profile);
  }
  return profiles;
}

function getExpectedValue(policiesByProfile, profile, key) {
  const policy = policiesByProfile?.[profile];
  const list = getAllowlist(policy, key);
  return list?.[0] ?? null;
}

function hasAnyPolicy(policiesByProfile) {
  return policiesByProfile && Object.values(policiesByProfile).some(Boolean);
}

function inferProfile(quoteRtmrs, policiesByProfile, profileFromComposeHash) {
  if (!policiesByProfile) return profileFromComposeHash || null;
  if (quoteRtmrs?.mrtd) {
    const mrtdProfiles = getProfilesWithValue(quoteRtmrs.mrtd, policiesByProfile, 'mrtd');
    if (mrtdProfiles.length > 0) return mrtdProfiles[0];
  }
  for (let i = 0; i <= 3; i++) {
    const val = quoteRtmrs?.[`rtmr${i}`];
    const profiles = getProfilesWithValue(val, policiesByProfile, `rtmr${i}`);
    if (profiles.length > 0) return profiles[0];
  }
  return profileFromComposeHash || null;
}

/** When no profile inferred, use debug for expected display (common case). */
const DEFAULT_PROFILE = 'debug';

function itaDisagreesWithDisplayedQuote(quoteRtmrs, itaRtmrs) {
  if (!itaRtmrs || !quoteRtmrs) return false;
  const keys = ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];
  for (const k of keys) {
    const q = normalizeHex(quoteRtmrs[k]);
    const i = normalizeHex(itaRtmrs[k]);
    if (q && i && q !== i) return true;
  }
  return false;
}

export function RtmrCard({
  quoteRtmrs,
  itaRtmrs,
  measurementSources,
  replayedRtmrs,
  policiesByProfile,
  tagToUse,
  profileFromComposeHash,
}) {
  const showExpected = hasAnyPolicy(policiesByProfile);
  const inferredProfile = showExpected
    ? inferProfile(quoteRtmrs, policiesByProfile, profileFromComposeHash)
    : null;
  const rows = [];
  for (let i = 0; i <= 3; i++) {
    const val = quoteRtmrs?.[`rtmr${i}`] || null;
    const src = measurementSources?.[`rtmr${i}`];
    const sourceLabel = src === 'ita' ? 'ITA' : src === 'quote' ? 'quote' : null;
    const replayed = replayedRtmrs?.[i] ?? null;
    const replayMatch = val && replayed && val === replayed;
    const rtmrKey = `rtmr${i}`;
    const inReleaseProfiles = policiesByProfile
      ? getProfilesWithValue(val, policiesByProfile, rtmrKey)
      : [];
    const profileForExpected = inferredProfile || DEFAULT_PROFILE;
    const expectedVal = getExpectedValue(policiesByProfile, profileForExpected, rtmrKey);
    const allowlist = getAllowlist(policiesByProfile?.[profileForExpected], rtmrKey);
    const policyMatch = val && allowlist && isInAllowlist(val, allowlist);

    rows.push(
      <div key={i} className="rtmr-row">
        <span className="rtmr-label">RTMR{i}</span>
        <div className="rtmr-values">
          <div>
            <span className="label">Observed ({sourceLabel || '—'}):</span>{' '}
            <code>{truncateHex(val, 12)}</code>
          </div>
          {showExpected && (
            <div>
              <span className="label">Expected ({tagToUse} · {profileForExpected}):</span>{' '}
              <code>{truncateHex(expectedVal, 12)}</code>
              {allowlist && allowlist.length > 1 && (
                <span className="label" style={{ marginLeft: '0.25rem' }}>
                  (or one of {allowlist.length} values)
                </span>
              )}
              {val && allowlist && (
                <span className={policyMatch ? 'result-ok' : 'result-err'}>
                  {' '}
                  {policyMatch ? '✓ Match' : '✗ Mismatch'}
                </span>
              )}
            </div>
          )}
          {i === 3 && val && replayed && (
            <div className="rtmr-replay">
              <span className="label">Event log replay:</span>{' '}
              <code>{truncateHex(replayed, 12)}</code>
              <span className={replayMatch ? 'result-ok' : 'result-err'}>
                {' '}
                {replayMatch ? '✓ Matches quote' : '✗ Mismatch'}
              </span>
            </div>
          )}
          {showExpected && val && !policyMatch && (
            <div className="rtmr-expected">
              <span className="label">In release allowlist:</span>{' '}
              {inReleaseProfiles.length > 0 ? (
                <span className="result-ok">✓ {inReleaseProfiles.join(', ')}</span>
              ) : (
                <span className="result-err">✗ Not in any profile</span>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }
  if (quoteRtmrs?.mrtd) {
    const mrtdSrc = measurementSources?.mrtd;
    const mrtdSourceLabel = mrtdSrc === 'ita' ? 'ITA' : mrtdSrc === 'quote' ? 'quote' : null;
    const mrtdInProfiles = policiesByProfile
      ? getProfilesWithValue(quoteRtmrs.mrtd, policiesByProfile, 'mrtd')
      : [];
    const profileForMrtd = inferredProfile || DEFAULT_PROFILE;
    const expectedMrtd = getExpectedValue(policiesByProfile, profileForMrtd, 'mrtd');
    const mrtdAllowlist = getAllowlist(policiesByProfile?.[profileForMrtd], 'mrtd');
    const mrtdPolicyMatch =
      quoteRtmrs.mrtd && mrtdAllowlist && isInAllowlist(quoteRtmrs.mrtd, mrtdAllowlist);
    rows.unshift(
      <div key="mrtd" className="rtmr-row">
        <span className="rtmr-label">MRTD</span>
        <div className="rtmr-values">
          <div>
            <span className="label">Observed ({mrtdSourceLabel || '—'}):</span>{' '}
            <code>{truncateHex(quoteRtmrs.mrtd, 12)}</code>
          </div>
          {showExpected && (
            <div>
              <span className="label">Expected ({tagToUse} · {profileForMrtd}):</span>{' '}
              <code>{truncateHex(expectedMrtd, 12)}</code>
              {mrtdAllowlist && mrtdAllowlist.length > 1 && (
                <span className="label" style={{ marginLeft: '0.25rem' }}>
                  (or one of {mrtdAllowlist.length} values)
                </span>
              )}
              {quoteRtmrs.mrtd && mrtdAllowlist && (
                <span className={mrtdPolicyMatch ? 'result-ok' : 'result-err'}>
                  {' '}
                  {mrtdPolicyMatch ? '✓ Match' : '✗ Mismatch'}
                </span>
              )}
            </div>
          )}
          {showExpected && !mrtdPolicyMatch && (
            <div className="rtmr-expected">
              <span className="label">In allowlist:</span>{' '}
              {mrtdInProfiles.length > 0 ? (
                <span className="result-ok">✓ {mrtdInProfiles.join(', ')}</span>
              ) : (
                <span className="result-err">✗ Not in any profile</span>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }
  if (quoteRtmrs?.tcb_status) {
    rows.push(
      <div key="tcb" className="rtmr-row">
        <span className="rtmr-label">TCB status</span>
        <code>{quoteRtmrs.tcb_status}</code>
      </div>
    );
  }
  const itaMismatchWarning =
    itaRtmrs && itaDisagreesWithDisplayedQuote(quoteRtmrs, itaRtmrs);

  return (
    <Card title="RTMR / MRTD measurements">
      <p className="rtmr-hint">
        MRTD and RTMR0–3 shown for policy comparison are parsed from the TDX quote (same as published
        releases). All registers are compared against the release allowlist. Intel Trust Authority (ITA)
        JWT signature is verified separately. TCB status comes from ITA claims (when present). For KMS,
        RTMR3 is also checked against event log replay.
      </p>
      {itaMismatchWarning && (
        <p className="rtmr-hint">
          <strong>Note:</strong> At least one ITA JWT claim for MRTD/RTMR0–3 differs from the quote
          parse. Values above use the quote; see raw claims below.
        </p>
      )}
      {rows}
    </Card>
  );
}
