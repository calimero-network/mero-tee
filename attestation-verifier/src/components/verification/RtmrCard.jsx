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

function getProfilesWithValue(value, policiesByProfile, key) {
  if (!policiesByProfile || !value) return [];
  const profiles = [];
  for (const [profile, policy] of Object.entries(policiesByProfile)) {
    if (!policy) continue;
    const list = policy[key];
    if (isInAllowlist(value, list)) profiles.push(profile);
  }
  return profiles;
}

function hasAnyPolicy(policiesByProfile) {
  return policiesByProfile && Object.values(policiesByProfile).some(Boolean);
}

export function RtmrCard({ quoteRtmrs, replayedRtmrs, policiesByProfile, tagToUse }) {
  const showExpected = hasAnyPolicy(policiesByProfile);
  const rows = [];
  for (let i = 0; i <= 3; i++) {
    const fromQuote = quoteRtmrs?.[`rtmr${i}`] || null;
    const replayed = replayedRtmrs?.[i] ?? null;
    const replayMatch = fromQuote && replayed && fromQuote === replayed;
    const key = `allowed_rtmr${i}`;
    const inReleaseProfiles = policiesByProfile
      ? getProfilesWithValue(fromQuote, policiesByProfile, key)
      : [];

    rows.push(
      <div key={i} className="rtmr-row">
        <span className="rtmr-label">RTMR{i}</span>
        <div className="rtmr-values">
          <div>
            <span className="label">Received (quote):</span>{' '}
            <code>{truncateHex(fromQuote, 12)}</code>
          </div>
          <div>
            <span className="label">Replayed (event log):</span>{' '}
            <code>{truncateHex(replayed, 12)}</code>
            {fromQuote && replayed && (
              <span className={replayMatch ? 'result-ok' : 'result-err'}>
                {' '}
                {replayMatch ? '✓ Match' : '✗ Mismatch'}
              </span>
            )}
          </div>
          {showExpected && fromQuote && (
            <div className="rtmr-expected">
              <span className="label">In release allowlist ({tagToUse}):</span>{' '}
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
    const mrtdInProfiles = policiesByProfile
      ? getProfilesWithValue(quoteRtmrs.mrtd, policiesByProfile, 'allowed_mrtd')
      : [];
    rows.push(
      <div key="mrtd" className="rtmr-row">
        <span className="rtmr-label">MRTD</span>
        <div className="rtmr-values">
          <code>{truncateHex(quoteRtmrs.mrtd, 12)}</code>
          {showExpected && (
            <div className="rtmr-expected">
              <span className="label">In release allowlist:</span>{' '}
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
  return (
    <Card title="RTMR / MRTD measurements">
      <p className="rtmr-hint">
        RTMR0–2 are set by TDX firmware at boot; RTMR3 is extended by the event log at runtime.
        A match for RTMR3 indicates event log integrity. Values are compared against release policy
        allowlists.
      </p>
      {rows}
    </Card>
  );
}
