import { useState } from 'react';
import { Card } from '../ui/Card.jsx';
import { truncateHex } from '../../utils/hex.js';

function Rtmr3StepRow({ step, index }) {
  const [showDetail, setShowDetail] = useState(false);
  const digestOk = step.digestMatch === true;
  const digestFail = step.digestMatch === false;
  return (
    <div className="rtmr3-step">
      <button
        type="button"
        className="rtmr3-step-toggle"
        onClick={() => setShowDetail(!showDetail)}
      >
        <span className={`toggle-icon${showDetail ? ' open' : ''}`}>▶</span>
        Step {index + 1}: {step.event}
        {step.digestMatch !== null && (
          <span className={digestOk ? 'result-ok' : digestFail ? 'result-err' : ''}>
            {' '}
            {digestOk ? '✓ digest OK' : digestFail ? '✗ digest mismatch' : ''}
          </span>
        )}
      </button>
      {showDetail && (
        <div className="rtmr3-step-detail">
          <div className="rtmr3-formula">
            RTMR3_new = SHA384(RTMR3_old ‖ SHA384(event_type:event:payload))
          </div>
          <div className="hash-row">
            <span className="label">digest = SHA384(event):</span>{' '}
            <code title={step.digestComputed}>{truncateHex(step.digestComputed, 12)}</code>
            {step.digestStored && (
              <>
                {' '}
                <span className="label">stored:</span>{' '}
                <code title={step.digestStored}>{truncateHex(step.digestStored, 12)}</code>
                {step.digestMatch !== null && (
                  <span className={step.digestMatch ? 'result-ok' : 'result-err'}>
                    {' '}
                    {step.digestMatch ? '✓' : '✗'}
                  </span>
                )}
              </>
            )}
          </div>
          <div className="hash-row">
            <span className="label">RTMR3_old:</span>{' '}
            <code title={step.rtmrBefore}>{truncateHex(step.rtmrBefore, 12)}</code>
          </div>
          <div className="hash-row">
            <span className="label">RTMR3_new:</span>{' '}
            <code title={step.rtmrAfter}>{truncateHex(step.rtmrAfter, 12)}</code>
          </div>
        </div>
      )}
    </div>
  );
}

function EventSummary({ event, index }) {
  const name = (event.event || event.event_type) ?? '—';
  const payload = event.event_payload ?? event.eventPayload ?? '';
  const imr = event.imr ?? '—';
  const isComposeHash = name === 'compose-hash';
  const isAppId = name === 'app-id';
  const digest = event.digest ?? '';
  return (
    <div className="event-summary-row">
      <span className="event-imr">imr={imr}</span>
      <span className="event-name">{name}</span>
      <code className="event-payload">
        {typeof payload === 'string' && payload.length > 80
          ? truncateHex(payload, 16)
          : String(payload).slice(0, 64)}
        {String(payload).length > 64 && '…'}
      </code>
      {digest && (
        <code className="event-digest" title={digest}>
          digest: {truncateHex(digest, 8)}
        </code>
      )}
      {(isComposeHash || isAppId) && (
        <span className="event-badge">{isComposeHash ? 'compose_hash' : 'app_id'}</span>
      )}
    </div>
  );
}

export function EventLogCard({
  eventCount,
  eventLog,
  composeHash,
  appId,
  expectedComposeHashes,
  expectedPolicyComposeHashes,
  rtmr3ReplaySteps,
  quoteRtmr3,
  selectedProfile,
  style,
}) {
  const [expanded, setExpanded] = useState(false);
  const [showChain, setShowChain] = useState(false);
  const imr3Events = eventLog?.filter((e) => e.imr === 3) ?? [];
  const chainMatchesQuote =
    rtmr3ReplaySteps?.length > 0 &&
    quoteRtmr3 &&
    rtmr3ReplaySteps[rtmr3ReplaySteps.length - 1]?.rtmrAfter?.toLowerCase() ===
      quoteRtmr3.toLowerCase();
  const composeHashEvent = imr3Events.find((e) => e.event === 'compose-hash');
  const appIdEvent = imr3Events.find((e) => e.event === 'app-id');

  return (
    <Card title="Event log" style={style}>
      <div className="event-count">{eventCount} events</div>
      <div className="event-log-section">
        <h4 className="event-log-heading">imr=3 events (RTMR3 chain)</h4>
        <p className="event-log-desc">
          compose_hash and app_id from compose-hash and app-id events. RTMR3 chain:{' '}
          <code>RTMR3_new = SHA384(RTMR3_old ‖ SHA384(event_type:event:payload))</code>
        </p>
        {rtmr3ReplaySteps && rtmr3ReplaySteps.length > 0 && (
          <div className="event-log-section">
            <button
              type="button"
              className="event-log-toggle"
              onClick={() => setShowChain(!showChain)}
            >
              <span className={`toggle-icon${showChain ? ' open' : ''}`}>▶</span>
              Verify RTMR3 chain ({rtmr3ReplaySteps.length} steps)
              {quoteRtmr3 && (
                <span className={chainMatchesQuote ? 'result-ok' : 'result-err'}>
                  {' '}
                  {chainMatchesQuote ? '✓ Matches quote' : '✗ Mismatch'}
                </span>
              )}
            </button>
            {showChain && (
              <div className="rtmr3-chain">
                {rtmr3ReplaySteps.map((step, i) => (
                  <Rtmr3StepRow key={i} step={step} index={i} />
                ))}
              </div>
            )}
          </div>
        )}
        {composeHashEvent && (
          <div className="event-highlight">
            <span className="label">compose-hash event payload:</span>{' '}
            <code title={composeHashEvent.event_payload ?? composeHashEvent.eventPayload}>
              {composeHashEvent.event_payload ?? composeHashEvent.eventPayload ?? '—'}
            </code>
          </div>
        )}
        {appIdEvent && (
          <div className="event-highlight">
            <span className="label">app-id event payload:</span>{' '}
            <code title={appIdEvent.event_payload ?? appIdEvent.eventPayload}>
              {appIdEvent.event_payload ?? appIdEvent.eventPayload ?? '—'}
            </code>
          </div>
        )}
        {expectedComposeHashes && Object.keys(expectedComposeHashes).length > 0 && composeHash && (
          <div className="expected-compose-section">
            <span className="label">
              Compare to release{selectedProfile ? ` (${selectedProfile})` : ''}:
            </span>
            {(selectedProfile
              ? [[selectedProfile, expectedComposeHashes[selectedProfile]]].filter(
                  ([, p]) => p != null
                )
              : Object.entries(expectedComposeHashes)
            ).map(([profile, p]) => {
              const expected = (p?.event_payload ?? '').toLowerCase();
              const match = expected && composeHash === expected;
              return (
                <div key={profile} className="hash-row">
                  <span className="label">{profile}:</span> <code>{expected || '—'}</code>
                  {expected && (
                    <span className={match ? 'result-ok' : 'result-err'}>
                      {' '}
                      {match ? '✓ Match' : '✗ Mismatch'}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
        {expectedPolicyComposeHashes &&
          Object.keys(expectedPolicyComposeHashes).length > 0 &&
          composeHash && (
            <div className="expected-compose-section">
              <span className="label">
                Compare to profile policy allowlist
                {selectedProfile ? ` (${selectedProfile})` : ''}:
              </span>
              {(selectedProfile
                ? [[selectedProfile, expectedPolicyComposeHashes[selectedProfile]]].filter(
                    ([, h]) => h != null
                  )
                : Object.entries(expectedPolicyComposeHashes)
              ).map(([profile, hashes]) => {
                const values = Array.isArray(hashes) ? hashes.filter(Boolean) : [];
                const match = values.includes(composeHash);
                return (
                  <div key={profile} className="hash-row">
                    <span className="label">{profile}:</span> <code>{values.join(', ') || '—'}</code>
                    {values.length > 0 && (
                      <span className={match ? 'result-ok' : 'result-err'}>
                        {' '}
                        {match ? '✓ Match' : '✗ Mismatch'}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
      </div>
      <div className="event-log-section">
        <button
          type="button"
          className="event-log-toggle"
          onClick={() => setExpanded(!expanded)}
        >
          <span className={`toggle-icon${expanded ? ' open' : ''}`}>▶</span>
          All imr=3 events ({imr3Events.length})
        </button>
        {expanded && (
          <div className="event-list">
            {imr3Events.map((e, i) => (
              <EventSummary key={i} event={e} index={i} />
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}
