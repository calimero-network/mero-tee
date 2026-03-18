import { Card } from '../ui/Card.jsx';

export function ComposeHashCard({ composeHash, appId, matches, profiles, tagToUse }) {
  const hasMatch = composeHash && matches?.length > 0;
  return (
    <Card title="Compose hash" status={hasMatch ? 'ok' : composeHash ? 'err' : null}>
      <div className="hash-row">
        <span className="label">Received:</span>
        <code>{composeHash || 'n/a'}</code>
      </div>
      <div className="hash-row">
        <span className="label">app_id:</span>
        <code>{appId || 'n/a'}</code>
      </div>
      {hasMatch && (
        <span className="result-ok">
          ✓ MATCH — compose_hash matches release policy for profile(s): {matches.join(', ')}{' '}
          ({tagToUse})
        </span>
      )}
      {composeHash && !hasMatch && (
        <>
          <span className="result-err">✗ NO MATCH — compose_hash not found in primary or last 5 releases.</span>
          {profiles && Object.keys(profiles).length > 0 && (
            <div className="expected-section">
              <span className="label">Expected (from {tagToUse}):</span>
              {Object.entries(profiles).map(([profile, p]) => (
                <div key={profile} className="hash-row">
                  <span className="label">{profile}:</span>
                  <code>{(p.event_payload ?? '').toLowerCase() || '(empty)'}</code>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Card>
  );
}
