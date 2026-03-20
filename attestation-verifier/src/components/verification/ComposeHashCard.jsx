import { Card } from '../ui/Card.jsx';

export function ComposeHashCard({
  composeHash,
  appId,
  matches,
  policyMatches,
  profiles,
  policyComposeHashesByProfile,
  releaseComposePublishing,
  tagToUse,
}) {
  const hasCompatMatch = composeHash && matches?.length > 0;
  const hasPolicyMatch = composeHash && policyMatches?.length > 0;
  const hasAnyMatch = hasCompatMatch || hasPolicyMatch;
  const policyOnlyMatch = !hasCompatMatch && hasPolicyMatch;
  const publishingInconsistent =
    releaseComposePublishing && releaseComposePublishing.allConsistent === false;
  const inconsistentProfiles = releaseComposePublishing?.inconsistentProfiles || [];
  const canonicalMismatchButConsistent =
    composeHash && !hasAnyMatch && !publishingInconsistent;
  const cardStatus = hasCompatMatch
    ? 'ok'
    : policyOnlyMatch || canonicalMismatchButConsistent
      ? 'warn'
      : composeHash
        ? 'err'
        : null;

  return (
    <Card title="Compose hash" status={cardStatus}>
      <div className="hash-row">
        <span className="label">Received:</span>
        <code>{composeHash || 'n/a'}</code>
      </div>
      <div className="hash-row">
        <span className="label">app_id:</span>
        <code>{appId || 'n/a'}</code>
      </div>
      {hasCompatMatch && (
        <span className="result-ok">
          ✓ MATCH — compose_hash matches release policy for profile(s): {matches.join(', ')}{' '}
          ({tagToUse})
        </span>
      )}
      {policyOnlyMatch && (
        <span className="result-warn">
          ⚠ POLICY MATCH ONLY — compose_hash is allowed by profile policy ({policyMatches.join(', ')})
          but does not match compatibility map profile entries.
        </span>
      )}
      {composeHash && !hasAnyMatch && (
        <>
          <span className={publishingInconsistent ? 'result-err' : 'result-warn'}>
            {publishingInconsistent
              ? '✗ NO MATCH — compose_hash not found in primary or last 5 releases.'
              : '⚠ NO CANONICAL MATCH — compose_hash not found in primary or last 5 releases.'}
          </span>
          {publishingInconsistent ? (
            <div className="result-warn">
              Release asset publishing inconsistency detected for profile(s):{' '}
              <code>{inconsistentProfiles.join(', ') || 'unknown'}</code>. Compatibility map and
              profile policy allowlists disagree.
            </div>
          ) : (
            <div className="result-warn">
              Release assets are internally consistent. This usually indicates a deployment-specific
              compose hash (deployment name/app-id/env/rendering drift) rather than verifier
              extraction mismatch.
            </div>
          )}
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
      {policyComposeHashesByProfile &&
        Object.keys(policyComposeHashesByProfile).length > 0 &&
        !hasCompatMatch && (
          <div className="expected-section">
            <span className="label">Policy allowlist (kms_allowed_event_payload):</span>
            {Object.entries(policyComposeHashesByProfile).map(([profile, hashes]) => (
              <div key={profile} className="hash-row">
                <span className="label">{profile}:</span>
                <code>{Array.isArray(hashes) && hashes.length > 0 ? hashes.join(', ') : '(empty)'}</code>
              </div>
            ))}
          </div>
        )}
    </Card>
  );
}
