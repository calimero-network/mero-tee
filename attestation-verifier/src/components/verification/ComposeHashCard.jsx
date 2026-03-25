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
  selectedProfile,
  style,
}) {
  const hasCompatMatch = composeHash && matches?.length > 0;
  const hasPolicyMatch = composeHash && policyMatches?.length > 0;
  const hasAnyMatch = hasCompatMatch || hasPolicyMatch;
  const policyOnlyMatch = !hasCompatMatch && hasPolicyMatch;
  const publishingInconsistent =
    releaseComposePublishing && releaseComposePublishing.allConsistent === false;
  const inconsistentProfiles = releaseComposePublishing?.inconsistentProfiles || [];
  const cardStatus = hasCompatMatch ? 'ok' : policyOnlyMatch ? 'warn' : composeHash ? 'err' : null;

  const profilesToShow =
    selectedProfile && profiles?.[selectedProfile]
      ? [[selectedProfile, profiles[selectedProfile]]]
      : profiles
        ? Object.entries(profiles)
        : [];
  const policyProfilesToShow =
    selectedProfile && policyComposeHashesByProfile?.[selectedProfile]
      ? [[selectedProfile, policyComposeHashesByProfile[selectedProfile]]]
      : policyComposeHashesByProfile
        ? Object.entries(policyComposeHashesByProfile)
        : [];

  return (
    <Card title="Compose hash" status={cardStatus} style={style}>
      <div className="hash-row">
        <span className="label">Received:</span>
        <code>{composeHash || 'n/a'}</code>
      </div>
      <div className="hash-row">
        <span className="label">app_id:</span>
        <code>{appId || 'n/a'}</code>
      </div>
      {selectedProfile && (
        <div className="hash-row">
          <span className="label">Verifying against profile:</span>
          <code>{selectedProfile}</code>
        </div>
      )}
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
          <span className="result-err">
            ✗ NO MATCH
            {selectedProfile ? ` for profile ${selectedProfile}` : ' — compose_hash not found in primary or last 5 releases'}
            .
          </span>
          {!selectedProfile && (
            publishingInconsistent ? (
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
            )
          )}
          {profilesToShow.length > 0 && (
            <div className="expected-section">
              <span className="label">
                Expected {selectedProfile ? `for ${selectedProfile}` : ''} (from {tagToUse}):
              </span>
              {profilesToShow.map(([profile, p]) => (
                <div key={profile} className="hash-row">
                  <span className="label">{profile}:</span>
                  <code>{(p.event_payload ?? '').toLowerCase() || '(empty)'}</code>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {policyProfilesToShow.length > 0 && !hasCompatMatch && (
        <div className="expected-section">
          <span className="label">Policy allowlist {selectedProfile ? `(${selectedProfile})` : ''}:</span>
          {policyProfilesToShow.map(([profile, hashes]) => (
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
