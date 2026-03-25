import { Card } from '../ui/Card.jsx';

export function QuoteAttestationCard({ verified }) {
  const status = verified == null ? null : verified ? 'ok' : 'err';
  return (
    <Card
      title="Quote attestation"
      status={status}
    >
      {verified == null ? (
        <span className="result-warn">
          Attestation token was returned but JWT signature status is unavailable.
        </span>
      ) : verified ? (
        <span className="result-ok">
          ✓ Verified — Quote verified by Intel Trust Authority. JWT signature signed by Intel (JWKS).
        </span>
      ) : (
        <span className="result-err">
          ✗ Token verification failed — Could not verify JWT signature.
        </span>
      )}
    </Card>
  );
}
