import { Card } from '../ui/Card.jsx';

export function QuoteAttestationCard({ verified }) {
  return (
    <Card
      title="Quote attestation"
      status={verified ? 'ok' : 'err'}
    >
      {verified ? (
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
