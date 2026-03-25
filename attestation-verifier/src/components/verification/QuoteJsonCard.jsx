import { useState } from 'react';
import { Card } from '../ui/Card.jsx';

export function QuoteJsonCard({ itaClaims, attestation, style }) {
  const [activeTab, setActiveTab] = useState('ita');
  const data = activeTab === 'ita' ? itaClaims : attestation;
  const jsonStr = data ? JSON.stringify(data, null, 2) : '';

  if (!itaClaims && !attestation) return null;

  return (
    <Card title="Quote / attestation data" style={style}>
      <div className="json-viewer-tabs">
        {itaClaims && (
          <button
            type="button"
            className={`json-viewer-tab ${activeTab === 'ita' ? 'active' : ''}`}
            onClick={() => setActiveTab('ita')}
          >
            ITA claims (decoded JWT)
          </button>
        )}
        {attestation && (
          <button
            type="button"
            className={`json-viewer-tab ${activeTab === 'attestation' ? 'active' : ''}`}
            onClick={() => setActiveTab('attestation')}
          >
            Attestation response
          </button>
        )}
      </div>
      <pre className="json-viewer-content">{jsonStr}</pre>
    </Card>
  );
}
