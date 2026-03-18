import { useState } from 'react';

export function MeroTeeVerifierForm({ status, onVerifyByUrl, onVerifyByPaste }) {
  const [kmsUrl, setKmsUrl] = useState('');
  const [releaseTag, setReleaseTag] = useState('');
  const [jsonInput, setJsonInput] = useState('');

  const handleUrlSubmit = (e) => {
    e.preventDefault();
    if (kmsUrl.trim()) onVerifyByUrl(kmsUrl.trim(), releaseTag.trim() || undefined);
  };

  const handlePasteSubmit = (e) => {
    e.preventDefault();
    if (jsonInput.trim()) onVerifyByPaste(jsonInput.trim(), releaseTag.trim());
  };

  return (
    <>
      <form onSubmit={handleUrlSubmit} className="verifier-form">
        <div className="input-row">
          <input
            type="url"
            value={kmsUrl}
            onChange={(e) => setKmsUrl(e.target.value)}
            placeholder="https://your-kms.phala.network"
            disabled={status === 'loading'}
          />
          <button type="submit" disabled={status === 'loading' || !kmsUrl.trim()}>
            {status === 'loading' ? 'Verifying…' : 'Verify'}
          </button>
        </div>
        <div className="input-row">
          <input
            type="text"
            value={releaseTag}
            onChange={(e) => setReleaseTag(e.target.value)}
            placeholder="Release tag (optional)"
            disabled={status === 'loading'}
          />
        </div>
      </form>
      <p className="hint" style={{ marginTop: '1rem' }}>
        Or paste attestation JSON from <code>POST /attest</code> (compose hash extraction only;
        full verification requires URL).
      </p>
      <form onSubmit={handlePasteSubmit}>
        <textarea
          value={jsonInput}
          onChange={(e) => setJsonInput(e.target.value)}
          placeholder='Paste attestation JSON from: curl -X POST -d \'{"nonceB64":"..."}\' https://your-kms/attest'
          rows={6}
          disabled={status === 'loading'}
        />
        <button type="submit" disabled={status === 'loading' || !jsonInput.trim()}>
          Extract compose hash
        </button>
      </form>
    </>
  );
}
