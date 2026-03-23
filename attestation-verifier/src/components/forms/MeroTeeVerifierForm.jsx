import { useState } from 'react';

export function MeroTeeVerifierForm({ status, onVerifyByUrl }) {
  const [kmsUrl, setKmsUrl] = useState('');
  const [releaseTag, setReleaseTag] = useState('');

  const handleUrlSubmit = (e) => {
    e.preventDefault();
    if (kmsUrl.trim()) onVerifyByUrl(kmsUrl.trim(), releaseTag.trim() || undefined);
  };

  return (
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
  );
}
