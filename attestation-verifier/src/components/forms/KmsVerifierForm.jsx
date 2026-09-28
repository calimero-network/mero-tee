import { useRef } from 'react';
import { CustomSelect } from '../ui/CustomSelect.jsx';

const PROFILES = [
  { value: '', label: 'All profiles' },
  { value: 'debug', label: 'debug' },
  { value: 'debug-read-only', label: 'debug-read-only' },
  { value: 'locked-read-only', label: 'locked-read-only' },
];

const ATTEST_EXAMPLE = `NONCE=$(head -c 32 /dev/urandom | base64 -w0); echo "$NONCE"
curl -s -X POST http://<kms-replica>:8080/attest \\
  -H 'content-type: application/json' -d "{\\"nonceB64\\":\\"$NONCE\\"}"`;

export function KmsVerifierForm({ initialReleaseTag, initialProfile, status, onVerify }) {
  const profileRef = useRef(initialProfile || '');

  const handleSubmit = (e) => {
    e.preventDefault();
    const form = e.target;
    const attestJson = form.attest_json?.value?.trim();
    const nonceB64 = form.nonce_b64?.value?.trim() || null;
    const releaseTag = form.release_tag?.value?.trim() || null;
    const profile = profileRef.current || null;
    if (attestJson) onVerify(attestJson, nonceB64, releaseTag, profile);
  };

  return (
    <form onSubmit={handleSubmit} className="verifier-form">
      <div className="input-row input-row--col">
        <label htmlFor="attest_json" className="hint">
          mero-kms <code>/attest</code> response (JSON), fetched from inside the KMS network:
        </label>
        <pre className="hint">{ATTEST_EXAMPLE}</pre>
        <textarea
          id="attest_json"
          name="attest_json"
          rows={6}
          placeholder='{"quoteB64":"…"}'
          disabled={status === 'loading'}
        />
      </div>
      <div className="input-row input-row--col">
        <label htmlFor="nonce_b64" className="hint">Nonce you sent (base64, optional; checks the quote is fresh)</label>
        <input
          id="nonce_b64"
          type="text"
          name="nonce_b64"
          disabled={status === 'loading'}
        />
      </div>
      <div className="input-row input-row--col">
        <label htmlFor="release_tag" className="hint">Release tag (optional, e.g. mero-kms-v1.2.3)</label>
        <input
          id="release_tag"
          type="text"
          name="release_tag"
          placeholder="mero-kms-v1.2.3"
          defaultValue={initialReleaseTag}
          disabled={status === 'loading'}
        />
      </div>
      <div className="input-row input-row--col">
        <label className="hint">Profile to verify against (optional)</label>
        <CustomSelect
          id="profile"
          name="profile"
          options={PROFILES}
          defaultValue={initialProfile || ''}
          disabled={status === 'loading'}
          onChange={(v) => { profileRef.current = v; }}
        />
      </div>
      <div className="input-row">
        <button type="submit" disabled={status === 'loading'}>
          {status === 'loading' && <span className="spinner" />}
          {status === 'loading' ? 'Verifying…' : 'Verify KMS'}
        </button>
      </div>
    </form>
  );
}
