import { useRef } from 'react';
import { CustomSelect } from '../ui/CustomSelect.jsx';

const PROFILES = [
  { value: '', label: 'All profiles' },
  { value: 'debug', label: 'debug' },
  { value: 'debug-read-only', label: 'debug-read-only' },
  { value: 'locked-read-only', label: 'locked-read-only' },
];

export function KmsVerifierForm({ initialUrl, initialReleaseTag, initialProfile, status, onVerify }) {
  const profileRef = useRef(initialProfile || '');

  const handleSubmit = (e) => {
    e.preventDefault();
    const form = e.target;
    const url = form.kms_url?.value?.trim();
    const releaseTag = form.release_tag?.value?.trim() || null;
    const profile = profileRef.current || null;
    if (url) onVerify(url, releaseTag || undefined, profile || undefined);
  };

  return (
    <form onSubmit={handleSubmit} className="verifier-form">
      <div className="input-row">
        <label htmlFor="kms_url" className="sr-only">KMS URL</label>
        <input
          id="kms_url"
          type="url"
          name="kms_url"
          placeholder="https://your-kms.phala.network"
          defaultValue={initialUrl}
          disabled={status === 'loading'}
        />
        <button type="submit" disabled={status === 'loading'}>
          {status === 'loading' && <span className="spinner" />}
          {status === 'loading' ? 'Verifying…' : 'Verify KMS'}
        </button>
      </div>
      <div className="input-row">
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
    </form>
  );
}
