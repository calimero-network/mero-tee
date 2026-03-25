const PROFILES = [
  { value: '', label: 'All (compare to all profiles)' },
  { value: 'debug', label: 'debug' },
  { value: 'debug-read-only', label: 'debug-read-only' },
  { value: 'locked-read-only', label: 'locked-read-only' },
];

export function KmsVerifierForm({ initialUrl, initialReleaseTag, initialProfile, status, onVerify }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    const form = e.target;
    const url = form.kms_url?.value?.trim();
    const releaseTag = form.release_tag?.value?.trim() || null;
    const profile = form.profile?.value?.trim() || null;
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
          {status === 'loading' ? 'Verifying…' : 'Verify KMS'}
        </button>
      </div>
      <div className="input-row">
        <label htmlFor="release_tag" className="hint">Release tag for compose_hash check (optional, e.g. mero-kms-v1.2.3)</label>
        <input
          id="release_tag"
          type="text"
          name="release_tag"
          placeholder="mero-kms-v1.2.3"
          defaultValue={initialReleaseTag}
          disabled={status === 'loading'}
        />
      </div>
      <div className="input-row">
        <label htmlFor="profile" className="hint">Profile to verify against (optional): compare compose_hash to a specific image profile</label>
        <select id="profile" name="profile" defaultValue={initialProfile || ''} disabled={status === 'loading'}>
          {PROFILES.map(({ value, label }) => (
            <option key={value || 'all'} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>
    </form>
  );
}
