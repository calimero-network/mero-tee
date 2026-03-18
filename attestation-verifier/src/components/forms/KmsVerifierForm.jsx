export function KmsVerifierForm({ initialUrl, initialReleaseTag, status, onVerify }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    const form = e.target;
    const url = form.kms_url?.value?.trim();
    const releaseTag = form.release_tag?.value?.trim() || null;
    if (url) onVerify(url, releaseTag || undefined);
  };

  return (
    <form onSubmit={handleSubmit} className="verifier-form">
      <div className="input-row">
        <input
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
      <p className="hint">Release tag for compose_hash check (optional, e.g. mero-kms-v1.2.3)</p>
      <div className="input-row">
        <input
          type="text"
          name="release_tag"
          placeholder="mero-kms-v1.2.3"
          defaultValue={initialReleaseTag}
          disabled={status === 'loading'}
        />
      </div>
    </form>
  );
}
