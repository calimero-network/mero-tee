import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { ResultView } from '../components/result/ResultView.jsx';
import { CopyButton } from '../components/CopyButton.jsx';
import { PROFILES } from '../lib/registers.js';

const ATTEST_EXAMPLE = `NONCE=$(head -c 32 /dev/urandom | base64 -w0); echo "$NONCE"
curl -s -X POST http://<kms-replica>:8080/attest \\
  -H 'content-type: application/json' -d "{\\"nonceB64\\":\\"$NONCE\\"}"`;

/**
 * A mero-kms replica. `/kms?kms_attest_url=…&release_tag=…&profile=…` (set by
 * mdma's manager and cloud console) verifies at once, with no paste; otherwise
 * the operator pastes a replica's `/attest` response fetched inside its VPC.
 */
export function KmsVerificationPage() {
  const [searchParams] = useSearchParams();
  const releaseTagParam = searchParams.get('release_tag');
  const profileParam = searchParams.get('profile');
  const attestUrlParam = searchParams.get('kms_attest_url');
  const kms = useVerification();
  const { verify } = kms;

  useEffect(() => {
    if (attestUrlParam) {
      verify({ url: attestUrlParam }, null, releaseTagParam || null, profileParam || null);
    }
  }, [attestUrlParam, releaseTagParam, profileParam, verify]);

  const onSubmit = (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const attestJson = form.attest_json.value.trim();
    if (!attestJson) return;
    verify(
      attestJson,
      form.nonce_b64.value.trim() || null,
      form.release_tag.value.trim() || null,
      form.profile.value || null,
    );
  };

  const onRetry = () => {
    const r = kms.request;
    if (r?.attestUrl) verify({ url: r.attestUrl }, null, r.releaseTag, r.profile);
  };

  // A Verify link shows progress from the first paint, not an empty form.
  const view = kms.status === 'idle' && attestUrlParam
    ? {
      ...kms,
      status: 'loading',
      phase: 'attest',
      request: { attestUrl: attestUrlParam, releaseTag: releaseTagParam, profile: profileParam },
    }
    : kms;
  const ran = view.status !== 'idle';
  // After an error the form stays open, to correct what was entered.
  const failedToRun = view.status === 'error';
  const loading = view.status === 'loading';
  const form = (
    <form className="form" onSubmit={onSubmit}>
      <p className="muted small">
        mero-kms replicas listen only inside their VPC, so this site cannot reach them. From inside that network,
        call a replica’s <code>/attest</code> with a nonce of your own and paste the response here.
      </p>
      <div className="raw-block">
        <div className="raw-block__head">
          <span className="lbl">From inside the KMS network</span>
          <CopyButton text={ATTEST_EXAMPLE} label="Copy command" />
        </div>
        <pre className="cmd">{ATTEST_EXAMPLE}</pre>
      </div>
      <div className="field">
        <label htmlFor="attest_json" className="lbl"><code>/attest</code> response (JSON)</label>
        <textarea id="attest_json" name="attest_json" rows={6} className="txt" placeholder='{"quoteB64":"…"}' required disabled={loading} />
      </div>
      <div className="form__grid">
        <div className="field">
          <label htmlFor="nonce_b64" className="lbl">Nonce you sent (base64)</label>
          <input id="nonce_b64" name="nonce_b64" type="text" className="inp inp--mono" disabled={loading} />
          <span className="field__hint">Optional, but without it the quote could be an old one.</span>
        </div>
        <div className="field">
          <label htmlFor="release_tag" className="lbl">Release (optional)</label>
          <input
            id="release_tag"
            name="release_tag"
            type="text"
            className="inp inp--mono"
            placeholder="mero-kms-v2.3.131"
            defaultValue={releaseTagParam || ''}
            disabled={loading}
          />
          <span className="field__hint">Empty: the five latest mero-kms releases.</span>
        </div>
        <div className="field">
          <label htmlFor="profile" className="lbl">Profile (optional)</label>
          <select id="profile" name="profile" className="sel" defaultValue={profileParam || ''} disabled={loading}>
            <option value="">Any profile</option>
            {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>
      </div>
      <div className="form__actions">
        <button type="submit" className="btn" disabled={loading}>Verify KMS</button>
      </div>
    </form>
  );

  return (
    <>
      {!ran && (
        <header className="page-head">
          <div className="eyebrow">KMS attestation</div>
          <h1>Verify a KMS</h1>
          <p className="lede">
            Check that a mero-kms replica, which holds the keys nodes’ storage is encrypted with, runs on genuine
            Intel TDX hardware and boots exactly the software a mero-kms release allows.
          </p>
        </header>
      )}

      {ran && <ResultView kind="kms" state={view} onRetry={kms.request?.attestUrl ? onRetry : null} />}

      {/* One element throughout, so what was typed or pasted survives a run. */}
      <details className="fold" open={!ran || failedToRun}>
        <summary>{ran ? 'Verify something else: paste an /attest response' : 'Paste a replica’s /attest response'}</summary>
        <div className="fold__body">{form}</div>
      </details>

      <p className="muted small">
        The Calimero console and manager link here with a fresh check of their KMS, no paste needed. Verifying a
        node? Use <Link to="/mero-tee">Node</Link>. What each check means: <Link to="/docs">How it works</Link>.
      </p>
    </>
  );
}
