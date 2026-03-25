import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { useNodeVerification } from '../hooks/useNodeVerification.js';
import { VerificationResults } from '../components/verification/VerificationResults.jsx';
import { MeroTeeVerifierForm } from '../components/forms/MeroTeeVerifierForm.jsx';
import './VerificationPage.css';

export function MeroTeeVerificationPage() {
  const [searchParams] = useSearchParams();
  const nodeUrlParam = searchParams.get('node_url') || searchParams.get('nodeUrl');
  const nodeReleaseTagParam = searchParams.get('release_tag') || searchParams.get('releaseTag');
  const { status, error, result, verify } = useVerification();
  const {
    status: nodeStatus,
    error: nodeError,
    result: nodeResult,
    verify: verifyNode,
  } = useNodeVerification();

  useEffect(() => {
    if (nodeUrlParam) {
      verifyNode(nodeUrlParam, nodeReleaseTagParam || undefined);
    }
  }, [nodeUrlParam, nodeReleaseTagParam, verifyNode]);

  const handleVerifyByUrl = (kmsUrl, releaseTag) => {
    verify(kmsUrl, releaseTag || undefined);
  };

  const handleVerifyNode = (nodeUrl, releaseTag) => {
    verifyNode(nodeUrl, releaseTag || undefined);
  };

  const activeStatus = nodeStatus !== 'idle' ? nodeStatus : status;
  const activeError = nodeStatus !== 'idle' ? nodeError : error;
  const activeResult = nodeStatus === 'success' ? nodeResult : result;

  return (
    <section className="verification-page">
      <h2>Mero TEE Verification</h2>
      <p className="hint">
        Verify mero-tee node attestations (GCP TDX nodes) or KMS instances. Enter a node URL (e.g.{' '}
        <code>http://public-ip:80</code>) or KMS URL.
      </p>
      <MeroTeeVerifierForm status={activeStatus} onVerifyByUrl={handleVerifyByUrl} />
      <div className="verifier-form" style={{ marginTop: '1.5rem' }}>
        <h3>Node (merod) verification</h3>
        <p className="hint">
          Verify a Calimero node at its admin API base URL. The node must be reachable (http://public-ip:80).
          MRTD/RTMR measurements are compared against published release policy (like KMS).
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target;
            const urlInput = form.querySelector('input[name="node_url"]');
            const tagInput = form.querySelector('input[name="node_release_tag"]');
            if (urlInput?.value?.trim()) {
              handleVerifyNode(urlInput.value.trim(), tagInput?.value?.trim() || undefined);
            }
          }}
          className="verifier-form"
        >
          <div className="input-row">
            <input
              type="url"
              name="node_url"
              placeholder="http://34.65.123.45:80"
              disabled={nodeStatus === 'loading'}
              defaultValue={nodeUrlParam || ''}
            />
            <button type="submit" disabled={nodeStatus === 'loading'}>
              {nodeStatus === 'loading' ? 'Verifying…' : 'Verify node'}
            </button>
          </div>
          <div className="input-row" style={{ marginTop: '0.5rem' }}>
            <label htmlFor="node_release_tag" className="input-label">
              Release tag for MRTD/RTMR check (optional, e.g. mero-tee-v2.2.4):
            </label>
            <input
              type="text"
              id="node_release_tag"
              name="node_release_tag"
              placeholder="mero-tee-v2.2.4"
              disabled={nodeStatus === 'loading'}
              defaultValue={nodeReleaseTagParam || ''}
              style={{ maxWidth: '16rem' }}
            />
          </div>
        </form>
      </div>
      {(nodeStatus === 'loading' || status === 'loading') && (
        <p className="result-warn">Verifying…</p>
      )}
      {nodeStatus === 'success' && nodeResult?.policyWarning && (
        <p className="result-warn">{nodeResult.policyWarning}</p>
      )}
      {(activeError || nodeError || error) && (
        <p className="result-err">{activeError || nodeError || error}</p>
      )}
      {activeStatus === 'success' && activeResult && (
        <VerificationResults result={activeResult} />
      )}
    </section>
  );
}
