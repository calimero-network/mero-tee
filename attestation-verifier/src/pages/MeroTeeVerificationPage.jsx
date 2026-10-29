import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useNodeVerification } from '../hooks/useNodeVerification.js';
import { ResultView } from '../components/result/ResultView.jsx';

/**
 * A node (merod). `/mero-tee?node_url=…&release_tag=…` (the console's and the
 * manager's Verify links) verifies at once; the form verifies another node.
 */
export function MeroTeeVerificationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const nodeUrlParam = searchParams.get('node_url') || searchParams.get('nodeUrl');
  const releaseTagParam = searchParams.get('release_tag') || searchParams.get('releaseTag');
  const node = useNodeVerification();
  const { verify } = node;

  useEffect(() => {
    if (nodeUrlParam) {
      verify(nodeUrlParam, releaseTagParam || undefined);
    }
  }, [nodeUrlParam, releaseTagParam, verify]);

  const onSubmit = (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const url = form.node_url.value.trim();
    const tag = form.node_release_tag.value.trim();
    if (!url) return;
    const next = new URLSearchParams({ node_url: url });
    if (tag) next.set('release_tag', tag);
    if (url === nodeUrlParam && (tag || null) === (releaseTagParam || null)) {
      verify(url, tag || undefined);
    } else {
      // The URL carries what is verified, so the page can be shared and reloaded.
      setSearchParams(next);
    }
  };

  // A Verify link shows progress from the first paint, not an empty form.
  const view = node.status === 'idle' && nodeUrlParam
    ? { ...node, status: 'loading', phase: 'attest', request: { nodeUrl: nodeUrlParam, releaseTag: releaseTagParam } }
    : node;
  const ran = view.status !== 'idle';
  // After an error the form stays open, to correct what was entered.
  const failedToRun = view.status === 'error';
  const loading = view.status === 'loading';
  const form = (
    <form className="form" onSubmit={onSubmit}>
      <div className="form__grid">
        <div className="field">
          <label htmlFor="node_url" className="lbl">Node URL</label>
          <input
            id="node_url"
            name="node_url"
            type="url"
            required
            className="inp inp--mono"
            placeholder="https://<name>.relay.cloud.calimero.network"
            defaultValue={nodeUrlParam || ''}
            disabled={loading}
          />
          <span className="field__hint">The node’s public URL. The verifier asks it for a quote over a nonce of its own.</span>
        </div>
        <div className="field">
          <label htmlFor="node_release_tag" className="lbl">Release (optional)</label>
          <input
            id="node_release_tag"
            name="node_release_tag"
            type="text"
            className="inp inp--mono"
            placeholder="mero-tee-v2.3.131"
            defaultValue={releaseTagParam || ''}
            disabled={loading}
          />
          <span className="field__hint">The mero-tee release to compare with. Empty: the latest.</span>
        </div>
      </div>
      <div className="form__actions">
        <button type="submit" className="btn" disabled={loading}>Verify node</button>
      </div>
    </form>
  );

  return (
    <>
      {!ran && (
        <header className="page-head">
          <div className="eyebrow">Node attestation</div>
          <h1>Verify a node</h1>
          <p className="lede">
            Check that a Calimero node runs on genuine Intel TDX hardware, boots exactly the software a
            mero-tee release published, and answers at its URL itself.
          </p>
        </header>
      )}

      {ran && (
        <ResultView
          kind="node"
          state={view}
          onRetry={() => node.request && verify(node.request.nodeUrl, node.request.releaseTag || undefined)}
        />
      )}

      {/* One element throughout, so what was typed or pasted survives a run. */}
      <details className="fold" open={!ran || failedToRun}>
        <summary>{ran ? 'Verify something else' : 'Enter a node URL'}</summary>
        <div className="fold__body">{form}</div>
      </details>

      <p className="muted small">
        Verifying a KMS? Use <Link to="/kms">KMS</Link>. What each check means: <Link to="/docs">How it works</Link>.
      </p>
    </>
  );
}
