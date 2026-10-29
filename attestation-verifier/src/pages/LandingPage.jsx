import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';

const PROOFS = [
  {
    proof: 'Genuine hardware',
    how: 'Intel Trust Authority confirms the quote was signed by an Intel TDX processor for a trust domain, a VM whose memory the host cannot read.',
  },
  {
    proof: 'The published software',
    how: 'The quote’s MRTD and RTMR0–3, a hash chain of everything that booted, equal the values Calimero published with the release on GitHub.',
  },
  {
    proof: 'Made just now',
    how: 'The quote carries a random nonce this verifier chose for the check, so an old quote cannot be replayed.',
  },
  {
    proof: 'The machine at that address',
    how: 'For a node: the quote commits to the node’s transport key, and the URL completes a sealed handshake with it.',
  },
];

/**
 * What attestation proves and the two ways in. `/?kms_url=…` (older links)
 * goes on to /kms as before.
 */
export function LandingPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const kmsUrl = searchParams.get('kms_url');
  const releaseTag = searchParams.get('release_tag');

  if (kmsUrl) {
    const params = new URLSearchParams({ kms_url: kmsUrl });
    if (releaseTag) params.set('release_tag', releaseTag);
    return <Navigate to={`/kms?${params}`} replace />;
  }

  const onNode = (e) => {
    e.preventDefault();
    const url = e.currentTarget.node_url.value.trim();
    if (url) navigate(`/mero-tee?${new URLSearchParams({ node_url: url })}`);
  };

  return (
    <>
      <header className="page-head">
        <div className="eyebrow">Attestation verifier</div>
        <h1>Check what a Calimero machine is running</h1>
        <p className="lede">
          Calimero nodes and key servers run inside Intel TDX trust domains. Each can produce a quote: a statement,
          signed by the processor, of exactly what software booted. This page checks a quote independently of
          Calimero’s own consoles, against measurements published with each release.
        </p>
      </header>

      <section className="entry" aria-label="Verify">
        <div className="entry__item">
          <div className="lbl">Node</div>
          <h2>Verify a node</h2>
          <p>
            Asks the node for a fresh quote, has Intel verify it, and compares it with the mero-tee release it should
            run.
          </p>
          <form className="form" onSubmit={onNode}>
            <label htmlFor="landing_node_url" className="sr-only">Node URL</label>
            <div className="inline-form">
              <input
                id="landing_node_url"
                name="node_url"
                type="url"
                required
                className="inp inp--mono"
                placeholder="https://<name>.relay.cloud.calimero.network"
              />
              <button type="submit" className="btn">Verify node</button>
            </div>
          </form>
        </div>
        <div className="entry__item">
          <div className="lbl">KMS</div>
          <h2>Verify a KMS</h2>
          <p>
            The key servers that release each node’s storage key. The Calimero console and manager link here with a
            fresh check; operators can also paste a replica’s <code>/attest</code> response.
          </p>
          <div className="form">
            <div className="form__actions">
              <Link to="/kms" className="btn btn--ghost">Verify a KMS</Link>
              <Link to="/agent" className="small">or a private agent</Link>
            </div>
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="proves-title">
        <div className="section__head">
          <h2 id="proves-title">What a verified result proves</h2>
          <Link to="/docs" className="small">How it works, in detail</Link>
        </div>
        <div className="pane scroll-x">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">Proves</th>
                <th scope="col">How the verifier checks it</th>
              </tr>
            </thead>
            <tbody>
              {PROOFS.map((p) => (
                <tr key={p.proof}>
                  <td className="strong" style={{ whiteSpace: 'nowrap' }}>{p.proof}</td>
                  <td>{p.how}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
