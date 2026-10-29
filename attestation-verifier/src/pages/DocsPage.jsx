import { Link } from 'react-router-dom';
import { REGISTERS, REGISTER_INFO } from '../lib/registers.js';

const STEPS = [
  {
    step: 'Get a fresh quote',
    text: 'For a node, the verifier’s API asks the node’s /admin-api/tee/attest for a quote over a random nonce of its own. For a KMS from a console link, it asks the manager, which relays a replica’s /attest, with its own nonce. A pasted response carries the nonce you sent, if you give it.',
  },
  {
    step: 'Check the nonce',
    text: 'The first 32 bytes of the quote’s report_data must be that nonce, read from the quote bytes Intel verifies. Otherwise the quote could be a replay of an older one.',
  },
  {
    step: 'Tie the node to its URL',
    text: 'The rest of report_data must commit to the node’s transport key, and the server at the URL must complete a sealed handshake with that key. A node without sealed transport cannot be checked this way, and the result says so.',
  },
  {
    step: 'Have Intel verify the quote',
    text: 'Intel Trust Authority appraises the quote and returns a signed token; the verifier checks the token’s signature against Intel’s published keys.',
  },
  {
    step: 'Compare the measurements',
    text: 'MRTD and RTMR0–3 are parsed from the quote and must all be in the lists the release published: published-mrtds.json for a node, the KMS allowlists of kms-attestation-policy.<profile>.json for a KMS.',
  },
];

const TERMS = [
  {
    term: 'Trust domain (TD)',
    meaning: 'An Intel TDX confidential VM. Its memory is encrypted by the processor and cannot be read by the host, the hypervisor or the cloud provider.',
    link: ['Intel TDX', 'https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html'],
  },
  {
    term: 'Quote',
    meaning: 'A statement signed by the processor: the TD’s measurement registers and 64 bytes of report_data the TD chose (here, a nonce and a key commitment).',
  },
  {
    term: 'Intel Trust Authority',
    meaning: 'Intel’s attestation service. It verifies a quote’s signature chain and the platform’s patch level (TCB status), and returns a signed token.',
    link: ['Intel Trust Authority', 'https://www.intel.com/content/www/us/en/security/trust-authority.html'],
  },
  {
    term: 'mero-kms',
    meaning: 'The key service: a cluster of TDX VMs. Node storage keys derive from a root that exists only in the replicas’ memory, and a key is released only to a node whose quote matches the release policy.',
    link: ['mero-kms releases', 'https://github.com/calimero-network/mero-tee/releases'],
  },
  {
    term: 'Profile',
    meaning: 'Each release builds three image profiles: debug, debug-read-only and locked-read-only. The role and profile are measured into RTMR2 and RTMR3, so a debug image cannot pass as a locked one.',
  },
];

export function DocsPage() {
  return (
    <>
      <header className="page-head">
        <div className="eyebrow">How it works</div>
        <h1>What the verifier checks, and how</h1>
        <p className="lede">
          A verification passes only when every check below passes. A check that could not run is shown as not
          checked, never as passed.
        </p>
      </header>

      <section className="section" aria-labelledby="steps-title">
        <h2 id="steps-title">Steps</h2>
        <div className="pane scroll-x">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">Step</th>
                <th scope="col">What happens</th>
              </tr>
            </thead>
            <tbody>
              {STEPS.map((s, i) => (
                <tr key={s.step}>
                  <td className="mono muted">{String(i + 1).padStart(2, '0')}</td>
                  <td className="strong">{s.step}</td>
                  <td>{s.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section" aria-labelledby="regs-title">
        <h2 id="regs-title">Measurement registers</h2>
        <div className="pane scroll-x">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">Register</th>
                <th scope="col">What it records</th>
              </tr>
            </thead>
            <tbody>
              {REGISTERS.map((r) => (
                <tr key={r}>
                  <td className="strong mono">{REGISTER_INFO[r].label}</td>
                  <td>{REGISTER_INFO[r].meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section" aria-labelledby="terms-title">
        <h2 id="terms-title">Terms</h2>
        <div className="pane scroll-x">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">Term</th>
                <th scope="col">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {TERMS.map((t) => (
                <tr key={t.term}>
                  <td className="strong">{t.term}</td>
                  <td>
                    {t.meaning}
                    {t.link && (
                      <>
                        {' '}
                        <a href={t.link[1]} target="_blank" rel="noopener noreferrer">{t.link[0]}</a>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section" aria-labelledby="release-title">
        <h2 id="release-title">Verifying the release itself</h2>
        <div className="prose">
          <p>
            This page trusts the measurements published with each release. To check the release assets themselves
            (Sigstore signatures, checksums, provenance), run the{' '}
            <a href="https://github.com/calimero-network/mero-tee/tree/master/scripts/release" target="_blank" rel="noopener noreferrer">
              release verification scripts
            </a>
            ; to reproduce a quote’s measurements, see the{' '}
            <a href="https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md" target="_blank" rel="noopener noreferrer">
              attestation scripts
            </a>
            .
          </p>
          <p>
            Start a check: <Link to="/mero-tee">verify a node</Link>, <Link to="/kms">verify a KMS</Link> or{' '}
            <Link to="/agent">verify a private agent</Link>.
          </p>
        </div>
      </section>
    </>
  );
}
