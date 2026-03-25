import './DocsSection.css';

const CONCEPTS = [
  {
    tag: 'TEE',
    title: 'Trusted Execution Environment',
    body: 'A secure CPU enclave where code and data are protected from the OS, hypervisor, and cloud provider. Intel TDX produces a cryptographic quote proving exactly what software is running.',
    links: [
      { label: 'Intel TDX overview', href: 'https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html' },
      { label: 'Intel Trust Authority', href: 'https://www.intel.com/content/www/us/en/security/trust-authority.html' },
    ],
  },
  {
    tag: 'KMS',
    title: 'Key Management Service',
    body: 'A Phala-hosted service inside a TDX TEE that holds private keys for Calimero contexts. Because it runs in a TEE, not even Phala can access the keys.',
    links: [
      { label: 'Phala Network', href: 'https://phala.network' },
      { label: 'Phala Cloud', href: 'https://cloud.phala.network' },
      { label: 'mero-kms releases', href: 'https://github.com/calimero-network/mero-tee/releases' },
    ],
  },
  {
    tag: 'RTMR',
    title: 'Runtime Measurement Registers',
    body: 'Hardware registers in the TDX quote recording cumulative SHA-384 measurements of everything loaded at boot and runtime. RTMR3 is extended by an event log replayed here to verify integrity.',
    links: [
      { label: 'Attestation scripts', href: 'https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md' },
    ],
  },
];

const STEPS = [
  { n: '01', text: 'Fetch the TDX quote from the KMS or node URL via the backend.' },
  { n: '02', text: 'Send the quote to Intel Trust Authority (ITA), which validates it and returns a signed JWT.' },
  { n: '03', text: 'Verify the JWT signature against Intel\'s public JWKS endpoint.' },
  { n: '04', text: 'Replay the event log step-by-step and confirm the final RTMR3 matches the hardware quote.' },
  { n: '05', text: 'Compare the compose hash from the event log against Calimero\'s official GitHub release policy.' },
];

export function DocsSection() {
  return (
    <section className="docs-section">
      <div className="docs-concepts">
        <h2 className="docs-subheading">Key concepts</h2>
        <div className="docs-concepts-grid">
          {CONCEPTS.map(({ tag, title, body, links }) => (
            <div key={tag} className="docs-concept-card">
              <span className="docs-tag">{tag}</span>
              <h3 className="docs-title">{title}</h3>
              <p className="docs-body">{body}</p>
              {links?.length > 0 && (
                <ul className="docs-links">
                  {links.map(({ label, href }) => (
                    <li key={href}>
                      <a href={href} target="_blank" rel="noopener noreferrer">{label} ↗</a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="docs-how">
        <h2 className="docs-subheading">How it works</h2>
        <ol className="docs-steps">
          {STEPS.map(({ n, text }) => (
            <li key={n} className="docs-step">
              <span className="docs-step-n">{n}</span>
              <span className="docs-step-text">{text}</span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
