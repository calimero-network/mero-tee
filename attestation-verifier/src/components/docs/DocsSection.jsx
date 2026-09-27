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
    body: 'mero-kms runs as a cluster of Intel TDX confidential VMs on GCP. Node storage keys derive from a root that exists only in the replicas\' memory, and a key is released only to a node whose quote matches the release policy.',
    links: [
      { label: 'mero-kms releases', href: 'https://github.com/calimero-network/mero-tee/releases' },
    ],
  },
  {
    tag: 'RTMR',
    title: 'Runtime Measurement Registers',
    body: 'Hardware registers in the TDX quote recording cumulative SHA-384 measurements of what was loaded at boot. RTMR2 carries the kernel command line (including the image role and profile); RTMR3 is extended once at boot with the role, profile and root hash.',
    links: [
      { label: 'Attestation scripts', href: 'https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md' },
    ],
  },
];

const STEPS = [
  { n: '01', text: 'Take the TDX quote: fetched from a node URL by the backend, or a KMS /attest response pasted by the operator.' },
  { n: '02', text: 'Send the quote to Intel Trust Authority (ITA), which validates it and returns a signed JWT.' },
  { n: '03', text: 'Verify the JWT signature against Intel\'s public JWKS endpoint.' },
  { n: '04', text: 'Check the quote\'s report data is bound to the nonce sent, when one is given.' },
  { n: '05', text: 'Compare MRTD and RTMR0–3 against Calimero\'s signed release policy on GitHub.' },
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
