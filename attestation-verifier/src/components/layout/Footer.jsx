import calimeroLogo from '../../assets/calimero-logo.svg';
import './Footer.css';

const LINKS = [
  {
    heading: 'Product',
    items: [
      { label: 'Calimero Network', href: 'https://calimero.network' },
      { label: 'Mero Cloud', href: 'https://manager.cloud.calimero.network/' },
    ],
  },
  {
    heading: 'Developers',
    items: [
      { label: 'Documentation', href: 'https://docs.calimero.network' },
      { label: 'GitHub — Calimero', href: 'https://github.com/calimero-network' },
      { label: 'GitHub — mero-tee', href: 'https://github.com/calimero-network/mero-tee' },
      { label: 'mero-tee Releases', href: 'https://github.com/calimero-network/mero-tee/releases' },
    ],
  },
  {
    heading: 'Security',
    items: [
      { label: 'Attestation Scripts', href: 'https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md' },
      { label: 'Published MRTDs', href: 'https://github.com/calimero-network/mero-tee/releases' },
      { label: 'Intel Trust Authority', href: 'https://www.intel.com/content/www/us/en/security/trust-authority.html' },
    ],
  },
];

export function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <img src={calimeroLogo} alt="Calimero" className="footer-logo" />
          <p className="footer-tagline">
            Privacy-preserving infrastructure for decentralised applications.
          </p>
        </div>
        <nav className="footer-links">
          {LINKS.map(({ heading, items }) => (
            <div key={heading} className="footer-col">
              <h4 className="footer-col-heading">{heading}</h4>
              <ul>
                {items.map(({ label, href }) => (
                  <li key={label}>
                    <a href={href} target="_blank" rel="noopener noreferrer">{label}</a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </div>
      <div className="footer-bottom">
        <span>© {new Date().getFullYear()} Calimero Network. All rights reserved.</span>
      </div>
    </footer>
  );
}
