import { Link, NavLink, Outlet } from 'react-router-dom';
import calimeroLogo from '../assets/calimero-logo.svg';

const NAV = [
  { to: '/mero-tee', label: 'Node' },
  { to: '/kms', label: 'KMS' },
  { to: '/agent', label: 'Agent' },
  { to: '/docs', label: 'How it works' },
];

const FOOT = [
  { label: 'mero-tee releases', href: 'https://github.com/calimero-network/mero-tee/releases' },
  { label: 'Source', href: 'https://github.com/calimero-network/mero-tee/tree/master/attestation-verifier' },
  { label: 'Attestation scripts', href: 'https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md' },
  { label: 'Intel Trust Authority', href: 'https://www.intel.com/content/www/us/en/security/trust-authority.html' },
  { label: 'calimero.network', href: 'https://calimero.network' },
];

export function Layout() {
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="bar">
        <div className="bar__inner">
          <Link to="/" className="bar__brand" aria-label="Calimero attestation verifier, home">
            <img src={calimeroLogo} alt="Calimero" />
            <span className="bar__name">Attestation verifier</span>
          </Link>
          <nav className="bar__nav" aria-label="Main">
            {NAV.map(({ to, label }) => (
              <NavLink key={to} to={to}>{label}</NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main id="main" className="main">
        <Outlet />
      </main>
      <footer className="foot">
        <div className="foot__inner">
          <span>© {new Date().getFullYear()} Calimero Network</span>
          <nav className="foot__links" aria-label="Footer">
            {FOOT.map(({ label, href }) => (
              <a key={href} href={href} target="_blank" rel="noopener noreferrer">{label}</a>
            ))}
          </nav>
        </div>
      </footer>
    </div>
  );
}
