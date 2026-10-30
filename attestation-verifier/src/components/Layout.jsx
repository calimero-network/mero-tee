import { useState } from 'react';
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

const THEME_KEY = 'calimero-verifier-theme';

/** Light by default; dark only when chosen here. index.html applies the saved
 * choice before first paint, so this reads the attribute it set. */
function ThemeSwitch() {
  const [dark, setDark] = useState(() => document.documentElement.getAttribute('data-theme') === 'dark');
  const toggle = () => {
    const next = !dark;
    if (next) document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
    try {
      localStorage.setItem(THEME_KEY, next ? 'dark' : 'light');
    } catch {
      // Blocked storage: the choice lasts for this page only.
    }
    setDark(next);
  };
  return (
    <button
      type="button"
      className="bar__theme"
      onClick={toggle}
      aria-pressed={dark}
      aria-label={dark ? 'Light theme' : 'Dark theme'}
      title={dark ? 'Light theme' : 'Dark theme'}
    >
      {dark ? (
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
          <circle cx="8" cy="8" r="3" />
          <path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1" />
        </svg>
      ) : (
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
          <path d="M13.5 9.6A5.5 5.5 0 0 1 6.4 2.5a5.5 5.5 0 1 0 7.1 7.1Z" />
        </svg>
      )}
    </button>
  );
}

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
          <div className="bar__end">
            <nav className="bar__nav" aria-label="Main">
              {NAV.map(({ to, label }) => (
                <NavLink key={to} to={to}>{label}</NavLink>
              ))}
            </nav>
            <ThemeSwitch />
          </div>
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
