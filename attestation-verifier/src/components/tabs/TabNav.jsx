import { NavLink } from 'react-router-dom';
import './TabNav.css';

const TABS = [
  { path: '/kms', label: 'KMS', description: 'Verify a mero-kms (GCP TDX) attestation' },
  { path: '/mero-tee', label: 'Mero TEE', description: 'Verify mero-tee node attestations' },
  { path: '/agent', label: 'Agent', description: 'Verify a private agent before trusting its key' },
];

export function TabNav() {
  return (
    <nav className="tab-nav" role="tablist">
      {TABS.map(({ path, label, description }) => (
        <NavLink
          key={path}
          to={path}
          className={({ isActive }) => `tab-nav-item ${isActive ? 'tab-nav-item--active' : ''}`}
          role="tab"
        >
          <span className="tab-nav-label">{label}</span>
          <span className="tab-nav-desc">{description}</span>
        </NavLink>
      ))}
    </nav>
  );
}
