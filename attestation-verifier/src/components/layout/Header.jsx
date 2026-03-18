import { Link } from 'react-router-dom';
import './Header.css';

export function Header() {
  return (
    <header className="header">
      <Link to="/" className="header-brand">
        <h1>Calimero Attestation Verifier</h1>
        <p>Verify Phala KMS and mero-tee instances against official release policy</p>
      </Link>
      <a
        href="https://github.com/calimero-network/mero-tee"
        target="_blank"
        rel="noopener noreferrer"
        className="header-github"
      >
        View on GitHub
      </a>
    </header>
  );
}
