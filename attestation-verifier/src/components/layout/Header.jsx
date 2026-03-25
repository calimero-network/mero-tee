import { Link } from 'react-router-dom';
import calimeroLogo from '../../assets/calimero-logo.svg';
import './Header.css';

export function Header() {
  return (
    <header className="header">
      <Link to="/" className="header-brand">
        <img src={calimeroLogo} alt="Calimero" className="header-logo" />
      </Link>
    </header>
  );
}
