import { Outlet } from 'react-router-dom';
import { Header } from './Header.jsx';
import { Footer } from './Footer.jsx';
import { AnimatedBackground } from './AnimatedBackground.jsx';
import { TabNav } from '../tabs/TabNav.jsx';
import './Layout.css';

export function Layout() {
  return (
    <div className="layout">
      <AnimatedBackground />
      <Header />
      <main className="layout-main">
        <div className="page-hero">
          <h1 className="page-hero-title">Attestation Verifier</h1>
          <p className="page-hero-sub">
            Verify Phala KMS and mero-tee nodes against official Calimero release policy
          </p>
        </div>
        <TabNav />
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
