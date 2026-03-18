import { Outlet } from 'react-router-dom';
import { Header } from './Header.jsx';
import { TabNav } from '../tabs/TabNav.jsx';
import './Layout.css';

export function Layout() {
  return (
    <div className="layout">
      <Header />
      <main className="layout-main">
        <TabNav />
        <Outlet />
      </main>
    </div>
  );
}
