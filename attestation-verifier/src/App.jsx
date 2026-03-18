import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout.jsx';
import { LandingPage } from './pages/LandingPage.jsx';
import { KmsVerificationPage } from './pages/KmsVerificationPage.jsx';
import { MeroTeeVerificationPage } from './pages/MeroTeeVerificationPage.jsx';

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<LandingPage />} />
        <Route path="/kms" element={<KmsVerificationPage />} />
        <Route path="/mero-tee" element={<MeroTeeVerificationPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
