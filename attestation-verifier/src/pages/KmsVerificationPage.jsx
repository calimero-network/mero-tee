import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { VerificationResults } from '../components/verification/VerificationResults.jsx';
import { KmsVerifierForm } from '../components/forms/KmsVerifierForm.jsx';
import { DocsSection } from '../components/docs/DocsSection.jsx';
import './VerificationPage.css';

export function KmsVerificationPage() {
  const [searchParams] = useSearchParams();
  const kmsUrlParam = searchParams.get('kms_url');
  const releaseTagParam = searchParams.get('release_tag');
  const profileParam = searchParams.get('profile');
  const { status, error, result, verify } = useVerification();

  useEffect(() => {
    if (kmsUrlParam) {
      verify(kmsUrlParam, releaseTagParam || undefined, profileParam || undefined);
    }
  }, [kmsUrlParam, releaseTagParam, profileParam, verify]);

  return (
    <section className="verification-page">
      <h2>KMS Instance (Phala)</h2>
      <p className="hint">
        Verify a Phala KMS instance by URL. The backend fetches attestation and verifies via Intel
        Trust Authority.
      </p>
      <KmsVerifierForm
        initialUrl={kmsUrlParam}
        initialReleaseTag={releaseTagParam}
        initialProfile={profileParam}
        status={status}
        onVerify={verify}
      />
      {status === 'loading' && (
        <p className="status-loading">
          Fetching attestation and verifying with Intel Trust Authority…
        </p>
      )}
      {status === 'error' && <div className="error-banner">{error}</div>}
      {status === 'success' && result && <VerificationResults result={result} />}
      <DocsSection />
    </section>
  );
}
