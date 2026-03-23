import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { VerificationResults } from '../components/verification/VerificationResults.jsx';
import { KmsVerifierForm } from '../components/forms/KmsVerifierForm.jsx';
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
        <p className="result-warn">
          Verifying (backend fetches attestation from KMS, verifies quote via Intel Trust
          Authority)…
        </p>
      )}
      {status === 'error' && <p className="result-err">{error}</p>}
      {status === 'success' && result && <VerificationResults result={result} />}
    </section>
  );
}
