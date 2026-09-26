import { useSearchParams } from 'react-router-dom';
import { useVerification } from '../hooks/useVerification.js';
import { VerificationResults } from '../components/verification/VerificationResults.jsx';
import { KmsVerifierForm } from '../components/forms/KmsVerifierForm.jsx';
import { DocsSection } from '../components/docs/DocsSection.jsx';
import './VerificationPage.css';

export function KmsVerificationPage() {
  const [searchParams] = useSearchParams();
  const releaseTagParam = searchParams.get('release_tag');
  const profileParam = searchParams.get('profile');
  const { status, error, result, verify } = useVerification();

  return (
    <section className="verification-page">
      <h2>KMS cluster (GCP TDX)</h2>
      <p className="hint">
        mero-kms replicas listen only inside their VPC, so this service cannot reach them. Call a
        replica&apos;s <code>/attest</code> from inside that network and paste the response: its quote
        is verified by Intel Trust Authority and its MRTD/RTMR0–3 are matched against the KMS
        allowlists of the signed <code>kms-attestation-policy</code> of each mero-kms release.
      </p>
      <KmsVerifierForm
        initialReleaseTag={releaseTagParam}
        initialProfile={profileParam}
        status={status}
        onVerify={verify}
      />
      {status === 'loading' && (
        <p className="status-loading">
          Verifying with Intel Trust Authority and matching release policies…
        </p>
      )}
      {status === 'error' && <div className="error-banner">{error}</div>}
      {status === 'success' && result && <VerificationResults result={result} />}
      <DocsSection />
    </section>
  );
}
