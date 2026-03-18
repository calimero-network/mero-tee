import { Navigate, useSearchParams } from 'react-router-dom';
import { IntroSection } from '../components/intro/IntroSection.jsx';

/**
 * Landing page: intro + redirect.
 * If kms_url in query, redirect to /kms for MDMA deep-linking.
 */
export function LandingPage() {
  const [searchParams] = useSearchParams();
  const kmsUrl = searchParams.get('kms_url');
  const releaseTag = searchParams.get('release_tag');

  if (kmsUrl) {
    const params = new URLSearchParams({ kms_url: kmsUrl });
    if (releaseTag) params.set('release_tag', releaseTag);
    return <Navigate to={`/kms?${params}`} replace />;
  }

  return (
    <>
      <IntroSection />
      <section className="landing-cta">
        <p className="landing-cta-text">
          Select a tab above to verify <strong>KMS (Phala)</strong> or <strong>Mero TEE</strong> attestations.
        </p>
      </section>
    </>
  );
}
