import { Navigate, useSearchParams } from 'react-router-dom';

/**
 * Landing page: redirect straight to /kms (default tab).
 * Deep-link support: if kms_url param present, pass it through.
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

  return <Navigate to="/kms" replace />;
}
