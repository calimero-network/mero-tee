import './IntroSection.css';

export function IntroSection() {
  return (
    <section className="intro-section">
      <h2>What is the Quote Attestation Verifier?</h2>
      <p>
        This tool verifies that a mero-kms (Key Management Service) replica or a mero-tee node is
        running trusted, unmodified code inside an Intel TDX Trusted Execution Environment (TEE). It
        performs:
      </p>
      <ul>
        <li>
          <strong>Quote verification</strong> — Sends the TDX quote to Intel Trust Authority (ITA),
          which cryptographically validates the quote and returns a signed JWT. The verifier checks
          the JWT signature against Intel&apos;s public keys.
        </li>
        <li>
          <strong>Measurement check</strong> — MRTD and the Runtime Measurement Registers (RTMR0–3)
          are parsed from the quote and compared with the allowlists of the signed release policy:{' '}
          <code>kms-attestation-policy.&lt;profile&gt;.json</code> for the KMS,{' '}
          <code>published-mrtds.json</code> for nodes. The image role and profile are measured into
          RTMR2 and RTMR3, so a debug image cannot pass as a locked one.
        </li>
      </ul>
      <p className="intro-note">
        To verify the release assets themselves (Sigstore signatures, checksums), use the{' '}
        <a
          href="https://github.com/calimero-network/mero-tee/tree/master/scripts/release"
          target="_blank"
          rel="noopener noreferrer"
        >
          official verification scripts
        </a>
        .
      </p>
    </section>
  );
}
