import './IntroSection.css';

export function IntroSection() {
  return (
    <section className="intro-section">
      <h2>What is the Quote Attestation Verifier?</h2>
      <p>
        This tool verifies that a Phala KMS (Key Management Service) instance is running trusted,
        unmodified code inside an Intel TDX Trusted Execution Environment (TEE). It performs:
      </p>
      <ul>
        <li>
          <strong>Quote verification</strong> — Sends the TDX quote to Intel Trust Authority (ITA),
          which cryptographically validates the quote and returns a signed JWT. The verifier checks
          the JWT signature against Intel&apos;s public keys.
        </li>
        <li>
          <strong>RTMR visualization</strong> — Runtime Measurement Registers (RTMR0–3) are hardware
          measurements from the quote. RTMR3 is extended at boot/runtime by the event log. We replay
          the event log and compare replayed values to the quote to verify event log integrity.
        </li>
        <li>
          <strong>Compose hash check</strong> — The event log contains a <code>compose-hash</code>{' '}
          (64-char hex) that identifies the exact KMS image. We compare it against the official
          release compatibility map to ensure you&apos;re running a known, released build.
        </li>
      </ul>
      <p className="intro-note">
        For full verification (including policy allowlists), use the{' '}
        <a
          href="https://github.com/calimero-network/mero-tee/blob/master/scripts/attestation/README.md"
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
