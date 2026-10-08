import { useState } from 'react';
import { verifyAgentAttestation } from '../services/api.js';
import { extractMeasurementsFromQuoteB64 } from '../utils/attestation.js';
import './VerificationPage.css';

const ATTEST_EXAMPLE = `NONCE=$(head -c 32 /dev/urandom | base64 -w0); echo "$NONCE"
curl -s -X POST http://<agent>:8090/attest \\
  -H 'content-type: application/json' -d "{\\"nonceB64\\":\\"$NONCE\\"}"`;

const REGISTERS = ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];

const normalize = (v) => String(v || '').trim().replace(/^0x/, '').toLowerCase();

/** Each register of the quote against the agent policy's list for it. */
function matchPolicy(measurements, policy) {
  return REGISTERS.map((reg) => {
    const allowed = (policy?.[`allowed_${reg}`] || []).map(normalize);
    const actual = normalize(measurements?.[reg]);
    return { reg, actual, ok: actual.length > 0 && allowed.includes(actual) };
  });
}

/**
 * A private agent (docs/design/private-agents.md). Its gate serves `/attest`: a
 * quote binding a fresh nonce to the agent's provisioning and signing keys.
 * This page has Intel Trust Authority verify the quote, checks it commits to
 * the keys the gate named, and matches its registers against the agent policy
 * (`agent-attestation-policy.<profile>.json`). An account owner authorizes the
 * signing key shown below as the agent's device only when everything passes.
 */
export function AgentVerificationPage() {
  const [state, setState] = useState({ status: 'idle', error: null, result: null });

  const onSubmit = async (e) => {
    e.preventDefault();
    const form = e.target;
    setState({ status: 'loading', error: null, result: null });
    try {
      let attestation;
      let policy;
      try {
        attestation = JSON.parse(form.attest_json.value);
      } catch {
        throw new Error('The /attest response is not valid JSON');
      }
      try {
        policy = JSON.parse(form.policy_json.value);
      } catch {
        throw new Error('The agent policy is not valid JSON');
      }
      const nonce = form.nonce_b64.value.trim() || null;
      const data = await verifyAgentAttestation(attestation, nonce);
      const measurements = extractMeasurementsFromQuoteB64(attestation.quoteB64);
      const registers = matchPolicy(measurements, policy);
      setState({
        status: 'success',
        error: null,
        result: {
          itaVerified: data.ita_token_verified === true,
          nonceVerified: data.nonce_verified === true,
          keysVerified: data.agent_keys_verified === true,
          keys: data.agent_keys || null,
          registers,
          policyOk: registers.every((r) => r.ok),
          profile: policy?.profile || null,
        },
      });
    } catch (err) {
      setState({ status: 'error', error: err.message || 'Verification failed', result: null });
    }
  };

  const { status, error, result } = state;
  const trusted = result && result.itaVerified && result.nonceVerified && result.keysVerified && result.policyOk;

  return (
    <section className="verification-page">
      <h2>Private agent (GCP TDX)</h2>
      <p className="hint">
        Call the agent&apos;s <code>/attest</code> with a nonce you chose and paste the response with the
        agent policy of its release. Its quote is verified by Intel Trust Authority, must carry your
        nonce and commit to the keys the gate names, and its MRTD/RTMR0–3 must be in the policy. Only
        then is the signing key below the agent&apos;s, running the measured build.
      </p>
      <form onSubmit={onSubmit} className="verifier-form">
        <div className="input-row input-row--col">
          <label htmlFor="attest_json" className="hint">
            mero-agent-gate <code>/attest</code> response (JSON):
          </label>
          <pre className="hint">{ATTEST_EXAMPLE}</pre>
          <textarea id="attest_json" name="attest_json" rows={6} placeholder='{"quoteB64":"…"}' disabled={status === 'loading'} />
        </div>
        <div className="input-row input-row--col">
          <label htmlFor="nonce_b64" className="hint">Nonce you sent (base64; required to trust the key)</label>
          <input id="nonce_b64" type="text" name="nonce_b64" disabled={status === 'loading'} />
        </div>
        <div className="input-row input-row--col">
          <label htmlFor="policy_json" className="hint">
            Agent policy (<code>agent-attestation-policy.&lt;profile&gt;.json</code>):
          </label>
          <textarea id="policy_json" name="policy_json" rows={6} placeholder='{"allowed_mrtd":["…"],…}' disabled={status === 'loading'} />
        </div>
        <div className="input-row">
          <button type="submit" disabled={status === 'loading'}>
            {status === 'loading' && <span className="spinner" />}
            {status === 'loading' ? 'Verifying…' : 'Verify agent'}
          </button>
        </div>
      </form>
      {status === 'error' && <div className="error-banner">{error}</div>}
      {status === 'success' && result && (
        <div className="verification-results">
          <ul className="hint">
            <li>Intel Trust Authority token: {result.itaVerified ? 'verified' : 'NOT verified'}</li>
            <li>Nonce: {result.nonceVerified ? 'bound to this request' : 'NOT checked (give the nonce you sent)'}</li>
            <li>Keys: {result.keysVerified ? 'committed to by the quote' : 'NOT committed to'}</li>
            {result.keys && (
              <li>
                Owner:{' '}
                {result.keys.ownerPublicKeyB64 ? (
                  <>claimed by <code>{result.keys.ownerPublicKeyB64}</code>; authorize it only if that is your key</>
                ) : (
                  'unclaimed; the first sealed bundle claims it'
                )}
              </li>
            )}
            {result.registers.map((r) => (
              <li key={r.reg}>
                {r.reg.toUpperCase()}: {r.ok ? 'in the agent policy' : 'NOT in the agent policy'} <code>{r.actual}</code>
              </li>
            ))}
          </ul>
          {trusted ? (
            <p>
              Signing key{result.profile ? ` (${result.profile})` : ''}, safe to authorize as this agent&apos;s
              device once its owner above is your key: <code>{result.keys.signingPublicKeyB64}</code>
            </p>
          ) : (
            <div className="error-banner">Do not authorize this agent&apos;s key: a check above failed.</div>
          )}
        </div>
      )}
    </section>
  );
}
