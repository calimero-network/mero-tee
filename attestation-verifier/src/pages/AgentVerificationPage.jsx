import { useState } from 'react';
import { Link } from 'react-router-dom';
import { verifyAgentAttestation } from '../services/api.js';
import { extractMeasurementsFromQuoteB64 } from '../utils/attestation.js';
import { compareRegisters } from '../lib/registers.js';
import { modelFromAgent, plannedRows } from '../lib/checks.js';
import { explainError } from '../lib/errors.js';
import { Verdict, formatTime } from '../components/result/Verdict.jsx';
import { Checklist } from '../components/result/Checklist.jsx';
import { RegisterTable } from '../components/result/RegisterTable.jsx';
import { Progress } from '../components/result/Progress.jsx';
import { CopyButton } from '../components/CopyButton.jsx';

const ATTEST_EXAMPLE = `NONCE=$(head -c 32 /dev/urandom | base64 -w0); echo "$NONCE"
curl -s -X POST http://<agent-td>:8090/attest -H 'content-type: application/json' \\
  -d "{\\"nonceB64\\":\\"$NONCE\\",\\"agentId\\":\\"<your agent id>\\"}"`;

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
    const form = e.currentTarget;
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
      const registers = compareRegisters(measurements, policy, 'agent');
      setState({
        status: 'success',
        error: null,
        result: {
          checkedAt: new Date().toISOString(),
          itaVerified: data.ita_token_verified === true,
          nonceVerified: data.nonce_verified === true,
          keysVerified: data.agent_keys_verified === true,
          keys: data.agent_keys || null,
          registers,
          policyOk: registers.every((r) => r.match),
          profile: policy?.profile || null,
        },
      });
    } catch (err) {
      setState({ status: 'error', error: err.message || 'Verification failed', result: null });
    }
  };

  const { status, error, result } = state;
  const loading = status === 'loading';

  const form = (
    <form className="form" onSubmit={onSubmit}>
      <div className="raw-block">
        <div className="raw-block__head">
          <span className="lbl">Ask the agent for a quote</span>
          <CopyButton text={ATTEST_EXAMPLE} label="Copy command" />
        </div>
        <pre className="cmd">{ATTEST_EXAMPLE}</pre>
      </div>
      <div className="field">
        <label htmlFor="attest_json" className="lbl">mero-agent-gate <code>/attest</code> response (JSON)</label>
        <textarea id="attest_json" name="attest_json" rows={6} className="txt" placeholder='{"quoteB64":"…"}' required disabled={loading} />
      </div>
      <div className="field">
        <label htmlFor="nonce_b64" className="lbl">Nonce you sent (base64)</label>
        <input id="nonce_b64" name="nonce_b64" type="text" className="inp inp--mono" disabled={loading} />
        <span className="field__hint">Required to trust the agent’s key.</span>
      </div>
      <div className="field">
        <label htmlFor="policy_json" className="lbl">
          Agent policy (<code>agent-attestation-policy.&lt;profile&gt;.json</code>)
        </label>
        <textarea id="policy_json" name="policy_json" rows={6} className="txt" placeholder='{"allowed_mrtd":["…"],…}' required disabled={loading} />
      </div>
      <div className="form__actions">
        <button type="submit" className="btn" disabled={loading}>Verify agent</button>
      </div>
    </form>
  );

  let view = null;
  if (loading) {
    view = (
      <Verdict verdict="loading" eyebrow="Agent attestation">
        <Progress
          phase="attest"
          steps={[
            { phase: 'attest', label: 'Verify the quote with Intel Trust Authority and check its nonce and keys' },
            { phase: 'compare', label: 'Check MRTD and RTMR0–3 against the agent policy' },
          ]}
        />
      </Verdict>
    );
  } else if (status === 'error') {
    const e = explainError(error);
    const rows = plannedRows('agent').map((r) => (r.id === e.check ? { ...r, status: 'fail', result: e.actual } : r));
    view = (
      <>
        <Verdict verdict={e.verdict} eyebrow="Agent attestation">
          <div className="explain">
            <h2>{e.title}</h2>
            <p>{e.explain}</p>
            <p><strong>What to do:</strong> {e.action}</p>
            <p className="raw">Details: {e.detail}</p>
          </div>
        </Verdict>
        <section className="section" aria-labelledby="checks-title">
          <h2 id="checks-title">Checks</h2>
          <Checklist key={error} rows={rows} />
        </section>
      </>
    );
  } else if (status === 'success' && result) {
    const model = modelFromAgent(result);
    const keys = result.keys;
    const signing = keys?.signingPublicKeyB64;
    view = (
      <>
        <Verdict
          verdict={model.verdict}
          eyebrow="Agent attestation"
          subject={keys?.agentId ? `Agent ${keys.agentId}` : 'Agent TD (no agent named)'}
          facts={[
            { label: 'Profile', value: <span className="mono">{result.profile || 'not named in the policy'}</span> },
            {
              label: 'Owner',
              value: keys?.ownerPublicKeyB64
                ? <span className="mono">{keys.ownerPublicKeyB64}</span>
                : 'Unclaimed: the first sealed bundle claims it',
            },
            { label: 'Checked', value: <time dateTime={result.checkedAt}>{formatTime(result.checkedAt)}</time> },
          ]}
        >
          {model.verdict === 'pass' && signing ? (
            <div className="notice notice--info">
              <p>
                <strong>Signing key</strong>, safe to authorize as this agent’s device once the owner below is your key:
              </p>
              <p className="mono" style={{ margin: '6px 0' }}>{signing}</p>
              <CopyButton text={signing} label="Copy signing key" />
            </div>
          ) : model.verdict === 'pass' ? (
            <p className="notice notice--info">This agent is not claimed yet, so it has no signing key to authorize.</p>
          ) : (
            <p className="notice notice--err"><strong>Do not authorize this agent’s key:</strong> a check below did not pass.</p>
          )}
        </Verdict>
        <section className="section" aria-labelledby="checks-title">
          <h2 id="checks-title">Checks</h2>
          <Checklist key={result.checkedAt} rows={model.rows} context={{ policyLabel: 'the pasted agent policy' }} />
        </section>
        <section className="section" aria-labelledby="measure-title">
          <h2 id="measure-title">Measurements</h2>
          <div className="pane">
            <RegisterTable registers={result.registers} expectedLabel="agent policy" />
          </div>
        </section>
      </>
    );
  }

  const ran = status !== 'idle';
  // After an error the form stays open, to correct what was entered.
  const failedToRun = status === 'error';
  return (
    <>
      {!ran && (
        <header className="page-head">
          <div className="eyebrow">Agent attestation</div>
          <h1>Verify a private agent</h1>
          <p className="lede">
            Before authorizing a private agent’s key, check that its quote is genuine, made for your nonce, commits to
            that agent and its keys, and that its measurements are in the agent policy of its release. One agent TD
            hosts several owners’ agents, so ask for yours by its agent id.
          </p>
        </header>
      )}
      {view}
      {/* One element throughout, so what was typed or pasted survives a run. */}
      <details className="fold" open={!ran || failedToRun}>
        <summary>{ran ? 'Verify something else' : 'Paste the agent’s /attest response and policy'}</summary>
        <div className="fold__body">{form}</div>
      </details>
      <p className="muted small">What each check means: <Link to="/docs">How it works</Link>.</p>
    </>
  );
}
