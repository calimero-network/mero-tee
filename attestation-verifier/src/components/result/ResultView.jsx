import { Verdict, formatTime } from './Verdict.jsx';
import { Checklist } from './Checklist.jsx';
import { Progress } from './Progress.jsx';
import { RegisterTable } from './RegisterTable.jsx';
import { RawData } from './RawData.jsx';
import { CopyButton } from '../CopyButton.jsx';
import { modelFromResult, plannedRows, releaseUrl, releaseAssetUrl, hostOf } from '../../lib/checks.js';
import { explainError } from '../../lib/errors.js';

const PROFILE_NOTE = {
  debug: 'debug image',
  'debug-read-only': 'read-only debug image',
  'locked-read-only': 'locked, read-only image',
};

function ReleaseLink({ tag }) {
  if (!tag) return <span className="muted">none</span>;
  return <a href={releaseUrl(tag)} target="_blank" rel="noopener noreferrer" className="mono">{tag}</a>;
}

function describe(kind, request, result) {
  if (kind === 'node') {
    const url = result?.nodeUrl || request?.nodeUrl;
    return { eyebrow: 'Node attestation', subject: hostOf(url) || url, noun: 'node' };
  }
  const url = result?.attestUrl || request?.attestUrl;
  const tag = result?.tagToUse || request?.releaseTag;
  const profile = request?.profile;
  const name = ['KMS', tag, profile].filter(Boolean).join(' · ');
  return {
    eyebrow: 'KMS attestation',
    subject: url ? `${name} via ${hostOf(url)}` : `${name} · pasted /attest response`,
    noun: 'KMS replica',
  };
}

function progressSteps(kind, request) {
  if (kind === 'node') {
    return [
      { phase: 'attest', label: `Fetch a fresh quote from ${hostOf(request?.nodeUrl)} and verify it with Intel Trust Authority` },
      { phase: 'policy', label: `Load the measurements published for ${request?.releaseTag || 'the latest mero-tee release'}` },
      { phase: 'compare', label: 'Check MRTD and RTMR0–3 against them' },
    ];
  }
  return [
    {
      phase: 'attest',
      label: request?.attestUrl
        ? `Fetch a fresh quote through ${hostOf(request.attestUrl)} and verify it with Intel Trust Authority`
        : 'Verify the pasted quote with Intel Trust Authority',
    },
    { phase: 'policy', label: `Load the KMS policies of ${request?.releaseTag || 'the five latest mero-kms releases'}` },
    { phase: 'compare', label: 'Check MRTD and RTMR0–3 against them' },
  ];
}

function summaryFor(kind, model, result, noun) {
  const profile = model.comparison?.profile;
  if (model.verdict === 'pass') {
    const what = kind === 'node' ? 'This node' : 'This KMS replica';
    return `${what} is genuine Intel TDX hardware running the software published in ${result.tagToUse}${profile ? ` for the ${profile} profile` : ''}.`;
  }
  if (model.verdict === 'fail') {
    const n = model.counts.failed;
    return `${n} check${n > 1 ? 's' : ''} failed. Do not trust this ${noun} until ${n > 1 ? 'they pass' : 'it passes'}; the failing check is open below.`;
  }
  return 'A required check could not run, so this is not a verdict either way. See below for what was not checked.';
}

/**
 * A node or KMS verification: progress while it runs, then the verdict, the
 * checklist, and the details below them.
 */
export function ResultView({ kind, state, onRetry }) {
  const { status, phase, error, result, request } = state;
  const { eyebrow, subject, noun } = describe(kind, request, result);
  const retry = onRetry && (
    <button type="button" className="btn btn--ghost btn--sm" onClick={onRetry} disabled={status === 'loading'}>
      Verify again
    </button>
  );
  const copyLink = <CopyButton text={typeof window !== 'undefined' ? window.location.href : ''} label="Copy link" />;

  if (status === 'loading') {
    return (
      <Verdict verdict="loading" eyebrow={eyebrow} subject={subject}>
        <Progress steps={progressSteps(kind, request)} phase={phase} />
      </Verdict>
    );
  }

  if (status === 'error') {
    const e = explainError(error);
    const rows = plannedRows(kind, { paste: kind === 'kms' && !request?.attestUrl }).map((r) => (
      r.id === e.check ? { ...r, status: 'fail', result: e.actual } : r
    ));
    return (
      <>
        <Verdict
          verdict={e.verdict}
          eyebrow={eyebrow}
          subject={subject}
          actions={<>{retry}{copyLink}</>}
        >
          <div className="explain">
            <h2>{e.title}</h2>
            <p>{e.explain}</p>
            <p><strong>What to do:</strong> {e.action}</p>
            <p className="raw">Details: {e.detail}</p>
          </div>
        </Verdict>
        <section className="section" aria-labelledby="checks-title">
          <div className="section__head">
            <h2 id="checks-title">Checks</h2>
            <span className="muted small">The verification stopped, so the remaining checks did not run.</span>
          </div>
          <Checklist key={error} rows={rows} />
        </section>
      </>
    );
  }

  if (status !== 'success' || !result) return null;

  const model = modelFromResult(result);
  const tag = result.tagToUse;
  const profile = model.comparison?.profile;
  const policyAsset = kind === 'node' ? 'published-mrtds.json' : profile ? `kms-attestation-policy.${profile}.json` : null;
  const { passed, failed, skipped } = model.counts;
  const countText = [`${passed} passed`, failed && `${failed} failed`, skipped && `${skipped} not checked`].filter(Boolean).join(' · ');

  const facts = [
    { label: 'Release', value: <ReleaseLink tag={tag} /> },
    profile && {
      label: model.comparison?.matched ? 'Profile' : 'Closest profile',
      value: <><span className="mono">{profile}</span> <span className="muted small">{PROFILE_NOTE[profile] || ''}</span></>,
    },
    kind === 'kms' && result.matchedImage && { label: 'Image', value: <span className="mono">{result.matchedImage}</span> },
    { label: 'Checked', value: <time dateTime={result.checkedAt}>{formatTime(result.checkedAt)}</time> },
    { label: 'Checks', value: countText },
  ].filter(Boolean);

  return (
    <>
      <Verdict
        verdict={model.verdict}
        eyebrow={eyebrow}
        subject={subject}
        summary={summaryFor(kind, model, result, noun)}
        facts={facts}
        actions={<>{retry}{copyLink}</>}
      >
        {model.caveats.map((c) => (
          <p key={c.id} className="notice"><strong>{c.title}: not checked.</strong> {c.reason}</p>
        ))}
      </Verdict>

      <section className="section" aria-labelledby="checks-title">
        <div className="section__head">
          <h2 id="checks-title">Checks</h2>
          <span className="muted small">Every check this verifier makes for this kind of machine.</span>
        </div>
        <Checklist
          key={result.checkedAt}
          rows={model.rows}
          context={{
            claims: result.ita_claims,
            sources: result.measurementSources,
            policyLabel: kind === 'node' ? `${tag} published-mrtds.json` : `${tag} kms-attestation-policy`,
          }}
        />
      </section>

      {model.comparison && (
        <section className="section" aria-labelledby="measure-title">
          <div className="section__head">
            <h2 id="measure-title">Measurements</h2>
            {policyAsset && (
              <a className="small" href={releaseAssetUrl(tag, policyAsset)} target="_blank" rel="noopener noreferrer">
                {policyAsset} in {tag}
              </a>
            )}
          </div>
          {model.itaDisagree.length > 0 && (
            <p className="notice">
              Intel’s claims for {model.itaDisagree.map((r) => r.toUpperCase()).join(', ')} differ from the values parsed
              from the quote. The table uses the quote; compare with the raw claims below.
            </p>
          )}
          <div className="pane">
            <RegisterTable
              registers={model.comparison.registers}
              sources={result.measurementSources}
              expectedLabel={`${tag} · ${profile}`}
            />
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="raw-title">
        <div className="section__head">
          <h2 id="raw-title">Raw data</h2>
          {tag && (
            <a className="small" href={releaseUrl(tag)} target="_blank" rel="noopener noreferrer">
              Release that published the measurements
            </a>
          )}
        </div>
        <RawData
          claims={result.ita_claims}
          attestation={result.attestation}
          attestationNote={
            kind === 'node' || result.attestUrl
              ? 'What the verifier kept from the response: the quote alone (base64), as Intel verified it.'
              : 'The /attest response you pasted.'
          }
          token={result.ita_token}
          policy={profile ? result.policiesByProfile?.[profile] : null}
          policyTitle={profile ? `Published policy · ${tag} · ${profile}` : undefined}
        />
      </section>
    </>
  );
}
