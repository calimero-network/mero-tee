import { Fragment, useState } from 'react';
import { StatusTag } from './StatusTag.jsx';
import { RegisterTable } from './RegisterTable.jsx';

/** What each check expects, and how the verifier establishes it. */
const EXPECTED = {
  intel: {
    expected: 'Intel Trust Authority accepts the quote and issues a signed token',
    how: 'The verifier’s API sends the quote to Intel Trust Authority’s appraisal service.',
  },
  token: {
    expected: 'The token’s signature verifies against Intel’s published keys',
    how: 'Checked against portal.trustauthority.intel.com/certs, with issuer portal.trustauthority.intel.com.',
  },
  nonce: {
    expected: 'The first 32 bytes of the quote’s report_data equal the nonce',
    how: 'Read from the quote bytes Intel verified, not from anything sent beside them.',
  },
  identity: {
    expected: 'report_data[32..64] commits to the node’s transport key, and this URL completes a sealed handshake with it',
    how: 'The API checks the commitment, then makes one sealed request to /admin-api/health over the given URL.',
  },
  keys: {
    expected: 'report_data[32..64] = SHA-256 of the agent id and the provisioning, signing and owner keys',
    how: 'Recomputed by the API from the response the gate returned.',
  },
  measure: {
    expected: 'MRTD and RTMR0–3 are each in the release’s published list',
    how: 'Parsed from the quote bytes and compared with the release’s published measurements.',
  },
  tcb: {
    expected: 'Shown for reference; not a pass or fail condition here',
    how: 'The attester_tcb_status claim in Intel’s token.',
  },
};

function Detail({ row, context }) {
  const e = EXPECTED[row.id] || {};
  const actual = row.status === 'notrun' ? 'Not run: an earlier step stopped the verification.' : row.result || row.reason;
  return (
    <div className="check-detail">
      <dl className="kv">
        <dt>Expected</dt>
        <dd>{e.expected}</dd>
        <dt>Actual</dt>
        <dd>{actual}</dd>
        {row.id === 'intel' && context?.claims?.attester_type && (
          <>
            <dt>Attester</dt>
            <dd className="mono">{context.claims.attester_type}</dd>
          </>
        )}
        {row.id === 'tcb' && context?.claims?.attester_tcb_date && (
          <>
            <dt>TCB date</dt>
            <dd className="mono">{context.claims.attester_tcb_date}</dd>
          </>
        )}
        {row.id === 'measure' && row.profile && (
          <>
            <dt>Compared with</dt>
            <dd>
              {context?.policyLabel || 'policy'} · <span className="mono">{row.profile}</span>
            </dd>
          </>
        )}
        <dt>How</dt>
        <dd className="muted">{e.how}</dd>
      </dl>
      {row.id === 'measure' && row.registers && (
        <RegisterTable registers={row.registers} sources={context?.sources} compact />
      )}
    </div>
  );
}

export function Checklist({ rows, context }) {
  const [open, setOpen] = useState(() => new Set(rows.filter((r) => r.status === 'fail').map((r) => r.id)));
  const toggle = (id) => setOpen((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });

  return (
    <div className="pane">
      <table className="tbl checks">
        <thead>
          <tr>
            <th scope="col">Check</th>
            <th scope="col">What it means</th>
            <th scope="col">Result</th>
            <th scope="col"><span className="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const isOpen = open.has(row.id);
            const detailId = `check-detail-${row.id}`;
            return (
              <Fragment key={row.id}>
                <tr className={`check${isOpen ? ' is-open' : ''}`}>
                  <td className="check-name strong">{row.title}</td>
                  <td className="check-meaning">{row.meaning}</td>
                  <td className="check-result">
                    <StatusTag status={row.status} />
                    {(row.result || row.reason) && row.status !== 'notrun' && (
                      <span className="result-text">{row.status === 'skip' ? row.reason : row.result}</span>
                    )}
                  </td>
                  <td className="check-toggle">
                    <button
                      type="button"
                      className="linkbtn"
                      aria-expanded={isOpen}
                      aria-controls={isOpen ? detailId : undefined}
                      onClick={() => toggle(row.id)}
                    >
                      {isOpen ? 'Hide' : 'Details'}
                      <span className="sr-only"> for {row.title}</span>
                    </button>
                  </td>
                </tr>
                {isOpen && (
                  <tr className="detail" id={detailId}>
                    <td colSpan={4}>
                      <Detail row={row} context={context} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
