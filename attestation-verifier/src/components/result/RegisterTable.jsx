import { REGISTER_INFO } from '../../lib/registers.js';
import { StatusTag } from './StatusTag.jsx';

/**
 * MRTD and RTMR0-3: the value the release allows, the value in the quote, and
 * whether they match. `compact` leaves out what each register records.
 */
export function RegisterTable({ registers, sources, expectedLabel, actualLabel = 'from the quote', compact = false }) {
  return (
    <div className="scroll-x" tabIndex={0} role="region" aria-label="Measurement registers">
      <table className={compact ? 'mini' : 'tbl tbl--measure'}>
        <thead>
          <tr>
            <th scope="col">Register</th>
            {!compact && <th scope="col">What it records</th>}
            <th scope="col">Expected{expectedLabel ? ` · ${expectedLabel}` : ''}</th>
            <th scope="col">Actual · {actualLabel}</th>
            <th scope="col">Match</th>
          </tr>
        </thead>
        <tbody>
          {registers.map((r) => {
            const info = REGISTER_INFO[r.reg];
            const expected = r.match ? r.actual : r.allowed[0];
            const more = r.allowed.length - 1;
            return (
              <tr key={r.reg}>
                <td className="strong">{info.label}</td>
                {!compact && <td className="muted small">{info.meaning}</td>}
                <td className="hex">
                  {expected || <span className="muted">none published</span>}
                  {more > 0 && <span className="sub">or one of {more} other allowed value{more > 1 ? 's' : ''}</span>}
                </td>
                <td className={`hex${r.match ? '' : ' hex--diff'}`}>
                  {r.actual || <span className="muted">not in the quote</span>}
                  {sources?.[r.reg] === 'ita' && <span className="sub">from Intel’s claims (quote not parsed)</span>}
                </td>
                <td><StatusTag status={r.match ? 'pass' : 'fail'} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
