import { Card } from '../ui/Card.jsx';
import { truncateHex } from '../../utils/hex.js';

export function RtmrCard({ quoteRtmrs, replayedRtmrs }) {
  const rows = [];
  for (let i = 0; i <= 3; i++) {
    const fromQuote = quoteRtmrs?.[`rtmr${i}`] || null;
    const replayed = replayedRtmrs?.[i] ?? null;
    const match = fromQuote && replayed && fromQuote === replayed;
    rows.push(
      <div key={i} className="rtmr-row">
        <span className="rtmr-label">RTMR{i}</span>
        <div className="rtmr-values">
          <div>
            <span className="label">Received (quote):</span>{' '}
            <code>{truncateHex(fromQuote, 12)}</code>
          </div>
          <div>
            <span className="label">Replayed (event log):</span>{' '}
            <code>{truncateHex(replayed, 12)}</code>
          </div>
          {fromQuote && replayed && (
            <span className={match ? 'result-ok' : 'result-err'}>
              {match ? '✓ Match' : '✗ Mismatch'}
            </span>
          )}
        </div>
      </div>
    );
  }
  if (quoteRtmrs?.mrtd) {
    rows.push(
      <div key="mrtd" className="rtmr-row">
        <span className="rtmr-label">MRTD</span>
        <code>{truncateHex(quoteRtmrs.mrtd, 12)}</code>
      </div>
    );
  }
  if (quoteRtmrs?.tcb_status) {
    rows.push(
      <div key="tcb" className="rtmr-row">
        <span className="rtmr-label">TCB status</span>
        <code>{quoteRtmrs.tcb_status}</code>
      </div>
    );
  }
  return <Card title="RTMR measurements">{rows}</Card>;
}
