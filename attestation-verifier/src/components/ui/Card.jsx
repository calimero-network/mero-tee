/**
 * Reusable card component.
 * Open/closed: extend via children, not modification.
 */

export function Card({ title, children, status, className = '' }) {
  const statusClass =
    status === 'ok' ? 'card-ok' : status === 'err' ? 'card-err' : status === 'warn' ? 'card-warn' : '';
  return (
    <div className={`result-card ${statusClass} ${className}`.trim()}>
      {title && <h3 className="card-title">{title}</h3>}
      <div className="card-body">{children}</div>
    </div>
  );
}
