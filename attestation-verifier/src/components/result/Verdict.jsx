const TITLES = {
  pass: ['✓', 'Verified'],
  fail: ['✕', 'Not verified'],
  incomplete: ['!', 'Could not verify'],
  loading: ['', 'Verifying…'],
};

export function formatTime(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return iso;
  }
}

/**
 * The outcome, first: one word, what was checked, when, and the facts that
 * identify it. `children` carries the explanation, caveats or progress.
 */
export function Verdict({ verdict, eyebrow, subject, summary, facts = [], actions, children }) {
  const [mark, title] = TITLES[verdict] || TITLES.incomplete;
  return (
    <section className={`verdict verdict--${verdict}`} aria-labelledby="verdict-title" aria-live="polite">
      <div className="verdict__top">
        <div className="verdict__title">
          {verdict === 'loading' ? (
            <span className="verdict__mark" aria-hidden="true"><span className="spinner" /></span>
          ) : (
            <span className="verdict__mark" aria-hidden="true">{mark}</span>
          )}
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            <h1 id="verdict-title">{title}</h1>
          </div>
        </div>
        {actions && <div className="verdict__actions">{actions}</div>}
      </div>
      {subject && <div className="verdict__subject">{subject}</div>}
      {summary && <p className="verdict__summary">{summary}</p>}
      {children}
      {facts.length > 0 && (
        <dl className="verdict__facts">
          {facts.filter(Boolean).map((f) => (
            <div key={f.label}>
              <dt className="lbl">{f.label}</dt>
              <dd>{f.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}
