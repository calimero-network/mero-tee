/** The steps of a verification in flight; `phase` is the hook's current one. */
export function Progress({ steps, phase }) {
  const at = steps.findIndex((s) => s.phase === phase);
  return (
    <ol className="steps" aria-label="Progress">
      {steps.map((s, i) => {
        const state = i < at ? 'done' : i === at ? 'active' : 'todo';
        return (
          <li key={s.phase} className={`is-${state}`} aria-current={state === 'active' ? 'step' : undefined}>
            <span className="step-mark" aria-hidden="true">
              {state === 'done' ? '✓' : state === 'active' ? <span className="spinner" /> : i + 1}
            </span>
            <span>
              {s.label}
              <span className="sr-only">{state === 'done' ? ' (done)' : state === 'active' ? ' (in progress)' : ''}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}
