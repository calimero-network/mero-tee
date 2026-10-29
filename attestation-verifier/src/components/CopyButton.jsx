import { useState } from 'react';

/** Copies `text`; says so for a moment, and to screen readers. */
export function CopyButton({ text, label = 'Copy', className = 'btn btn--ghost btn--sm' }) {
  const [state, setState] = useState('idle');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState('done');
    } catch {
      setState('failed');
    }
    setTimeout(() => setState('idle'), 1600);
  };
  return (
    <button type="button" className={className} onClick={copy} disabled={!text}>
      <span aria-live="polite">
        {state === 'done' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
      </span>
    </button>
  );
}
