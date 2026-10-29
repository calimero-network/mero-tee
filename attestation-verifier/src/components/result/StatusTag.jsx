const LABELS = {
  pass: ['✓', 'Pass'],
  fail: ['✕', 'Fail'],
  skip: ['–', 'Not checked'],
  info: ['◦', 'Info'],
  notrun: ['·', 'Not run'],
};

export function StatusTag({ status }) {
  const [mark, label] = LABELS[status] || LABELS.notrun;
  return (
    <span className={`tag tag--${status}`}>
      <span aria-hidden="true">{mark}</span>
      {label}
    </span>
  );
}
