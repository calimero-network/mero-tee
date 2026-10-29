import { CopyButton } from '../CopyButton.jsx';

function RawBlock({ title, text, note }) {
  if (!text) return null;
  return (
    <details className="fold">
      <summary>{title}</summary>
      <div className="fold__body raw-block">
        <div className="raw-block__head">
          <span className="muted small">{note}</span>
          <CopyButton text={text} />
        </div>
        <pre>{text}</pre>
      </div>
    </details>
  );
}

const json = (v) => (v ? JSON.stringify(v, null, 2) : '');

/** The raw material behind the verdict, each part folded, with copy buttons. */
export function RawData({ claims, attestation, attestationNote, token, policy, policyTitle }) {
  return (
    <div>
      <RawBlock
        title="Intel Trust Authority claims"
        note="The decoded payload of the token Intel returned."
        text={json(claims)}
      />
      <RawBlock
        title="Attestation response"
        note={attestationNote || 'The response the quote came from.'}
        text={json(attestation)}
      />
      <RawBlock title="Intel token (JWT)" note="As Intel returned it; its signature is checked against Intel’s JWKS." text={token} />
      <RawBlock title={policyTitle || 'Published policy'} note="The release’s published values this quote was compared with." text={json(policy)} />
    </div>
  );
}
