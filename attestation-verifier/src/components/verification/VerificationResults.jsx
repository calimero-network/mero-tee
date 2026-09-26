import { QuoteAttestationCard } from './QuoteAttestationCard.jsx';
import { RtmrCard } from './RtmrCard.jsx';
import { QuoteJsonCard } from './QuoteJsonCard.jsx';

/**
 * Shared verification results display.
 * Single responsibility: render result cards from verification data.
 * KMS results carry `matches` (release profiles whose KMS allowlists hold the quote)
 * and `nonce_verified`; node results compare against published-mrtds.json.
 */
export function VerificationResults({ result }) {
  if (!result) return null;

  const hasQuoteData = result.ita_token_verified != null;
  const hasRtmrData = result.quoteRtmrs != null;
  const isKms = Array.isArray(result.matches);

  let cardIndex = 0;
  const delay = (n) => ({ style: { animationDelay: `${n * 0.07}s` } });

  return (
    <div className="results-section">
      <h2>Results</h2>
      <div className="results-grid">
        {hasQuoteData && <QuoteAttestationCard verified={result.ita_token_verified} {...delay(cardIndex++)} />}
        {hasRtmrData && (
          <RtmrCard
            quoteRtmrs={result.quoteRtmrs}
            itaRtmrs={result.itaRtmrs}
            measurementSources={result.measurementSources}
            policiesByProfile={result.policiesByProfile}
            tagToUse={result.tagToUse}
            matchedProfile={result.selectedProfile || result.matches?.[0]}
            {...delay(cardIndex++)}
          />
        )}
        {hasQuoteData && (
          <QuoteJsonCard itaClaims={result.ita_claims} attestation={result.attestation} {...delay(cardIndex++)} />
        )}
      </div>
      {isKms && (
        <p className="results-footer">
          {result.nonce_verified
            ? 'Quote is bound to the nonce you sent to /attest.'
            : 'No nonce given: freshness of the pasted quote was not checked.'}
        </p>
      )}
      {result.tagToUse && (
        <p className="results-footer">
          Checked against release: {result.tagToUse}
          {isKms && (result.matches.length > 0
            ? ` (matched ${result.matches.join(', ')}${result.matchedImage ? `, image ${result.matchedImage}` : ''})`
            : ' (no profile matches all of MRTD and RTMR0–3)')}
        </p>
      )}
    </div>
  );
}
