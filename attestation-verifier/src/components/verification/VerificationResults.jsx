import { QuoteAttestationCard } from './QuoteAttestationCard.jsx';
import { RtmrCard } from './RtmrCard.jsx';
import { ComposeHashCard } from './ComposeHashCard.jsx';
import { EventLogCard } from './EventLogCard.jsx';

/**
 * Shared verification results display.
 * Single responsibility: render result cards from verification data.
 * Paste-only results omit quote/RTMR cards (no ITA verification).
 */
export function VerificationResults({ result }) {
  if (!result) return null;

  const hasQuoteData = result.ita_token_verified != null;
  const hasRtmrData = result.quoteRtmrs != null || result.replayedRtmrs != null;

  return (
    <div className="results-section">
      <h2>Results</h2>
      <div className="results-grid">
        {hasQuoteData && <QuoteAttestationCard verified={result.ita_token_verified} />}
        {hasRtmrData && (
          <RtmrCard quoteRtmrs={result.quoteRtmrs} replayedRtmrs={result.replayedRtmrs} />
        )}
        <ComposeHashCard
          composeHash={result.composeHash}
          appId={result.appId}
          matches={result.matches}
          profiles={result.profiles}
          tagToUse={result.tagToUse}
        />
        <EventLogCard eventCount={result.eventCount} />
      </div>
      {result.tagToUse && (
        <p className="results-footer">
          Checked against release: {result.tagToUse}
          {result.matches?.length > 0 ? ' (matched)' : ''}
        </p>
      )}
    </div>
  );
}
