import { QuoteAttestationCard } from './QuoteAttestationCard.jsx';
import { RtmrCard } from './RtmrCard.jsx';
import { ComposeHashCard } from './ComposeHashCard.jsx';
import { EventLogCard } from './EventLogCard.jsx';
import { QuoteJsonCard } from './QuoteJsonCard.jsx';

/**
 * Shared verification results display.
 * Single responsibility: render result cards from verification data.
 * Node (merod) verification omits compose hash and event log (KMS-only).
 */
export function VerificationResults({ result }) {
  if (!result) return null;

  const hasQuoteData = result.ita_token_verified != null;
  const hasRtmrData = result.quoteRtmrs != null || result.replayedRtmrs != null;
  const hasComposeOrEventLog = (result.eventCount ?? 0) > 0 || result.composeHash != null;

  return (
    <div className="results-section">
      <h2>Results</h2>
      <div className="results-grid">
        {hasQuoteData && <QuoteAttestationCard verified={result.ita_token_verified} />}
        {hasRtmrData && (
          <RtmrCard
            quoteRtmrs={result.quoteRtmrs}
            itaRtmrs={result.itaRtmrs}
            measurementSources={result.measurementSources}
            replayedRtmrs={result.replayedRtmrs}
            policiesByProfile={result.policiesByProfile}
            tagToUse={result.tagToUse}
            profileFromComposeHash={result.matches?.[0]}
          />
        )}
        {hasComposeOrEventLog && (
          <>
            <ComposeHashCard
              composeHash={result.composeHash}
              appId={result.appId}
              matches={result.matches}
              policyMatches={result.policyMatches}
              profiles={result.profiles}
              policyComposeHashesByProfile={result.policyComposeHashesByProfile}
              releaseComposePublishing={result.releaseComposePublishing}
              tagToUse={result.tagToUse}
              selectedProfile={result.selectedProfile}
            />
            <EventLogCard
              eventCount={result.eventCount}
              eventLog={result.eventLog}
              composeHash={result.composeHash}
              appId={result.appId}
              expectedComposeHashes={result.profiles}
              expectedPolicyComposeHashes={result.policyComposeHashesByProfile}
              rtmr3ReplaySteps={result.rtmr3ReplaySteps}
              quoteRtmr3={result.quoteRtmrs?.rtmr3}
              selectedProfile={result.selectedProfile}
            />
          </>
        )}
        {hasQuoteData && (
          <QuoteJsonCard itaClaims={result.ita_claims} attestation={result.attestation} />
        )}
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
