/**
 * What an error from the API or the hooks means for the person reading it, and
 * what to do next. `check` names the checklist row a failure belongs to: those
 * errors are a check that failed (verdict "Not verified"); the rest stopped the
 * run before an answer (verdict "Could not verify").
 */

const RULES = [
  {
    test: /Nonce mismatch/i,
    check: 'nonce',
    actual: 'report_data[0..32] differs from the nonce sent: possibly a replayed quote',
    title: 'The quote was not made for this request',
    explain:
      'The quote’s report data does not carry the nonce sent with this request. A genuine machine always includes it, so this answer may be a replay of an older quote, or something on the way changed it.',
    action: 'Do not trust this machine for now. Verify once more; if it fails again, report it to the operator.',
  },
  {
    test: /does not commit to the transport key/i,
    check: 'identity',
    actual: 'report_data[32..64] does not commit to the transport key the node named',
    title: 'The quote does not commit to the node’s transport key',
    explain:
      'The node named a transport key that its own quote does not commit to, so the key cannot be tied to the attested machine.',
    action: 'Do not open a sealed session with this node. Report it to the operator.',
  },
  {
    test: /malformed transportPublicKey/i,
    check: 'identity',
    title: 'The node reported a malformed transport key',
    explain: 'The transport key the node named is not 32 bytes, so it cannot be tied to the quote.',
    action: 'Report it to the operator.',
  },
  {
    test: /commit to the agent and keys|claimed agent has both/i,
    check: 'keys',
    actual: 'report_data[32..64] does not commit to the agent and keys the gate named',
    title: 'The quote does not commit to the agent’s keys',
    explain: 'The agent id and keys in the response are not the ones the quote’s report data commits to.',
    action: 'Do not authorize this agent’s key. Call /attest again and paste the whole response unchanged.',
  },
  {
    test: /host not in allowed list/i,
    title: 'This address is not one the verifier will contact',
    explain:
      'To avoid being used to probe arbitrary hosts, the verifier only contacts Calimero fleet node names (<name>.relay.cloud.calimero.network and the staging twin), bare public IP addresses, and the Calimero managers for KMS checks.',
    action: 'Use the Verify link from the Calimero console or manager, or the node’s relay URL.',
  },
  {
    test: /must name a public address/i,
    title: 'The address is not on the public internet',
    explain: 'The host resolves to a private, loopback or reserved address, which the verifier does not contact.',
    action: 'Use the node’s public URL.',
  },
  {
    test: /must use HTTPS|must use HTTP|Invalid node URL|Invalid KMS attestation URL|must not carry credentials/i,
    title: 'The URL is not valid',
    explain: 'The verifier needs a plain http(s) URL without a user name or password (https only for a KMS attestation URL).',
    action: 'Check the URL and try again.',
  },
  {
    test: /did not answer/i,
    title: 'The machine did not answer',
    explain: 'The verifier asked for a fresh quote and got no answer within 20 seconds.',
    action: 'Check that the node (or the manager relaying the KMS) is running and reachable from the internet, then verify again.',
  },
  {
    test: /attest failed: (\d+)|KMS attestation URL failed: (\d+)/i,
    title: 'The machine refused to attest',
    explain: 'The attestation endpoint answered with an error status instead of a quote.',
    action: 'The node may still be starting, or may not run an attesting build. Try again in a minute; if it persists, ask the operator.',
  },
  {
    test: /missing quote_b64|missing quoteB64|No attestation/i,
    title: 'The response has no quote',
    explain: 'The attestation response carries no TDX quote to verify.',
    action: 'For a paste, include the whole /attest response. For a node, check that it runs in a TDX VM.',
  },
  {
    test: /Unsupported TDX quote version|Quote too short/i,
    title: 'The quote is not a TDX quote this verifier reads',
    explain: 'The quote is truncated or not a version 4 or 5 Intel TDX quote.',
    action: 'Paste the response unchanged, or check the machine runs on Intel TDX.',
  },
  {
    test: /ITA verification failed/i,
    title: 'Intel Trust Authority did not verify the quote',
    explain:
      'Intel Trust Authority returned no verdict: it rejected the quote, or could not be reached.',
    action: 'Try again in a minute. If it keeps failing the quote itself may be invalid.',
  },
  {
    test: /ITA_API_KEY not configured/i,
    title: 'The verifier is not configured',
    explain: 'This deployment has no Intel Trust Authority API key, so it cannot verify quotes.',
    action: 'Report this to Calimero.',
  },
  {
    test: /not valid JSON/i,
    title: 'The pasted text is not JSON',
    explain: 'The box needs JSON exactly as it was returned, such as the body of an /attest response.',
    action: 'Paste the whole text, from the opening { to the closing }.',
  },
  {
    test: /nonce_b64 must be 32 bytes/i,
    title: 'The nonce is not 32 bytes',
    explain: 'The nonce must be the 32 random bytes you sent to /attest, base64-encoded.',
    action: 'Paste the exact nonce you sent.',
  },
  {
    test: /Failed to fetch|NetworkError|Load failed|HTTP 5\d\d/i,
    title: 'The verifier’s service could not be reached',
    explain: 'The request to this site’s verification API failed.',
    action: 'Check your connection and try again.',
  },
];

export function explainError(message) {
  const msg = String(message || 'Verification failed');
  const rule = RULES.find((r) => r.test.test(msg));
  if (!rule) {
    return {
      verdict: 'incomplete',
      check: null,
      title: 'Verification could not finish',
      explain: 'An unexpected error stopped the verification before it reached an answer.',
      action: 'Try again. If it persists, report the details below.',
      detail: msg,
    };
  }
  return {
    verdict: rule.check ? 'fail' : 'incomplete',
    check: rule.check || null,
    actual: rule.actual || rule.title,
    title: rule.title,
    explain: rule.explain,
    action: rule.action,
    detail: msg,
  };
}
