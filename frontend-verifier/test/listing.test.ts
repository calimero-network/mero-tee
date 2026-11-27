import { describe, expect, it } from 'vitest';

import { fetchListing, policyFor, Unverifiable, type Connect } from '../src/core/listing.js';
import { appRequest } from '../src/core/site.js';

const LABEL = 'b'.repeat(52);
const request = appRequest(`https://${LABEL}.apps.calimero.network/1.2.0/`)!;
const SHA = 'c'.repeat(64);
const DIGESTS = {
  package: 'com.example.app',
  version: '1.2.0',
  entry: 'index.html',
  files: [{ path: 'index.html', sha256: SHA, size: 10 }],
};

function wellKnown(body: unknown, status = 200): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status })) as typeof fetch;
}

function node(answer: unknown | Error, seen: string[] = []): Connect {
  return (api) => ({
    get: async (path) => {
      seen.push(`${api[0]} ${path}`);
      if (answer instanceof Error) throw answer;
      return answer;
    },
    attested: () => ({ node: api[0]!, release: '2.3.162', profile: 'locked-read-only' }),
  });
}

describe('the listing a page is checked against', () => {
  it('comes from the attested node the page names, over the sealed channel', async () => {
    const seen: string[] = [];
    const { listing, attested } = await fetchListing(
      request,
      wellKnown({ package: 'com.example.app', api: ['https://n1.example.calimero.network'] }),
      node(DIGESTS, seen),
    );
    expect(seen).toEqual(['https://n1.example.calimero.network packages/com.example.app/1.2.0/frontend']);
    expect(listing.entry).toBe('index.html');
    expect(listing.files.get('index.html')).toEqual({ sha256: SHA, size: 10 });
    expect(attested.release).toBe('2.3.162');
  });

  it('is unverifiable rather than trusted when anything is off', async () => {
    const cases: Array<[string, typeof fetch, Connect]> = [
      ['no well-known file', wellKnown({}, 404), node(DIGESTS)],
      ['a malformed well-known file', wellKnown({ package: 7, api: 'x' }), node(DIGESTS)],
      ['a node too old for the route', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node(new Error('404 NOT_FOUND: no route'))],
      ['no node passes attestation', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node(new Error('quote does not verify'))],
      ['an answer for another package', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node({ ...DIGESTS, package: 'com.other' })],
      ['an answer for another release', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node({ ...DIGESTS, version: '9.9.9' })],
      ['a malformed hash', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node({ ...DIGESTS, files: [{ path: 'index.html', sha256: 'zz', size: 1 }] })],
      ['an entry it does not list', wellKnown({ package: 'com.example.app', api: ['https://n'] }), node({ ...DIGESTS, entry: 'main.html' })],
    ];
    for (const [why, fetchPlain, connectTo] of cases) {
      await expect(fetchListing(request, fetchPlain, connectTo), why).rejects.toBeInstanceOf(Unverifiable);
    }
  });

  it("is asked of nodes under the release policy of the page's Calimero Cloud", () => {
    expect(policyFor(request).release).toMatchObject({ minReleaseVersion: '2.3.109', releaseSource: 'https://cloud.calimero.network' });
    const staging = appRequest(`https://${LABEL}.apps.relay.staging.cloud.calimero.network/1.2.0/`)!;
    expect(policyFor(staging).release).toMatchObject({ releaseSource: 'https://staging.cloud.calimero.network', allowDebugProfile: true });
  });
});
