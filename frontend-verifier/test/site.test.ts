import { describe, expect, it } from 'vitest';

import { appRequest, appsEnvironment, checkFile, servedFile, sha256Hex, type Listing } from '../src/core/site.js';

const hex = (s: string) => sha256Hex(new TextEncoder().encode(s));

async function listing(files: Record<string, string>, entry = 'index.html'): Promise<Listing> {
  const map = new Map<string, { sha256: string; size: number }>();
  for (const [path, body] of Object.entries(files)) map.set(path, { sha256: await hex(body), size: body.length });
  return { package: 'com.example.app', version: '1.2.0', entry, files: map };
}

const LABEL = 'a'.repeat(52);

describe('which requests are app pages', () => {
  it('takes a release path on a Calimero Cloud apps domain, with its environment', () => {
    expect(appRequest(`https://${LABEL}.apps.calimero.network/1.2.0/assets/app.js?x=1`)).toEqual({
      origin: `https://${LABEL}.apps.calimero.network`,
      hostname: `${LABEL}.apps.calimero.network`,
      environment: 'production',
      version: '1.2.0',
      file: 'assets/app.js',
    });
    expect(appRequest(`https://${LABEL}.apps.relay.staging.cloud.calimero.network/0.1.0-rc.2/`)?.environment).toBe('staging');
  });

  it('leaves out everything else: other hosts, nested names, plain http, the root and the well-known file', () => {
    for (const url of [
      'https://example.com/1.2.0/index.html',
      `https://x.${LABEL}.apps.calimero.network/1.2.0/`,
      `http://${LABEL}.apps.calimero.network/1.2.0/`,
      `https://${LABEL}.apps.calimero.network/`,
      `https://${LABEL}.apps.calimero.network/.well-known/calimero.json`,
      `https://${LABEL}.apps.calimero.network/app/abc/`,
      'not a url',
    ]) {
      expect(appRequest(url), url).toBeNull();
    }
    expect(appsEnvironment('apps.calimero.network')).toBeNull();
  });
});

describe('which release file the node serves for a request (core app_host::resolve)', () => {
  it('serves the exact path, the entry for the root and for client routes, and strips leading segments', async () => {
    const l = await listing({ 'index.html': '<html>', 'assets/app.js': 'js' });
    expect(servedFile(l, '', true)).toBe('index.html');
    expect(servedFile(l, 'assets/app.js', false)).toBe('assets/app.js');
    expect(servedFile(l, 'settings/profile', true)).toBe('index.html');
    expect(servedFile(l, 'settings/profile', false)).toBeNull();
    expect(servedFile(l, 'deep/link/assets/app.js', false)).toBe('assets/app.js');
    expect(servedFile(l, 'assets/evil.js', false)).toBeNull();
  });
});

describe('checking a loaded file', () => {
  it('passes the release bytes and catches changed or unlisted ones', async () => {
    const l = await listing({ 'index.html': '<html>', 'assets/app.js': 'console.log(1)' });
    const req = appRequest(`https://${LABEL}.apps.calimero.network/1.2.0/assets/app.js`)!;
    const bytes = (s: string) => new TextEncoder().encode(s);
    expect((await checkFile(l, req, 'u', bytes('console.log(1)'), false)).status).toBe('ok');
    const changed = await checkFile(l, req, 'u', bytes('steal()'), false);
    expect(changed).toMatchObject({ status: 'mismatch', path: 'assets/app.js', expected: await hex('console.log(1)') });
    const extra = appRequest(`https://${LABEL}.apps.calimero.network/1.2.0/assets/extra.js`)!;
    expect(await checkFile(l, extra, 'u', bytes('x'), false)).toMatchObject({ status: 'unlisted', file: 'assets/extra.js' });
    const page = appRequest(`https://${LABEL}.apps.calimero.network/1.2.0/inbox`)!;
    expect((await checkFile(l, page, 'u', bytes('<html>'), true)).status).toBe('ok');
    expect((await checkFile(l, page, 'u', bytes('<html><script>steal()</script>'), true)).status).toBe('mismatch');
  });
});
