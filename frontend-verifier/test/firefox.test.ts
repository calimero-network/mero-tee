/**
 * The Firefox path, driven through a fake `browser`: a response is held, hashed and then
 * delivered or stopped before the page receives it.
 */
import { describe, expect, it } from 'vitest';

import { install, type GetListing } from '../src/browser/background.js';
import { Unverifiable } from '../src/core/listing.js';
import { sha256Hex } from '../src/core/site.js';

const LABEL = 'd'.repeat(52);
const ORIGIN = `https://${LABEL}.apps.calimero.network`;
const enc = (s: string) => new TextEncoder().encode(s);

/** A fake `filterResponseData` stream: what the page would receive. */
class Stream {
  delivered: string[] = [];
  closed = false;
  ondata: (e: { data: ArrayBuffer }) => void = () => {};
  onstop: () => Promise<void> | void = () => {};
  write(bytes: Uint8Array) {
    this.delivered.push(new TextDecoder().decode(bytes));
  }
  close() {
    this.closed = true;
  }
}

function fakeBrowser() {
  const streams = new Map<string, Stream>();
  let listener: (d: unknown) => unknown = () => ({});
  const store: Record<string, unknown> = {};
  const noop = () => {};
  const api = {
    webRequest: {
      filterResponseData: (id: string) => {
        const s = new Stream();
        streams.set(id, s);
        return s;
      },
      onBeforeRequest: { addListener: (f: (d: unknown) => unknown) => (listener = f) },
      onCompleted: { addListener: noop },
    },
    action: { setBadgeText: noop, setBadgeBackgroundColor: noop, setTitle: noop },
    notifications: { create: noop },
    storage: { local: { get: async () => store }, onChanged: { addListener: noop } },
    tabs: { onRemoved: { addListener: noop }, onUpdated: { addListener: noop } },
    runtime: { onMessage: { addListener: noop } },
  };
  /** The page loads `path` in tab 1; the server answers `body`. Resolves to what the page got. */
  async function load(id: string, path: string, body: string, type = 'script') {
    listener({ requestId: id, url: `${ORIGIN}/1.0.0/${path}`, tabId: 1, type });
    const s = streams.get(id)!;
    s.ondata({ data: enc(body).buffer as ArrayBuffer });
    await s.onstop();
    return s;
  }
  return { api, load };
}

async function listingOf(files: Record<string, string>): Promise<GetListing> {
  const map = new Map<string, { sha256: string; size: number }>();
  for (const [p, b] of Object.entries(files)) map.set(p, { sha256: await sha256Hex(enc(b)), size: b.length });
  return async () => ({
    listing: { package: 'com.example.app', version: '1.0.0', entry: 'index.html', files: map },
    attested: { node: 'https://n1', release: '2.3.162', profile: 'locked-read-only' },
  });
}

describe('Firefox holds every file until it is checked', () => {
  it("delivers the release's files and stops a changed or unlisted one before the page gets it", async () => {
    const { api, load } = fakeBrowser();
    const tabs = install(api, await listingOf({ 'index.html': '<html>', 'assets/app.js': 'app()' }));

    const page = await load('1', '', '<html>', 'main_frame');
    expect(page.delivered).toEqual(['<html>']);
    const js = await load('2', 'assets/app.js', 'app()');
    expect(js.delivered).toEqual(['app()']);
    expect(tabs.get(1)?.checks.map((c) => c.status)).toEqual(['ok', 'ok']);

    const swapped = await load('3', 'assets/app.js', 'app(); steal()');
    expect(swapped.delivered).toEqual([]);
    expect(swapped.closed).toBe(true);
    const extra = await load('4', 'assets/keylogger.js', 'log()');
    expect(extra.delivered).toEqual([]);
    expect(tabs.get(1)?.blocked).toHaveLength(2);
  });

  it('replaces a changed page document with a warning instead of running it', async () => {
    const { api, load } = fakeBrowser();
    install(api, await listingOf({ 'index.html': '<html>' }));
    const page = await load('1', '', '<html><script src=evil.js></script>', 'main_frame');
    expect(page.delivered).toHaveLength(1);
    expect(page.delivered[0]).toContain('This page was blocked');
    expect(page.delivered[0]).not.toContain('evil.js');
  });

  it('delivers a page it cannot check with an amber verdict, and blocks it in strict mode', async () => {
    const unreachable: GetListing = async () => {
      throw new Unverifiable('no node of the cluster passed attestation');
    };
    const lax = fakeBrowser();
    const tabs = install(lax.api, unreachable);
    expect((await lax.load('1', '', '<html>', 'main_frame')).delivered).toEqual(['<html>']);
    expect(tabs.get(1)?.unverifiable).toContain('attestation');

    const strict = fakeBrowser();
    strict.api.storage.local.get = async () => ({ strict: true });
    install(strict.api, unreachable);
    await new Promise((r) => setTimeout(r, 0));
    const page = await strict.load('1', '', '<html>', 'main_frame');
    expect(page.delivered[0]).toContain('This page was blocked');
  });
});
