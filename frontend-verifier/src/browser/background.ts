/**
 * The extension's background: one listing per release, one state per tab, and the browser's
 * way of seeing each file the page loads.
 *
 * - Firefox (`webRequest.filterResponseData`): every response from an app origin is held,
 *   hashed and compared before the page receives a byte. A file that does not match the
 *   release, or that the release does not list, is never delivered; a page document is
 *   replaced by a warning.
 * - Chrome (no access to response bodies): each file the tab loaded is fetched again and
 *   compared after the fact. A mismatch turns the badge red and raises a notification; the
 *   page has already run. See docs: "Levels of frontend trust".
 */

import { appRequest, appsDomains, checkFile, type AppRequest, type Listing } from '../core/site.js';
import { fetchListing, Unverifiable, type Attested } from '../core/listing.js';
import { badge, newTab, verdict, type TabState } from '../core/verdict.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Where a release's listing comes from: `fetchListing` in the extension, a fake in tests. */
export type GetListing = (request: AppRequest) => Promise<{ listing: Listing; attested: Attested }>;

/**
 * Wire the verifier into `api` (the browser's `browser` or `chrome`). Answers the per-tab
 * state, for tests.
 */
export function install(api: any, getListing: GetListing = fetchListing): Map<number, TabState> {
/** Firefox can read and stop a response before the page gets it. */
const canFilter = typeof api.webRequest?.filterResponseData === 'function';

const tabs = new Map<number, TabState>();
/**
 * Strict mode (off by default, set from the popup): a page that cannot be checked is blocked
 * too. Without it a page is delivered with an amber badge, so someone who can both swap the
 * page and keep every node from answering gets a warning shown, not a block.
 */
let strict = false;
void api.storage?.local?.get('strict').then((v: { strict?: boolean }) => {
  strict = v?.strict === true;
});
api.storage?.onChanged?.addListener((changes: { strict?: { newValue?: boolean } }) => {
  if (changes.strict) strict = changes.strict.newValue === true;
});
/** One attested listing per release, shared by every tab on it. */
const listings = new Map<string, Promise<{ listing: Listing; attested: Attested }>>();

function listingFor(request: AppRequest) {
  const key = `${request.origin}/${request.version}`;
  let found = listings.get(key);
  if (!found) {
    found = getListing(request);
    // A failure is not remembered: the next page load asks again.
    found.catch(() => listings.delete(key));
    listings.set(key, found);
  }
  return found;
}

function tabFor(tabId: number, request: AppRequest, isDocument: boolean): TabState {
  let tab = tabs.get(tabId);
  if (!tab || (isDocument && (tab.origin !== request.origin || tab.version !== request.version))) {
    tab = newTab(request.origin, request.version);
    tabs.set(tabId, tab);
  }
  return tab;
}

function show(tabId: number) {
  const tab = tabs.get(tabId);
  const action = api.action ?? api.browserAction;
  if (!tab) {
    void action.setBadgeText({ tabId, text: '' });
    return;
  }
  const b = badge(verdict(tab));
  void action.setBadgeText({ tabId, text: b.text });
  void action.setBadgeBackgroundColor({ tabId, color: b.color });
  void action.setTitle({ tabId, title: `Calimero: ${b.title}` });
}

function warnTampered(tab: TabState) {
  api.notifications?.create?.({
    type: 'basic',
    iconUrl: 'icon-128.png',
    title: 'This Calimero app page was changed',
    message: `${tab.origin} served a file that is not part of release ${tab.version}. Close the page and do not sign in.`,
  });
}

async function attach(tab: TabState, request: AppRequest): Promise<Listing | null> {
  try {
    const { listing, attested } = await listingFor(request);
    tab.package = listing.package;
    tab.attested = attested;
    return listing;
  } catch (e) {
    tab.unverifiable = e instanceof Unverifiable ? e.reason : String(e);
    return null;
  }
}

const WARNING_PAGE = (origin: string) =>
  new TextEncoder().encode(
    `<!doctype html><meta charset="utf-8"><title>Page blocked</title>` +
      `<body style="font:16px system-ui;max-width:40em;margin:4em auto;padding:0 1em">` +
      `<h1>This page was blocked</h1><p>${origin} served a page that does not match the release ` +
      `its attested node verified. Someone between you and the node may have changed it. ` +
      `Do not sign in. The Calimero frontend verifier stopped it before it ran.</p></body>`,
  );

/** Firefox: hold the response, check it, then deliver it or stop it. */
function filter(details: any) {
  const request = appRequest(details.url);
  if (!request || details.tabId < 0) return {};
  const isDocument = details.type === 'main_frame' || details.type === 'sub_frame';
  const tab = tabFor(details.tabId, request, details.type === 'main_frame');
  const listing = attach(tab, request);
  const stream = api.webRequest.filterResponseData(details.requestId);
  const chunks: Uint8Array[] = [];
  stream.ondata = (e: { data: ArrayBuffer }) => chunks.push(new Uint8Array(e.data));
  stream.onstop = async () => {
    const body = concat(chunks);
    const known = await listing;
    if (!known) {
      // Unverifiable (the node could not be attested, or is too old): delivered with an amber
      // badge, or, in strict mode, stopped like a mismatch.
      if (strict) {
        tab.blocked.push(details.url);
        if (isDocument) stream.write(WARNING_PAGE(request.origin));
      } else {
        stream.write(body);
      }
      stream.close();
      show(details.tabId);
      return;
    }
    const check = await checkFile(known, request, details.url, body, isDocument);
    tab.checks.push(check);
    if (check.status === 'ok') {
      stream.write(body);
    } else {
      tab.blocked.push(details.url);
      if (isDocument) stream.write(WARNING_PAGE(request.origin));
      warnTampered(tab);
    }
    stream.close();
    show(details.tabId);
  };
  return {};
}

/** Chrome: fetch what the tab loaded again and compare it, after the fact. */
async function recheck(details: any) {
  const request = appRequest(details.url);
  if (!request || details.tabId < 0 || details.statusCode !== 200) return;
  const isDocument = details.type === 'main_frame' || details.type === 'sub_frame';
  const tab = tabFor(details.tabId, request, details.type === 'main_frame');
  const listing = await attach(tab, request);
  if (listing) {
    try {
      const res = await fetch(details.url, {
        credentials: 'omit',
        headers: isDocument ? { accept: 'text/html' } : {},
      });
      const check = await checkFile(listing, request, details.url, await res.arrayBuffer(), isDocument);
      tab.checks.push(check);
      if (check.status !== 'ok') warnTampered(tab);
    } catch (e) {
      tab.unverifiable = `a file could not be fetched again to check it (${String(e)})`;
    }
  }
  show(details.tabId);
}

function concat(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

const urls = appsDomains().map((d) => `https://*.${d}/*`);

if (canFilter) {
  api.webRequest.onBeforeRequest.addListener(filter, { urls }, ['blocking']);
} else {
  api.webRequest.onCompleted.addListener((d: any) => void recheck(d), { urls });
}

api.tabs.onRemoved.addListener((tabId: number) => tabs.delete(tabId));
api.tabs.onUpdated.addListener((tabId: number, change: { url?: string }) => {
  if (change.url && !appRequest(change.url)) {
    tabs.delete(tabId);
    show(tabId);
  }
});

/** The popup asks for its tab's state. */
api.runtime.onMessage.addListener((msg: { tabId?: number }, _sender: unknown, reply: (s: unknown) => void) => {
  const tab = typeof msg?.tabId === 'number' ? tabs.get(msg.tabId) : undefined;
  reply(tab ? { ...tab, verdict: verdict(tab), enforcing: canFilter, strict } : null);
  return false;
});

return tabs;
}
