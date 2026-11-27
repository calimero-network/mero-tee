/**
 * Where a request sits on a Calimero app's origin, and which release file it is.
 *
 * A package's frontend is served at `{label}.{appsDomain}/{version}/{path}` (core's
 * `app_host`). `servedFile` mirrors core's `app_host::resolve`, so the extension checks the
 * same file the node would serve for that request: the exact path, the entry for an HTML
 * navigation to a client route, or the path with up to 16 leading segments dropped (a deep
 * link into an entry built with a relative base).
 */

import { CLOUD_ENVIRONMENTS, type CloudEnvironment } from '@calimero-network/mero-js';

/** Core's `app_host::MAX_STRIPPED_SEGMENTS`. */
export const MAX_STRIPPED_SEGMENTS = 16;

/** A request to a release's frontend: which origin, which release, which path in it. */
export interface AppRequest {
  origin: string;
  hostname: string;
  environment: CloudEnvironment;
  version: string;
  /** The path after `/{version}/`, without query or fragment, percent-decoded. */
  file: string;
}

/** The Calimero Cloud whose apps domain `hostname` is a direct subdomain of, or `null`. */
export function appsEnvironment(hostname: string): CloudEnvironment | null {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  for (const [env, info] of Object.entries(CLOUD_ENVIRONMENTS) as Array<[CloudEnvironment, { appsDomain: string }]>) {
    const suffix = `.${info.appsDomain}`;
    if (host.endsWith(suffix) && !host.slice(0, -suffix.length).includes('.')) return env;
  }
  return null;
}

/** Every apps domain the extension watches, for its host permissions and request filters. */
export function appsDomains(): string[] {
  return Object.values(CLOUD_ENVIRONMENTS).map((e) => e.appsDomain);
}

/**
 * The release file `url` asks for, when it is a request to a frontend on a Calimero Cloud apps
 * domain under `/{version}/`; `null` for anything else (the origin's root and its redirects,
 * `/.well-known/calimero.json`, another host).
 */
export function appRequest(url: string): AppRequest | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  const environment = appsEnvironment(u.hostname);
  if (!environment) return null;
  const rest = u.pathname.replace(/^\/+/, '');
  const slash = rest.indexOf('/');
  const version = slash < 0 ? rest : rest.slice(0, slash);
  if (!/^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$/.test(version)) return null;
  let file = slash < 0 ? '' : rest.slice(slash + 1);
  try {
    file = decodeURIComponent(file);
  } catch {
    return null;
  }
  return { origin: u.origin, hostname: u.hostname, environment, version, file };
}

/** What the node verified for a release: the entry and each file's SHA-256 (hex). */
export interface Listing {
  package: string;
  version: string;
  entry: string;
  files: Map<string, { sha256: string; size: number }>;
}

/**
 * The listed file the node serves for `file` (core's `app_host::resolve`), or `null` when it
 * serves none: then whatever came back is not the release's.
 */
export function servedFile(listing: Listing, file: string, wantsHtml: boolean): string | null {
  if (file === '') return listing.entry;
  if (listing.files.has(file)) return file;
  const segments = file.split('/');
  const last = segments[segments.length - 1] ?? file;
  if (wantsHtml && !last.includes('.')) return listing.entry;
  for (let drop = 1; drop < Math.min(segments.length, MAX_STRIPPED_SEGMENTS + 1); drop++) {
    const tail = segments.slice(drop).join('/');
    if (listing.files.has(tail)) return tail;
  }
  return null;
}

/** SHA-256 of `bytes`, lowercase hex. */
export async function sha256Hex(bytes: ArrayBuffer | Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** How one loaded file compares with the listing. */
export type FileCheck =
  | { status: 'ok'; url: string; path: string }
  | { status: 'mismatch'; url: string; path: string; expected: string; got: string }
  | { status: 'unlisted'; url: string; file: string };

/** Compare `bytes`, served for `request`, with what the node verified. */
export async function checkFile(
  listing: Listing,
  request: AppRequest,
  url: string,
  bytes: ArrayBuffer | Uint8Array<ArrayBuffer>,
  wantsHtml: boolean,
): Promise<FileCheck> {
  const path = servedFile(listing, request.file, wantsHtml);
  if (path === null) return { status: 'unlisted', url, file: request.file };
  const expected = listing.files.get(path)!.sha256;
  const got = await sha256Hex(bytes);
  return got === expected ? { status: 'ok', url, path } : { status: 'mismatch', url, path, expected, got };
}
