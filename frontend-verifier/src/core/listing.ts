/**
 * The file list a release's frontend must match, from a node the extension attested itself.
 *
 * `/.well-known/calimero.json` on the app's origin only names the package and the cluster's
 * API nodes; it arrives over the same TLS as the page, so it is trusted with nothing. Each
 * node is attested by mero-js (the TDX quote, Intel's collateral, the Sigstore-signed
 * mero-tee release and the transport key bound into the quote) before the listing is asked
 * for over the sealed channel. A server that swapped the page cannot also answer that
 * request: it would need the key attested inside the TEE.
 */

import { CLOUD_ENVIRONMENTS, NodeTransport, type NodePolicy } from '@calimero-network/mero-js';

import type { AppRequest, Listing } from './site.js';

/**
 * The oldest mero-tee release the extension trusts, as mero-react's `minReleaseVersion`: every
 * release ever signed stays validly signed, so a floor keeps out ones with a fixed flaw.
 */
export const MIN_RELEASE_VERSION = '2.3.109';

/** Why a page could not be checked; the badge shows it as unverified, never as verified. */
export class Unverifiable extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

/** The node that answered, and what its attestation established. */
export interface Attested {
  node: string;
  release?: string;
  profile?: string;
}

/** What the extension sends a node over the sealed channel. */
export type SealedGet = (path: string) => Promise<unknown>;

/** How to reach a cluster's nodes: attested and sealed, from its API URLs. Replaced in tests. */
export type Connect = (api: string[], policy: NodePolicy) => { get: SealedGet; attested: () => Attested };

/** The real thing: mero-js's `NodeTransport`, which attests each node before its first request. */
export const connect: Connect = (api, policy) => {
  const [baseUrl, ...nodes] = api;
  if (!baseUrl) throw new Unverifiable('the page names no node to ask');
  const transport = new NodeTransport({ baseUrl, nodes, policy });
  return {
    get: (path) => transport.json('GET', path),
    attested: () => {
      const v = transport.verification();
      return {
        node: transport.nodeUrl,
        ...(v && v.status === 'verified' ? { release: v.release, profile: v.profile } : {}),
      };
    },
  };
};

/** The policy a node of `request`'s Calimero Cloud must attest to. */
export function policyFor(request: AppRequest): NodePolicy {
  const env = CLOUD_ENVIRONMENTS[request.environment];
  return {
    release: {
      minReleaseVersion: MIN_RELEASE_VERSION,
      releaseSource: env.cloudUrl,
      ...env.trust,
    },
  };
}

interface WellKnown {
  package?: unknown;
  api?: unknown;
}

interface Digests {
  package?: unknown;
  version?: unknown;
  entry?: unknown;
  files?: unknown;
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Read the node's answer; anything malformed is unverifiable rather than trusted in part. */
export function parseListing(answer: unknown, request: AppRequest, pkg: string): Listing {
  const d = (answer ?? {}) as Digests;
  if (d.package !== pkg || d.version !== request.version || typeof d.entry !== 'string' || !Array.isArray(d.files)) {
    throw new Unverifiable('the node answered for another release');
  }
  const files = new Map<string, { sha256: string; size: number }>();
  for (const f of d.files as Array<Record<string, unknown>>) {
    if (typeof f.path !== 'string' || typeof f.sha256 !== 'string' || !HEX64.test(f.sha256) || typeof f.size !== 'number') {
      throw new Unverifiable('the node answered a malformed file list');
    }
    files.set(f.path, { sha256: f.sha256, size: f.size });
  }
  if (!files.has(d.entry)) throw new Unverifiable('the node named an entry it does not list');
  return { package: pkg, version: request.version, entry: d.entry, files };
}

/**
 * The listing for `request`'s release, from an attested node of the cluster the page names.
 * `fetchPlain` reads the well-known file (untrusted); `connectTo` attests and seals.
 */
export async function fetchListing(
  request: AppRequest,
  fetchPlain: typeof fetch = (input, init) => fetch(input, init),
  connectTo: Connect = connect,
): Promise<{ listing: Listing; attested: Attested }> {
  let known: WellKnown;
  try {
    const res = await fetchPlain(`${request.origin}/.well-known/calimero.json`, { credentials: 'omit', cache: 'no-store' });
    if (!res.ok) throw new Error(`${res.status}`);
    known = (await res.json()) as WellKnown;
  } catch (e) {
    throw new Unverifiable(`the page's cluster could not be found (${String(e)})`);
  }
  if (typeof known.package !== 'string' || !Array.isArray(known.api) || known.api.some((a) => typeof a !== 'string')) {
    throw new Unverifiable("the page's /.well-known/calimero.json is malformed");
  }
  const pkg = known.package;
  const node = connectTo(known.api as string[], policyFor(request));
  let answer: unknown;
  try {
    answer = await node.get(
      `packages/${encodeURIComponent(pkg)}/${encodeURIComponent(request.version)}/frontend`,
    );
  } catch (e) {
    const message = String((e as Error)?.message ?? e);
    if (/\b404\b/.test(message)) {
      throw new Unverifiable('the node does not list this release (or runs a release before 1.0.0-rc.39)');
    }
    throw new Unverifiable(`no node of the cluster passed attestation or answered (${message})`);
  }
  return { listing: parseListing(answer, request, pkg), attested: node.attested() };
}
