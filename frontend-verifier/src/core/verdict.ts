/**
 * What the extension knows about one tab's app page, and the verdict it shows.
 */

import type { Attested } from './listing.js';
import type { FileCheck } from './site.js';

export type Verdict = 'checking' | 'verified' | 'tampered' | 'unverified';

/** One tab on a Calimero app's page. */
export interface TabState {
  origin: string;
  package?: string;
  version: string;
  attested?: Attested;
  /** Why the page could not be checked, when it could not. */
  unverifiable?: string;
  checks: FileCheck[];
  /** Firefox only: files the extension stopped before the page received them. */
  blocked: string[];
}

export function newTab(origin: string, version: string): TabState {
  return { origin, version, checks: [], blocked: [] };
}

/**
 * The tab's verdict. Any mismatched or unlisted file makes it `tampered`, whatever else
 * passed: one swapped script is enough to read everything the page shows. `verified` needs
 * an attested listing and at least one checked file, all of them matching.
 */
export function verdict(tab: TabState): Verdict {
  if (tab.checks.some((c) => c.status !== 'ok')) return 'tampered';
  if (tab.unverifiable) return 'unverified';
  if (!tab.attested || tab.checks.length === 0) return 'checking';
  return 'verified';
}

/** The toolbar badge for a verdict: text and background color. */
export function badge(v: Verdict): { text: string; color: string; title: string } {
  switch (v) {
    case 'verified':
      return { text: 'OK', color: '#0f7a6c', title: 'Every file matches what the attested node verified' };
    case 'tampered':
      return { text: '!', color: '#b3261e', title: 'A file does not match the release: do not use this page' };
    case 'unverified':
      return { text: '?', color: '#9a5b00', title: 'This page could not be checked' };
    default:
      return { text: '…', color: '#56636f', title: 'Checking this page' };
  }
}
