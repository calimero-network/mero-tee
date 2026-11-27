import { describe, expect, it } from 'vitest';

import { newTab, verdict } from '../src/core/verdict.js';

describe('a tab verdict', () => {
  it('is verified only with an attested listing and every checked file matching', () => {
    const tab = newTab('https://x', '1.0.0');
    expect(verdict(tab)).toBe('checking');
    tab.attested = { node: 'https://n' };
    expect(verdict(tab)).toBe('checking');
    tab.checks.push({ status: 'ok', url: 'u', path: 'index.html' });
    expect(verdict(tab)).toBe('verified');
    tab.checks.push({ status: 'unlisted', url: 'u2', file: 'x.js' });
    expect(verdict(tab)).toBe('tampered');
  });

  it('is unverified when the page could not be checked, and tampered wins over it', () => {
    const tab = newTab('https://x', '1.0.0');
    tab.unverifiable = 'no node answered';
    expect(verdict(tab)).toBe('unverified');
    tab.checks.push({ status: 'mismatch', url: 'u', path: 'a.js', expected: 'a', got: 'b' });
    expect(verdict(tab)).toBe('tampered');
  });
});
