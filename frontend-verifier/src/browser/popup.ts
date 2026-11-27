/* eslint-disable @typescript-eslint/no-explicit-any */
declare const browser: any;
declare const chrome: any;
const api: any = typeof browser !== 'undefined' ? browser : chrome;

const WORDS: Record<string, string> = {
  verified: 'Every file of this page matches the release its attested node verified.',
  tampered: 'This page served a file that is not part of its release. Close it and do not sign in.',
  unverified: 'This page could not be checked.',
  checking: 'Checking this page…',
};

function row(dl: HTMLElement, term: string, value: string | undefined) {
  if (!value) return;
  const dt = document.createElement('dt');
  dt.textContent = term;
  const dd = document.createElement('dd');
  dd.textContent = value;
  dl.append(dt, dd);
}

async function main() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const state: any = await api.runtime.sendMessage({ tabId: tab?.id });
  const strict = document.getElementById('strict') as HTMLInputElement;
  const stored = await api.storage.local.get('strict');
  strict.checked = stored?.strict === true;
  strict.addEventListener('change', () => void api.storage.local.set({ strict: strict.checked }));
  if (!state) return;
  const verdict = document.getElementById('verdict')!;
  verdict.textContent = WORDS[state.verdict] ?? state.verdict;
  verdict.className = `verdict ${state.verdict}`;
  const facts = document.getElementById('facts')!;
  facts.hidden = false;
  row(facts, 'Origin', state.origin);
  row(facts, 'Package', state.package);
  row(facts, 'Release', state.version);
  row(facts, 'Node', state.attested?.node);
  row(facts, 'Node image', state.attested?.release && `mero-tee ${state.attested.release} (${state.attested.profile ?? 'profile unknown'})`);
  row(facts, 'Files checked', String(state.checks.length));
  row(facts, 'Why unchecked', state.unverifiable);
  const bad = state.checks.filter((c: any) => c.status !== 'ok');
  if (bad.length) {
    const box = document.getElementById('problems')!;
    box.hidden = false;
    const ul = document.createElement('ul');
    for (const c of bad) {
      const li = document.createElement('li');
      li.textContent = c.status === 'mismatch' ? `${c.path}: does not match` : `${c.file}: not in the release`;
      ul.append(li);
    }
    box.append(ul);
  }
  document.getElementById('mode')!.textContent = state.enforcing
    ? 'This browser lets the extension stop a changed file before the page runs it.'
    : 'This browser does not let extensions stop a file: a changed file is detected after the page loaded it.';
}

void main();
