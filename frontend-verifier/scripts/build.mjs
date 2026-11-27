// Builds dist/chrome and dist/firefox: the same code, each with its browser's manifest.
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
rmSync(join(root, 'dist'), { recursive: true, force: true });
for (const target of ['chrome', 'firefox']) {
  const out = join(root, 'dist', target);
  mkdirSync(out, { recursive: true });
  await build({
    entryPoints: {
      background: join(root, 'src/browser/entry.ts'),
      popup: join(root, 'src/browser/popup.ts'),
    },
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: target === 'chrome' ? 'chrome120' : 'firefox128',
    outdir: out,
    logLevel: 'warning',
    loader: { '.wasm': 'file' },
  });
  copyFileSync(join(root, `static/manifest.${target}.json`), join(out, 'manifest.json'));
  cpSync(join(root, 'static/popup.html'), join(out, 'popup.html'));
  cpSync(join(root, 'static/icon-128.png'), join(out, 'icon-128.png'));
}
console.log('built dist/chrome and dist/firefox');
