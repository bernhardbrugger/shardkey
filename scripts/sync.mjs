// Maintenance helper - NOT needed to use shardkey (index.html is the product).
//
//   node scripts/sync.mjs          refresh vendored libraries + CSP hashes in index.html
//   node scripts/sync.mjs --check  verify only (used by the test suite / CI)
//
// 1. Re-inlines the pinned QR libraries from node_modules into the
//    <script id="vendor-..."> blocks, byte for byte (plus a one-line banner).
// 2. Re-computes the SHA-256 hashes of every inline <script> and <style> block
//    and writes them into the Content-Security-Policy <meta> tag, so the page
//    runs with NO 'unsafe-inline' and NO 'unsafe-eval'.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export const INDEX = join(root, 'index.html');

const VENDOR = [
  { id: 'vendor-qrcode-generator', pkg: 'qrcode-generator', file: 'dist/qrcode.js',
    banner: (v) => `/*! qrcode-generator ${v} | MIT License | (c) 2009 Kazuhiko Arase | https://github.com/kazuhikoarase/qrcode-generator */` },
  { id: 'vendor-jsqr', pkg: 'jsqr', file: 'dist/jsQR.js',
    banner: (v) => `/*! jsQR ${v} | Apache License 2.0 | (c) Cosmo Wolfe | https://github.com/cozmo/jsQR */` },
];

const sha256b64 = (s) => createHash('sha256').update(s, 'utf8').digest('base64');

export function vendorBlock(v) {
  const dir = join(root, 'node_modules', v.pkg);
  const version = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version;
  const code = readFileSync(join(dir, v.file), 'utf8').replace(/\r\n/g, '\n').replace(/\s+$/, '');
  if (/<\/script/i.test(code)) throw new Error(`${v.pkg} contains "</script" - cannot inline`);
  return `\n${v.banner(version)}\n${code}\n`;
}

const BLOCK_RE = (id) => new RegExp(`(<script id="${id}">)([\\s\\S]*?)(</script>)`);

export function csp(html) {
  const hashes = (re) => [...html.matchAll(re)].map((m) => `'sha256-${sha256b64(m[1])}'`);
  const scripts = hashes(/<script\b[^>]*>([\s\S]*?)<\/script>/g);
  const styles = hashes(/<style\b[^>]*>([\s\S]*?)<\/style>/g);
  return [
    `default-src 'none'`,
    `script-src ${scripts.join(' ')}`,
    `style-src ${styles.join(' ')}`,
    `img-src 'self' data: blob:`,      // QR images are drawn locally (SVG/canvas/blob)
    `media-src blob:`,                 // camera preview
    `connect-src 'none'`,              // no fetch / XHR / WebSocket / beacon - ever
    `font-src 'none'`,
    `frame-src 'none'`,
    `worker-src 'none'`,
    `object-src 'none'`,
    `manifest-src 'none'`,
    `base-uri 'none'`,
    `form-action 'none'`,
  ].join('; ');
}

const CSP_RE = /(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(">)/;

/** Returns the html with vendored libs and CSP refreshed. */
export function seal(html) {
  for (const v of VENDOR) {
    if (!BLOCK_RE(v.id).test(html)) throw new Error(`index.html: missing <script id="${v.id}">`);
    html = html.replace(BLOCK_RE(v.id), (_, a, __, c) => a + vendorBlock(v) + c);
  }
  if (!CSP_RE.test(html)) throw new Error('index.html: missing CSP <meta> tag');
  return html.replace(CSP_RE, (_, a, __, c) => a + csp(html) + c);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const current = readFileSync(INDEX, 'utf8');
  const sealed = seal(current);
  if (process.argv.includes('--check')) {
    if (sealed !== current) { console.error('index.html is out of sync - run: npm run seal'); process.exit(1); }
    console.log('index.html: vendored libs and CSP hashes are up to date');
  } else {
    writeFileSync(INDEX, sealed);
    console.log(sealed === current ? 'index.html already up to date' : 'index.html updated');
  }
}
