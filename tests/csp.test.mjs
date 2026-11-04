import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { html, ROOT } from './helpers.mjs';
import { seal, vendorBlock } from '../scripts/sync.mjs';

const cspOf = (h) => /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(h)[1];

test('index.html is sealed: vendored libraries are byte-identical to the pinned npm packages and CSP hashes match', () => {
  assert.equal(seal(html), html, 'run `npm run seal`');
});

test('CSP forbids all network access and has no unsafe-inline / unsafe-eval', () => {
  const csp = cspOf(html);
  for (const d of ["default-src 'none'", "connect-src 'none'", "font-src 'none'", "frame-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "worker-src 'none'"])
    assert.ok(csp.includes(d), `missing ${d}`);
  assert.ok(!/unsafe-/.test(csp));
  assert.ok(!/https?:/.test(csp));
  assert.ok(!/script-src[^;]*(\*|data:|blob:|https?:)/.test(csp));
});

test('no external references anywhere in the page (no CDNs, fonts, analytics, trackers)', () => {
  // strip the vendored libraries (they contain URLs in comments) before scanning our own code
  const own = html.replace(/<script id="vendor-[^"]*">[\s\S]*?<\/script>/g, '');
  assert.ok(!/(src|href|action|poster)\s*=\s*["']?\s*(https?:)?\/\//i.test(own), 'external src/href');
  assert.ok(!/@import|url\(\s*["']?https?:/i.test(own), 'css import / external url()');
  assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\b/.test(own.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '')), 'network API used');
  assert.ok(!/<link\b/i.test(own), '<link> tag');
  assert.ok(!/gtag|analytics|googletagmanager|plausible/i.test(own));
});

test('single self-contained file: no other app files are needed', () => {
  assert.ok(html.length > 200_000);   // includes both vendored libraries
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.dependencies, undefined, 'package.json is for tests only');
});

test('vendorBlock output has the license banner', () => {
  assert.match(vendorBlock({ pkg: 'qrcode-generator', file: 'dist/qrcode.js', banner: (v) => `/*! ${v} */` }), /^\n\/\*! 2\.0\.4 \*\//);
});
