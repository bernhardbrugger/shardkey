// Loads the REAL shipped code out of index.html (no copies, no mocks).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const INDEX_PATH = join(ROOT, 'index.html');
export const html = readFileSync(INDEX_PATH, 'utf8');

export function scriptById(id) {
  const m = new RegExp(`<script id="${id}">([\\s\\S]*?)</script>`).exec(html);
  if (!m) throw new Error(`no <script id="${id}"> in index.html`);
  return m[1];
}

// shk-core attaches itself to globalThis.SHK (same realm as the tests, so deepStrictEqual works).
new Function(scriptById('shk-core'))();
export const SHK = globalThis.SHK;

// The inlined QR generator, evaluated exactly as shipped.
export const qrcode = new Function(`${scriptById('vendor-qrcode-generator')}\nreturn qrcode;`)();

export const bytes = (...a) => Uint8Array.from(a);
export const rnd = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

/** All k-element subsets of arr. */
export function* combinations(arr, k, start = 0, cur = []) {
  if (cur.length === k) { yield cur.slice(); return; }
  for (let i = start; i < arr.length; i++) {
    cur.push(arr[i]);
    yield* combinations(arr, k, i + 1, cur);
    cur.pop();
  }
}

/** Rejects with a ShardkeyError carrying the expected code. */
export async function rejectsCode(assert, fn, code) {
  try { await fn(); } catch (e) {
    assert.equal(e.name, 'ShardkeyError', `expected ShardkeyError, got ${e && e.stack}`);
    assert.equal(e.code, code, `expected ${code}, got ${e.code} (${e.message})`);
    return e;
  }
  assert.fail(`expected ${code}, but nothing was thrown`);
}

/** Chi-square critical value (Wilson-Hilferty approximation); z = 4.75 is about alpha = 1e-6. */
export function chiCritical(df, z = 4.75) {
  const a = 2 / (9 * df);
  return df * Math.pow(1 - a + z * Math.sqrt(a), 3);
}
