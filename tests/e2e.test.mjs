// End-to-end tests: drive the real index.html in Chromium (file:// URL, exactly how users run it offline).
// Independent QR decoding happens here in Node with the npm `jsqr` package (not the copy inlined in the page).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { PNG } from 'pngjs';
import jsQR from 'jsqr';
import { pathToFileURL } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { INDEX_PATH, ROOT, SHK, rnd } from './helpers.mjs';

const URL_ = pathToFileURL(INDEX_PATH).href;
const SHOTS = join(ROOT, 'docs', 'screenshots');
const tmp = mkdtempSync(join(tmpdir(), 'shardkey-e2e-'));
mkdirSync(SHOTS, { recursive: true });

const SECRET = 'correct horse battery staple – Grüße 🔐 日本語';
let browser;

before(async () => {
  const args = ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'];
  try { browser = await chromium.launch({ args }); }
  catch (e) { browser = await chromium.launch({ channel: 'chrome', args }); }   // fall back to an installed Chrome
});
after(async () => { await browser?.close(); });

async function open(opts = {}) {
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1000, height: 900 }, deviceScaleFactor: 2, acceptDownloads: true, ...opts });
  const page = await ctx.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`console.${m.type()}: ${m.text()}`); });
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) problems.push('network request: ' + r.url()); });
  await page.goto(URL_);
  return { ctx, page, problems };
}
const setRange = (page, id, v) => page.evaluate(([id, v]) => { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); }, [id, String(v)]);
const decodePng = (buf) => { const png = PNG.sync.read(buf); return jsQR(new Uint8ClampedArray(png.data), png.width, png.height)?.data ?? null; };
const cardTexts = (page) => page.$$eval('.share-card .sc-text', (n) => n.map((e) => e.textContent.replace(/\s+/g, '')));
const qrTexts = async (page) => {                       // screenshot every rendered QR code and read it with jsQR
  const out = [];
  for (const h of await page.$$('.share-card .sc-qr')) out.push(decodePng(await h.screenshot()));
  return out;
};
async function split(page, { text, label = '', n = 5, k = 3 }) {
  await page.fill('#secretText', text);
  await page.fill('#label', label);
  await setRange(page, 'nRange', n); await setRange(page, 'kRange', k);
  await page.click('#btnGenerate');
  await page.waitForSelector('.share-card');
}
const toRestore = (page) => page.click('#tab-recover');
const addText = async (page, text) => { await page.fill('#pasteBox', text); await page.click('#btnAddText'); };
const progress = (page) => page.textContent('#progText');

test('offline hardening: CSP blocks network, no requests are made', async () => {
  const { ctx, page, problems } = await open();
  const csp = await page.getAttribute('meta[http-equiv="Content-Security-Policy"]', 'content');
  assert.match(csp, /connect-src 'none'/);
  const verdict = await page.evaluate(async () => {
    const violations = [];
    document.addEventListener('securitypolicyviolation', (e) => violations.push(e.violatedDirective));
    let fetched = 'resolved';
    try { await fetch('https://example.com/'); } catch (e) { fetched = 'rejected'; }
    let ws = 'opened';
    try { new WebSocket('wss://example.com/'); } catch (e) { ws = 'blocked'; }
    await new Promise((r) => setTimeout(r, 100));
    return { fetched, ws, violations };
  });
  assert.equal(verdict.fetched, 'rejected');
  assert.ok(verdict.violations.some((v) => v.startsWith('connect-src')), JSON.stringify(verdict));
  // the page itself loaded without console errors and (above) without any network request
  assert.deepEqual(problems.filter((p) => !/Content Security Policy|example\.com|eval/i.test(p)), []);
  await ctx.close();
});

test('split in the UI -> render QR codes -> read with jsQR -> restore by pasting -> compare', async () => {
  const { ctx, page, problems } = await open();
  await split(page, { text: SECRET, label: 'Emergency password', n: 5, k: 3 });

  assert.equal(await page.locator('.share-card').count(), 5);
  assert.match(await page.textContent('.share-card[data-index="2"] .sc-count'), /Share 2 of 5 · 3 needed/);
  assert.equal(await page.textContent('.share-card .sc-label'), 'Emergency password');
  assert.match(await page.textContent('#outSummary'), /5 shares created, 3 needed/);
  await page.screenshot({ path: join(SHOTS, 'split.png'), fullPage: true });

  const texts = await cardTexts(page);
  const scanned = await qrTexts(page);
  assert.deepEqual(scanned, texts, 'every QR code decodes to exactly the share text printed below it');
  assert.ok(texts.every((t) => /^SHK1-[A-Z2-7]+$/.test(t)));

  await toRestore(page);
  assert.match(await progress(page), /No share collected yet/);
  await addText(page, scanned[4]);
  await addText(page, scanned[1]);
  assert.match(await progress(page), /2 of 3 shares collected/);
  assert.equal(await page.locator('#result').isVisible(), false, 'two shares must not reveal anything');
  await page.screenshot({ path: join(SHOTS, 'restore-partial.png'), fullPage: true });

  await addText(page, scanned[0].toLowerCase().replace(/(.{6})/g, '$1 '));      // sloppy typing is fine
  await page.waitForSelector('#result:not([hidden])');
  assert.match(await progress(page), /3 of 3 shares collected/);
  assert.equal(await page.textContent('#secretOut'), '••••••••••••', 'hidden by default');
  await page.click('#btnReveal');
  assert.equal(await page.textContent('#secretOut'), SECRET);
  await page.click('#btnReveal');
  assert.equal(await page.textContent('#secretOut'), '••••••••••••');
  await page.click('#btnReveal');
  await page.screenshot({ path: join(SHOTS, 'restore.png'), fullPage: true });
  assert.deepEqual(problems, []);
  await ctx.close();
});

test('restore messages: duplicate, wrong set, typo, garbage, remove share, k-1 shares', async () => {
  const { ctx, page } = await open();
  const a = await SHK.split({ data: SHK.utf8enc('set A'), kind: 'text', k: 3, n: 4 });
  const b = await SHK.split({ data: SHK.utf8enc('set B'), kind: 'text', k: 3, n: 4 });
  await toRestore(page);
  const last = () => page.textContent('#msgs li:last-child span');

  await addText(page, a.shares[0].text);
  await addText(page, a.shares[0].text);
  assert.match(await last(), /Share 1 was already collected/);
  assert.match(await progress(page), /1 of 3 shares collected/);

  await addText(page, b.shares[1].text);
  assert.match(await last(), /different set/);
  assert.match(await progress(page), /1 of 3/);

  const t = a.shares[1].text;
  await addText(page, t.slice(0, 20) + (t[20] === 'A' ? 'B' : 'A') + t.slice(21));
  assert.match(await last(), /Checksum mismatch/);
  await addText(page, 'hello world');
  assert.match(await last(), /not a shardkey share/);
  await addText(page, 'SHK1-AB0DE');
  assert.match(await last(), /Invalid character “0” at position 3/);

  await addText(page, a.shares[1].text);
  assert.match(await progress(page), /2 of 3/);
  assert.equal(await page.locator('#result').isVisible(), false);

  await addText(page, `${a.shares[2].text}\n${a.shares[3].text}`);            // several shares in one paste
  await page.waitForSelector('#result:not([hidden])');
  await page.click('#btnReveal');
  assert.equal(await page.textContent('#secretOut'), 'set A');

  assert.match(await progress(page), /4 of 3 shares collected/);
  await page.click('#shareList li:first-child button');                         // 4 -> 3 shares: still enough
  assert.match(await progress(page), /3 of 3 shares collected/);
  assert.equal(await page.locator('#result').isVisible(), true);
  await page.click('#shareList li:first-child button');                         // 3 -> 2 shares: the result goes away again
  await page.waitForSelector('#result', { state: 'hidden' });
  assert.match(await progress(page), /2 of 3/);
  await page.click('#btnResetRec');
  assert.match(await progress(page), /No share collected yet/);
  await ctx.close();
});

test('large file: AES-256-GCM, key shares + separate ciphertext file, binary-exact restore', async () => {
  const { ctx, page } = await open();
  const data = rnd(6000);
  await page.check('input[name=src][value=file]', { force: true });
  await page.setInputFiles('#secretFile', { name: 'Schlüssel ✓.bin', mimeType: 'application/octet-stream', buffer: Buffer.from(data) });
  await setRange(page, 'nRange', 4); await setRange(page, 'kRange', 2);
  await page.click('#btnGenerate');
  await page.waitForSelector('.share-card');
  assert.match(await page.textContent('#outSummary'), /AES-256-GCM/);
  assert.equal(await page.locator('#ctBox').isVisible(), true);

  const [ctDl] = await Promise.all([page.waitForEvent('download'), page.click('#btnCt')]);
  const ctPath = join(tmp, 'ct.shkc');
  await ctDl.saveAs(ctPath);
  assert.match(ctDl.suggestedFilename(), /^shardkey-[0-9A-F]{12}\.shkc$/);
  assert.ok(readFileSync(ctPath).length > 6000);

  const texts = await cardTexts(page);
  assert.ok(texts[0].length < 120);
  assert.deepEqual(await qrTexts(page), texts);

  await toRestore(page);
  await addText(page, texts[3]); await addText(page, texts[0]);
  assert.equal(await page.locator('#ctNeed').isVisible(), true);
  assert.equal(await page.locator('#result').isVisible(), false, 'needs the ciphertext file too');
  await page.setInputFiles('#ctFile', { name: 'garbage.shkc', mimeType: 'application/octet-stream', buffer: Buffer.from(rnd(300)) });
  assert.match(await page.textContent('#msgs li:last-child span'), /not a valid ciphertext file/);
  await page.setInputFiles('#ctFile', ctPath);
  await page.waitForSelector('#resFile:not([hidden])');
  assert.match(await page.textContent('#resFileInfo'), /Schlüssel ✓\.bin · 5\.9 KB/);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#btnFileDl')]);
  assert.equal(dl.suggestedFilename(), 'Schlüssel ✓.bin');
  const out = join(tmp, 'restored.bin');
  await dl.saveAs(out);
  assert.ok(Buffer.from(data).equals(readFileSync(out)), 'restored file is byte-identical');
  await ctx.close();
});

test('PNG export of a card contains a scannable QR code; image upload restores from PNGs', async () => {
  const { ctx, page } = await open();
  await split(page, { text: 'png roundtrip ✓', label: 'PNG test', n: 3, k: 2 });
  const files = [];
  for (const idx of [1, 3]) {
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click(`.share-card[data-index="${idx}"] [data-act="png"]`)]);
    assert.equal(dl.suggestedFilename(), `shardkey-png-test-share-${idx}-of-3.png`);
    const p = join(tmp, `card${idx}.png`);
    await dl.saveAs(p); files.push(p);
    assert.equal(decodePng(readFileSync(p)), (await cardTexts(page))[idx - 1], `PNG ${idx} decodes to its share`);
  }
  await toRestore(page);
  await page.setInputFiles('#imgFiles', files);                                 // BarcodeDetector if present, jsQR otherwise
  await page.waitForSelector('#result:not([hidden])');
  await page.click('#btnReveal');
  assert.equal(await page.textContent('#secretOut'), 'png roundtrip ✓');

  await page.click('#btnResetRec');                                              // an image without a QR code
  const blank = new PNG({ width: 200, height: 200 }); blank.data.fill(255);
  await page.setInputFiles('#imgFiles', { name: 'blank.png', mimeType: 'image/png', buffer: PNG.sync.write(blank) });
  await page.waitForSelector('#msgs li');
  assert.match(await page.textContent('#msgs li span'), /No QR code found in “blank\.png”/);
  await ctx.close();
});

test('camera scanning: a fake webcam shows the QR codes one after another', async () => {
  // 1) render three shares in the page, 2) build a Y4M "webcam" video that shows them in turn, 3) scan them back.
  const gen = await open();
  await split(gen.page, { text: 'seen by the camera', n: 4, k: 3 });
  const frames = [];
  for (const h of (await gen.page.$$('.share-card .sc-qr')).slice(0, 3)) frames.push(PNG.sync.read(await h.screenshot()));
  await gen.ctx.close();

  const W = 640, H = 480, FRAME = Buffer.alloc(W * H * 3 / 2, 128);
  const y4m = [Buffer.from(`YUV4MPEG2 W${W} H${H} F5:1 Ip A1:1 C420jpeg\n`)];
  for (const png of frames) {
    const f = Buffer.from(FRAME); f.fill(255, 0, W * H);                         // white luma plane, neutral chroma
    const size = 440, x0 = (W - size) / 2, y0 = (H - size) / 2;
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      const sx = Math.floor((x * png.width) / size), sy = Math.floor((y * png.height) / size), i = (sy * png.width + sx) * 4;
      f[(y0 + y) * W + x0 + x] = Math.round(0.299 * png.data[i] + 0.587 * png.data[i + 1] + 0.114 * png.data[i + 2]);
    }
    for (let r = 0; r < 12; r++) y4m.push(Buffer.from('FRAME\n'), f);             // ~2.4 s per code at 5 fps
  }
  const video = join(tmp, 'cam.y4m');
  writeFileSync(video, Buffer.concat(y4m));

  const camBrowser = await chromium.launch({ args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', `--use-file-for-fake-video-capture=${video}`] });
  try {
    const ctx = await camBrowser.newContext({ locale: 'en-US', viewport: { width: 1000, height: 900 }, permissions: ['camera'] });
    const page = await ctx.newPage();
    await page.goto(URL_);
    await toRestore(page);
    await page.click('#btnCam');
    await page.waitForSelector('#camBox:not([hidden])');
    await page.waitForSelector('#result:not([hidden])', { timeout: 45000 });
    assert.equal(await page.locator('#camBox').isVisible(), false, 'camera stops once the secret is restored');
    await page.click('#btnReveal');
    assert.equal(await page.textContent('#secretOut'), 'seen by the camera');
    assert.match(await progress(page), /3 of 3 shares collected/);
    await ctx.close();
  } finally { await camBrowser.close(); }
});

test('print view: one card per page (PDF) and print screenshot', async () => {
  const { ctx, page } = await open({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: 1 });
  await split(page, { text: 'print me', label: 'Notfall-Passwort', n: 4, k: 2 });
  await page.emulateMedia({ media: 'print' });
  const visible = await page.evaluate(() => ({
    form: document.querySelector('#split-form').offsetParent !== null,
    tabs: document.querySelector('.tabs').offsetParent !== null,
    cards: [...document.querySelectorAll('.share-card')].filter((c) => c.offsetParent !== null).length,
    buttons: document.querySelector('.sc-actions').offsetParent !== null,
  }));
  assert.deepEqual(visible, { form: false, tabs: false, cards: 4, buttons: false });
  const pdf = await page.pdf({ format: 'A4', printBackground: true });
  const pages = (pdf.toString('latin1').match(/\/Type\s*\/Page\b(?!s)/g) || []).length;
  assert.equal(pages, 4, 'exactly one page per share');
  writeFileSync(join(tmp, 'print.pdf'), pdf);
  const card = await page.$('.share-card:first-child');
  await card.screenshot({ path: join(SHOTS, 'print.png') });
  await ctx.close();
});

test('German UI, mobile layout and explainer screenshots', async () => {
  const { ctx, page, problems } = await open({ locale: 'de-AT', viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true });
  assert.equal(await page.textContent('#tab-split'), 'Aufteilen');
  assert.equal(await page.textContent('#tab-recover'), 'Wiederherstellen');
  await page.click('#langBtn');
  assert.equal(await page.textContent('#tab-split'), 'Split');
  await page.click('#langBtn');
  await split(page, { text: 'Mobile Ansicht', label: 'Notfall-Passwort', n: 5, k: 3 });
  assert.match(await page.textContent('.share-card[data-index="1"] .sc-count'), /Share 1 von 5 · 3 nötig/);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: join(SHOTS, 'mobile.png'), fullPage: true, clip: { x: 0, y: 0, width: 390, height: 1700 } });
  await page.locator('#explain > summary').click();
  await page.locator('#explain').scrollIntoViewIfNeeded();
  await ctx.close();

  const d = await open({ viewport: { width: 1000, height: 900 }, deviceScaleFactor: 2 });
  await d.page.locator('#explain > summary').click();
  await d.page.locator('#explain').screenshot({ path: join(SHOTS, 'explainer.png') });
  // dragging a point moves the secret; the k-1 view shows several fitting curves
  const before = await d.page.textContent('#polyRead');
  const dot = d.page.locator('#polysvg .pt').first();
  await dot.scrollIntoViewIfNeeded();
  const box = await dot.boundingBox();
  await d.page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await d.page.mouse.down(); await d.page.mouse.move(box.x + box.width / 2, box.y - 50, { steps: 5 }); await d.page.mouse.up();
  assert.notEqual(await d.page.textContent('#polyRead'), before);
  await d.page.check('#pless');
  assert.equal(await d.page.locator('#polysvg .curve').count(), 5);
  assert.match(await d.page.textContent('#polyRead'), /every possible secret/);
  assert.deepEqual(d.problems, []);
  await d.ctx.close();
  assert.deepEqual(problems, []);
});
