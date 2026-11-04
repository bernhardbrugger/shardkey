import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SHK, qrcode, scriptById, bytes, rnd, combinations, rejectsCode, chiCritical } from './helpers.mjs';

const { gf } = SHK;
const text = (s) => SHK.utf8enc(s);
const split = (s, k, n, extra = {}) => SHK.split({ data: text(s), kind: 'text', k, n, ...extra });
const parse = (r) => r.shares.map((s) => SHK.parseShare(s.text));
const pick = (arr, idx) => idx.map((i) => arr[i]);

/* ------------------------------------------------------------------ GF(256) */
describe('GF(256) arithmetic', () => {
  // Independent reference: carry-less "Russian peasant" multiplication modulo 0x11B.
  const slowMul = (a, b) => {
    let p = 0;
    while (b) { if (b & 1) p ^= a; a <<= 1; if (a & 0x100) a ^= 0x11b; b >>= 1; }
    return p;
  };

  test('exp/log tables: generator 3 walks through all 255 non-zero elements', () => {
    assert.equal(gf.EXP[0], 1);
    assert.equal(new Set(Array.from(gf.EXP.subarray(0, 255))).size, 255);
    assert.ok(!gf.EXP.subarray(0, 255).includes(0));
    for (let i = 0; i < 255; i++) {
      assert.equal(gf.LOG[gf.EXP[i]], i);
      assert.equal(gf.EXP[i + 255], gf.EXP[i]);
    }
    for (let a = 1; a < 256; a++) assert.equal(gf.EXP[gf.LOG[a]], a);
  });

  test('table multiplication equals the bitwise reference for all 65536 pairs', () => {
    for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) assert.equal(gf.mul(a, b), slowMul(a, b), `${a}*${b}`);
  });

  test('known AES vectors (FIPS-197): 0x57*0x83 = 0xC1, inv(0x53) = 0xCA', () => {
    assert.equal(gf.mul(0x57, 0x83), 0xc1);
    assert.equal(gf.inv(0x53), 0xca);
  });

  test('every non-zero element has an inverse; 0 has none', () => {
    for (let a = 1; a < 256; a++) {
      assert.equal(gf.mul(a, gf.inv(a)), 1, `a=${a}`);
      assert.equal(gf.inv(gf.inv(a)), a);
      assert.equal(gf.div(a, a), 1);
    }
    assert.throws(() => gf.inv(0));
  });

  test('0 annihilates, 1 is the identity, multiplication is commutative', () => {
    for (let a = 0; a < 256; a++) {
      assert.equal(gf.mul(a, 0), 0);
      assert.equal(gf.mul(0, a), 0);
      assert.equal(gf.mul(a, 1), a);
      for (let b = 0; b < 256; b++) assert.equal(gf.mul(a, b), gf.mul(b, a));
    }
  });

  test('associativity and distributivity hold exhaustively (256^3 triples)', () => {
    for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) {
      const ab = gf.mul(a, b);
      for (let c = 0; c < 256; c++) {
        if (gf.mul(ab, c) !== gf.mul(a, gf.mul(b, c))) assert.fail(`assoc ${a} ${b} ${c}`);
        if (gf.mul(a, b ^ c) !== (ab ^ gf.mul(a, c))) assert.fail(`distrib ${a} ${b} ${c}`);
      }
    }
  });
});

describe('encoding helpers', () => {
  test('CRC-32 check value and Base32 (RFC 4648) vectors', () => {
    assert.equal(SHK.crc32(text('123456789')), 0xcbf43926);
    assert.equal(SHK.b32enc(text('foobar')), 'MZXW6YTBOI');
    assert.equal(SHK.b32enc(text('f')), 'MY');
    assert.equal(SHK.b32enc(text('')), '');
    for (let len = 0; len < 40; len++) {
      const b = rnd(len);
      assert.deepEqual(SHK.b32dec(SHK.b32enc(b)), b);
    }
  });

  test('the core never uses Math.random (crypto.getRandomValues is the only randomness)', () => {
    assert.ok(!/Math\.random/.test(scriptById('shk-core')));
    assert.ok(/getRandomValues/.test(scriptById('shk-core')));
  });
});

/* ------------------------------------------------------------------- Shamir */
describe('Shamir over GF(256)', () => {
  const cases = [[2, 2], [2, 3], [3, 3], [3, 5], [4, 7], [5, 5], [6, 9], [7, 10], [8, 16], [2, 16], [3, 16], [16, 16]];

  for (const [k, n] of cases) {
    test(`(k=${k}, n=${n}): every k-subset recovers the secret, every (k-1)-subset does not`, () => {
      const secret = rnd(32);
      const shares = SHK.shamirSplit(secret, k, n);
      assert.equal(shares.length, n);
      for (const s of shares) assert.equal(s.length, 32);
      const pts = shares.map((y, i) => ({ x: i + 1, y }));
      let ok = 0, bad = 0;
      for (const sub of combinations(pts, k)) {
        assert.deepEqual(SHK.shamirCombine(sub), secret);
        ok++;
      }
      for (const sub of combinations(pts, k - 1)) {
        assert.notDeepEqual(SHK.shamirCombine(sub), secret);      // 2^-256 chance of a false failure
        bad++;
      }
      assert.ok(ok > 0 && bad > 0);
    });
  }

  test('more than k shares still reconstruct (over-determined but consistent)', () => {
    const secret = rnd(20);
    const pts = SHK.shamirSplit(secret, 4, 9).map((y, i) => ({ x: i + 1, y }));
    for (const size of [5, 6, 9]) assert.deepEqual(SHK.shamirCombine(pts.slice(0, size)), secret);
  });

  test('empty and single-byte secrets work; parameter validation', () => {
    assert.deepEqual(SHK.shamirCombine(SHK.shamirSplit(new Uint8Array(0), 2, 3).slice(0, 2).map((y, i) => ({ x: i + 1, y }))), new Uint8Array(0));
    for (const [k, n] of [[1, 3], [3, 2], [2, 17], [0, 0], [2.5, 4], [NaN, 3]]) assert.throws(() => SHK.shamirSplit(bytes(1), k, n), { code: 'BAD_PARAMS' });
    assert.throws(() => SHK.shamirCombine([{ x: 1, y: bytes(1) }, { x: 1, y: bytes(2) }]), { code: 'INTERNAL' });   // duplicate x
    assert.throws(() => SHK.shamirCombine([{ x: 0, y: bytes(1) }, { x: 1, y: bytes(2) }]), { code: 'INTERNAL' });   // x = 0 is the secret itself
  });

  test('two splits of the same secret share nothing', () => {
    const secret = rnd(32);
    const a = SHK.shamirSplit(secret, 3, 5), b = SHK.shamirSplit(secret, 3, 5);
    for (let i = 0; i < 5; i++) assert.notDeepEqual(a[i], b[i]);
  });
});

describe('statistical independence from the secret (chi-square)', () => {
  // With k = 3, ANY two shares (x = 1, 2) are jointly uniform over all 65536 byte pairs, whatever the secret.
  // We sample 2^20 pairs for fixed secrets and test (a) uniformity, (b) that two different secrets are indistinguishable.
  const jointCounts = (secretByte, k, n, calls = 8, len = 1 << 17) => {
    const counts = new Uint32Array(65536);
    const secret = new Uint8Array(len).fill(secretByte);
    for (let c = 0; c < calls; c++) {
      const sh = SHK.shamirSplit(secret, k, n);
      for (let i = 0; i < len; i++) counts[(sh[0][i] << 8) | sh[1][i]]++;
    }
    return counts;
  };
  const chiUniform = (counts, N) => {
    const e = N / counts.length;
    let chi = 0;
    for (const c of counts) chi += (c - e) * (c - e) / e;
    return chi;
  };
  const chiTwoSample = (a, b) => {
    let chi = 0, df = -1;
    for (let i = 0; i < a.length; i++) if (a[i] + b[i]) { chi += (a[i] - b[i]) ** 2 / (a[i] + b[i]); df++; }
    return { chi, df };
  };
  const N = 8 * (1 << 17);

  test('k=3: two shares are uniform for secrets 0x00, 0x5A, 0xFF and indistinguishable from each other', () => {
    const crit = chiCritical(65535);
    const sets = [0x00, 0x5a, 0xff].map((s) => jointCounts(s, 3, 5));
    sets.forEach((c, i) => {
      const chi = chiUniform(c, N);
      assert.ok(chi < crit, `secret #${i}: chi2=${chi.toFixed(0)} >= ${crit.toFixed(0)}`);
    });
    for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
      const { chi, df } = chiTwoSample(sets[a], sets[b]);
      assert.ok(chi < chiCritical(df), `secrets ${a}/${b}: chi2=${chi.toFixed(0)} df=${df}`);
    }
  });

  test('k=2: a single share is uniform for secrets 0x00 and 0xFF', () => {
    const counts = [0x00, 0xff].map((s) => {
      const c = new Uint32Array(256), secret = new Uint8Array(1 << 18).fill(s);
      const sh = SHK.shamirSplit(secret, 2, 3);
      for (const v of sh[0]) c[v]++;
      return c;
    });
    for (const c of counts) assert.ok(chiUniform(c, 1 << 18) < chiCritical(255));
    const { chi, df } = chiTwoSample(counts[0], counts[1]);
    assert.ok(chi < chiCritical(df));
  });

  test('control: the statistic does have power (a leaky "share" is detected)', () => {
    const leaky = new Uint32Array(256);
    leaky[0x5a] = 1 << 18;                               // e.g. a scheme that outputs the secret itself
    assert.ok(chiUniform(leaky, 1 << 18) > chiCritical(255));
    const biased = new Uint32Array(256).fill(1000);
    biased[7] += 600; biased[8] -= 600;                  // a modest bias (+-60%) is flagged at this sample size
    assert.ok(chiUniform(biased, 256000) > chiCritical(255));
  });
});

/* ------------------------------------------------------------ share format */
describe('share format: round trips', () => {
  const samples = {
    ascii: 'correct horse battery staple',
    umlauts: 'Grüße aus Wien — Straße, Äpfel & Öl, Ünicode ✓',
    emoji: '🔐 family 👩‍👩‍👧‍👦 flag 🇦🇹 keycap 1️⃣ skin 👍🏽',
    combining: 'e\u0301 a\u0308 n\u0303 — Zalgo: Z̷̢a̶l̸g̵o̷',
    mixedScripts: 'مرحبا بالعالم · 日本語のパスワード · Пароль · 🧿',
    whitespace: '  leading\n\ttabs\r\nand trailing   \n',
    nul: 'a\u0000b',
  };
  for (const [name, s] of Object.entries(samples)) {
    test(`text "${name}" (3 of 5, any 3 shares)`, async () => {
      const r = await split(s, 3, 5);
      assert.equal(r.mode, 'direct');
      const parsed = parse(r);
      for (const sub of combinations(parsed, 3)) {
        const out = await SHK.recover(sub);
        assert.equal(out.kind, 'text');
        assert.equal(SHK.utf8dec(out.data), s);
      }
    });
  }

  test('empty secret round-trips', async () => {
    const r = await split('', 2, 3);
    assert.equal(r.mode, 'direct');
    const out = await SHK.recover(parse(r).slice(1));
    assert.equal(out.kind, 'text');
    assert.equal(out.data.length, 0);
  });

  test('binary file (all 256 byte values) with unicode name round-trips directly', async () => {
    const data = Uint8Array.from({ length: 256 }, (_, i) => i);
    const r = await SHK.split({ data, kind: 'file', name: 'Schlüssel 🔑.bin', k: 3, n: 4 });
    assert.equal(r.mode, 'direct');
    const out = await SHK.recover(parse(r).slice(1));
    assert.equal(out.kind, 'file');
    assert.equal(out.name, 'Schlüssel 🔑.bin');
    assert.deepEqual(out.data, data);
  });

  test('over-long file names are clamped to 255 UTF-8 bytes on a character boundary', async () => {
    const r = await SHK.split({ data: bytes(1, 2, 3), kind: 'file', name: '🔑'.repeat(100) + '.bin', k: 2, n: 2 });
    const out = await SHK.recover(parse(r));
    assert.ok(SHK.utf8enc(out.name).length <= 255);
    assert.ok(out.name.startsWith('🔑'));
    assert.ok(!out.name.includes('\ufffd'));
  });

  test('every share of a set has the same length, only [A-Z2-7-] characters, and fits a QR code', async () => {
    const r = await split('hunter2'.repeat(10), 4, 9);
    assert.equal(r.shares.length, 9);
    assert.equal(new Set(r.shares.map((s) => s.text.length)).size, 1);
    assert.equal(new Set(r.shares.map((s) => s.index)).size, 9);
    for (const s of r.shares) {
      assert.match(s.text, /^SHK1-[A-Z2-7]+$/);
      const q = qrcode(0, 'M'); q.addData(s.text, 'Alphanumeric'); q.make();
    }
    const p = parse(r);
    assert.equal(new Set(p.map((s) => s.setIdHex)).size, 1);
    assert.deepEqual(p.map((s) => s.x), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert.ok(p.every((s) => s.k === 4 && s.n === 9));
  });

  test('two splits get different set ids and different shares', async () => {
    const a = await split('same', 2, 3), b = await split('same', 2, 3);
    assert.notEqual(a.setId, b.setId);
    assert.notEqual(a.shares[0].text, b.shares[0].text);
  });
});

describe('direct vs. AES mode and the QR size limit', () => {
  test('the largest direct share still fits a QR code at error-correction level M', async () => {
    let L = 300, last;
    for (; ; L++) {                                     // find the direct/AES switch-over point
      const r = await SHK.split({ data: rnd(L), kind: 'file', name: '', k: 2, n: 2 });
      if (r.mode !== 'direct') break;
      last = r;
      assert.ok(r.shares[0].text.length <= SHK.MAX_QR_CHARS);
    }
    assert.ok(L > 380 && L < 450, `switch-over at ${L} bytes`);
    const q = qrcode(0, 'M'); q.addData(last.shares[0].text, 'Alphanumeric'); q.make();
    assert.ok(q.getModuleCount() <= 21 + 4 * (18 - 1), `QR is ${q.getModuleCount()} modules wide`);
  });

  test('large secret: AES-256-GCM, only the key is shared, ciphertext goes to a separate file', async () => {
    const data = rnd(5000);
    const r = await SHK.split({ data, kind: 'file', name: 'big.bin', k: 3, n: 5 });
    assert.equal(r.mode, 'aes');
    assert.equal(r.embedded, false);
    assert.ok(r.ciphertextFile instanceof Uint8Array && r.ciphertextFile.length > 5000);
    const p = parse(r);
    assert.ok(p.every((s) => s.aes && !s.embedded && s.data.length === 40 && s.ct === null));
    assert.ok(r.shares[0].text.length < 120, 'key shares stay tiny');
    for (const sub of [[0, 1, 2], [4, 2, 0], [1, 3, 4]]) {
      const out = await SHK.recover(pick(p, sub), r.ciphertextFile);
      assert.equal(out.name, 'big.bin');
      assert.deepEqual(out.data, data);
    }
  });

  test('forced AES mode embeds the ciphertext into every share when it fits', async () => {
    const r = await split('small but encrypted', 2, 3, { mode: 'aes' });
    assert.equal(r.mode, 'aes');
    assert.equal(r.embedded, true);
    assert.equal(r.ciphertextFile, null);
    const p = parse(r);
    assert.ok(p.every((s) => s.ct && s.ct.length === 12 + (1 + 19) + 16));
    assert.equal(SHK.utf8dec((await SHK.recover(pick(p, [2, 0]))).data), 'small but encrypted');
  });

  test('size limit is enforced', async () => {
    await rejectsCode(assert, () => SHK.split({ data: new Uint8Array(SHK.MAX_DATA_BYTES + 1), kind: 'file', k: 2, n: 2 }), 'TOO_LARGE');
    await rejectsCode(assert, () => split('x', 1, 3), 'BAD_PARAMS');
    await rejectsCode(assert, () => split('x', 5, 4), 'BAD_PARAMS');
    await rejectsCode(assert, () => split('x', 2, 17), 'BAD_PARAMS');
  });
});

describe('share format: error handling', () => {
  test('too few shares: k-1 never recover and say how many are missing', async () => {
    for (const [k, n] of [[2, 3], [3, 5], [5, 8]]) {
      const p = parse(await split('top secret', k, n));
      const e = await rejectsCode(assert, () => SHK.recover(p.slice(0, k - 1)), 'TOO_FEW');
      assert.deepEqual(e.params, { have: k - 1, need: k });
    }
    await rejectsCode(assert, () => SHK.recover([]), 'TOO_FEW');
  });

  test('lying about k does not help: k-1 shares with a doctored header fail verification', async () => {
    const direct = parse(await split('top secret', 3, 5));
    const doctored = direct.slice(0, 2).map((s) => SHK.parseShare(SHK.encodeShare({ ...s, k: 2 })));
    await rejectsCode(assert, () => SHK.recover(doctored), 'VERIFY_FAILED');

    const r = await SHK.split({ data: rnd(3000), kind: 'file', name: 'x', k: 3, n: 5 });
    const aes = parse(r).slice(0, 2).map((s) => SHK.parseShare(SHK.encodeShare({ ...s, k: 2 })));
    await rejectsCode(assert, () => SHK.recover(aes, r.ciphertextFile), 'DECRYPT_FAILED');
  });

  test('every single-character substitution in a share is rejected', async () => {
    const t = (await split('pw', 2, 3)).shares[0].text;
    const body = t.slice(5);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let tested = 0;
    for (let i = 0; i < body.length; i++) for (const c of alphabet) {
      if (c === body[i]) continue;
      const bad = 'SHK1-' + body.slice(0, i) + c + body.slice(i + 1);
      assert.throws(() => SHK.parseShare(bad), (e) => ['BAD_CHECKSUM', 'TRUNCATED'].includes(e.code), `pos ${i} -> ${c}`);
      tested++;
    }
    assert.ok(tested > 1000);
  });

  test('swapped neighbours, truncation, extra characters and dropped characters are rejected', async () => {
    const t = (await split('a password of some length', 3, 4)).shares[1].text;
    SHK.parseShare(t);
    const body = t.slice(5);
    for (let i = 0; i < body.length - 1; i++) {
      if (body[i] === body[i + 1]) continue;
      const sw = body.slice(0, i) + body[i + 1] + body[i] + body.slice(i + 2);
      assert.throws(() => SHK.parseShare('SHK1-' + sw), { name: 'ShardkeyError' }, `swap at ${i}`);
    }
    for (let cut = 1; cut < 12; cut++) assert.throws(() => SHK.parseShare(t.slice(0, -cut)), { name: 'ShardkeyError' });
    for (const extra of ['A', 'AB', 'ABCD', 'AAAAAAAA']) assert.throws(() => SHK.parseShare(t + extra), { name: 'ShardkeyError' });
    for (let i = 0; i < body.length; i++) assert.throws(() => SHK.parseShare('SHK1-' + body.slice(0, i) + body.slice(i + 1)), { name: 'ShardkeyError' });
  });

  test('specific messages: prefix, version, characters, checksum', async () => {
    const t = (await split('x', 2, 2)).shares[0].text;
    for (const junk of ['', 'hello world', 'ABCDEF', 'SHK-AAAA', 'http://example.com']) await rejectsCode(assert, () => SHK.parseShare(junk), 'BAD_PREFIX');
    await rejectsCode(assert, () => SHK.parseShare('SHK2-' + t.slice(5)), 'UNSUPPORTED_VERSION');
    const e = await rejectsCode(assert, () => SHK.parseShare('SHK1-AB0DEFGH'), 'BAD_ENCODING');
    assert.deepEqual(e.params, { char: '0', pos: 3 });
    await rejectsCode(assert, () => SHK.parseShare('SHK1-A'), 'TRUNCATED');
    await rejectsCode(assert, () => SHK.parseShare('SHK1-' + 'A'.repeat(40)), 'BAD_CHECKSUM');
  });

  test('forged but checksum-valid headers are rejected', async () => {
    const s = SHK.parseShare((await split('x', 3, 4)).shares[0].text);
    const good = { aes: false, embedded: false, setId: s.setId, k: 3, n: 4, x: 1, data: s.data };
    SHK.parseShare(SHK.encodeShare(good));
    const forge = (patch) => {
      const raw = SHK.b32dec(SHK.encodeShare({ ...good, ...patch.fields }).slice(5));
      const body = raw.slice(0, -4);
      patch.edit?.(body);
      const out = new Uint8Array(body.length + 4); out.set(body);
      new DataView(out.buffer).setUint32(body.length, SHK.crc32(body));
      return 'SHK1-' + SHK.b32enc(out);
    };
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[0] = 0x80; } })), 'BAD_HEADER');       // reserved flag bits
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[0] = 0x02; } })), 'BAD_HEADER');       // embedded without aes
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[8] = 0; } })), 'BAD_HEADER');          // x = 0 would be the secret
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[8] = 5; } })), 'BAD_HEADER');          // x > n
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[7] = (0 << 4) | 3; } })), 'BAD_HEADER'); // k = 1
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: {}, edit: (b) => { b[7] = (3 << 4) | 1; } })), 'BAD_HEADER'); // k > n
    await rejectsCode(assert, () => SHK.parseShare(forge({ fields: { aes: true, data: rnd(41) }, edit: () => {} })), 'BAD_HEADER');   // aes with wrong key length
  });

  test('mixed sets are detected, with both set ids reported', async () => {
    const a = parse(await split('one', 2, 3)), b = parse(await split('two', 2, 3));
    const e = await rejectsCode(assert, () => SHK.recover([a[0], b[1]]), 'MIXED_SETS');
    assert.deepEqual(new Set([e.params.a, e.params.b]), new Set([a[0].setIdHex, b[1].setIdHex]));
    const list = [a[0]];
    await rejectsCode(assert, () => SHK.addShare(list, b[0]), 'MIXED_SETS');
    assert.equal(list.length, 1);
  });

  test('same set id but different parameters is inconsistent', async () => {
    const a = parse(await split('one', 3, 5));
    const odd = SHK.parseShare(SHK.encodeShare({ ...a[1], k: 2, n: 5 }));
    await rejectsCode(assert, () => SHK.recover([a[0], odd]), 'INCONSISTENT');
  });

  test('duplicate indices: identical repeats are flagged, conflicting ones are errors', async () => {
    const p = parse(await split('dup', 2, 3));
    const list = [];
    assert.equal(SHK.addShare(list, p[0]), 'added');
    assert.equal(SHK.addShare(list, p[0]), 'duplicate');
    assert.equal(SHK.addShare(list, SHK.parseShare(p[0].text.toLowerCase())), 'duplicate');
    assert.equal(list.length, 1);
    const e = await rejectsCode(assert, () => SHK.recover([p[0], p[0]]), 'DUPLICATE_INDEX');
    assert.equal(e.params.x, 1);
    const flipped = SHK.parseShare(SHK.encodeShare({ ...p[0], data: p[0].data.map((v) => v ^ 1) }));   // same x, different data, valid CRC
    await rejectsCode(assert, () => SHK.addShare([p[0]], flipped), 'DUPLICATE_INDEX');
    // a duplicate must not be silently counted towards k
    await rejectsCode(assert, () => SHK.recover([p[1], p[1]]), 'DUPLICATE_INDEX');
  });

  test('a corrupted share that still carries a valid checksum is caught by the embedded hash', async () => {
    const p = parse(await split('integrity matters', 2, 3));
    const evil = SHK.parseShare(SHK.encodeShare({ ...p[0], data: p[0].data.map((v, i) => (i === 3 ? v ^ 0x40 : v)) }));
    await rejectsCode(assert, () => SHK.recover([evil, p[1]]), 'VERIFY_FAILED');
  });

  test('parsing is forgiving about case, whitespace, hyphen grouping and several shares per paste', async () => {
    const r = await split('format tolerance', 2, 3);
    const t = r.shares[0].text;
    const grouped = 'shk1-' + t.slice(5).toLowerCase().replace(/(.{5})/g, '$1 ').trim();
    const dashed = t.slice(0, 5) + t.slice(5).replace(/(.{4})/g, '$1-');
    const wrapped = t.replace(/(.{30})/g, '$1\r\n');
    for (const v of [grouped, dashed, wrapped, `  ${t}\n`]) assert.equal(SHK.parseShare(v).text, t);
    const pasted = `Share A:\n${r.shares[0].text}\n\n${r.shares[1].text.toLowerCase()}\r\n${r.shares[2].text}`;
    const parts = SHK.extractShares(pasted);
    assert.equal(parts.length, 4);                      // "Share A:" is its own (invalid) chunk
    assert.throws(() => SHK.parseShare(parts[0]), { code: 'BAD_PREFIX' });
    assert.deepEqual(parts.slice(1).map((x) => SHK.parseShare(x).x), [1, 2, 3]);
  });
});

describe('ciphertext file handling (AES mode)', () => {
  const makeBig = async () => {
    const data = rnd(4000);
    const r = await SHK.split({ data, kind: 'file', name: 'doc.pdf', k: 2, n: 3 });
    return { data, r, p: parse(r) };
  };

  test('missing ciphertext file, wrong set, garbage, tampering', async () => {
    const { r, p } = await makeBig();
    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2)), 'NEED_CIPHERTEXT');

    const other = await makeBig();
    const e = await rejectsCode(assert, () => SHK.recover(p.slice(0, 2), other.r.ciphertextFile), 'CT_MISMATCH');
    assert.equal(e.params.a, p[0].setIdHex);

    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2), rnd(500)), 'BAD_CT_FILE');
    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2), new Uint8Array(0)), 'BAD_CT_FILE');
    const damaged = r.ciphertextFile.slice(); damaged[300] ^= 1;
    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2), damaged), 'BAD_CT_FILE');     // CRC catches storage errors

    // an attacker who fixes the CRC is still stopped by AES-GCM authentication
    const c = SHK.parseCtFile(r.ciphertextFile);
    const forged = c.blob.slice(); forged[100] ^= 1;
    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2), SHK.encodeCtFile(c.setId, forged)), 'DECRYPT_FAILED');
  });

  test('ciphertext is bound to its set: moving it to another set id fails authentication', async () => {
    const a = await makeBig(), b = await makeBig();
    const ca = SHK.parseCtFile(a.r.ciphertextFile);
    const moved = SHK.encodeCtFile(b.p[0].setId, ca.blob);             // pretend a's ciphertext belongs to set b
    await rejectsCode(assert, () => SHK.recover(b.p.slice(0, 2), moved), 'DECRYPT_FAILED');
  });

  test('embedded ciphertext tampering is detected', async () => {
    const r = await split('embedded', 2, 3, { mode: 'aes' });
    const p = parse(r).map((s) => { const ct = s.ct.slice(); ct[14] ^= 1; return SHK.parseShare(SHK.encodeShare({ ...s, ct })); });
    await rejectsCode(assert, () => SHK.recover(p.slice(0, 2)), 'DECRYPT_FAILED');
  });
});
