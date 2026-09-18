'use strict';

// HIVEMIND-CRYPTO-1 §3.5: the nonce is a strictly sequential counter. Two
// concurrent operations on one CipherState must never share a nonce.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const m = require('../static/js/hivemind.js');

const suites = [m.NOISE_SUITE_AESGCM, m.NOISE_SUITE_CHACHA].filter(Boolean);
const EMPTY = new Uint8Array(0);

function cipher(suite) {
    const c = new m.NoiseCipherState(suite);
    c.initializeKey(new Uint8Array(32).fill(7));
    return c;
}

const hex = (b) => Buffer.from(b).toString('hex');

for (const suite of suites) {
    test(suite + ': concurrent encrypts use distinct nonces', async () => {
        const c = cipher(suite);
        const pt = new Uint8Array(16);
        const cts = await Promise.all([1, 2, 3, 4].map(() => c.encryptWithAd(EMPTY, pt)));
        assert.equal(new Set(cts.map(hex)).size, 4, 'two frames share a nonce');
        assert.equal(c.n, 4n);
        // the returned frames are in nonce order: a receiver decrypts them in order
        const r = cipher(suite);
        for (const ct of cts) assert.deepEqual(await r.decryptWithAd(EMPTY, ct), pt);
    });

    test(suite + ': two back-to-back decrypts both succeed', async () => {
        const s = cipher(suite);
        const f1 = await s.encryptWithAd(EMPTY, new Uint8Array([1]));
        const f2 = await s.encryptWithAd(EMPTY, new Uint8Array([2]));
        const r = cipher(suite);
        const res = await Promise.allSettled([r.decryptWithAd(EMPTY, f1), r.decryptWithAd(EMPTY, f2)]);
        assert.deepEqual(res.map((x) => x.status), ['fulfilled', 'fulfilled']);
        assert.deepEqual(res.map((x) => x.value[0]), [1, 2]);
        assert.equal(r.n, 2n);
    });

    test(suite + ': a failed decrypt does not advance, so the next frame is also rejected', async () => {
        const s = cipher(suite);
        const f1 = await s.encryptWithAd(EMPTY, new Uint8Array([1]));
        const f2 = await s.encryptWithAd(EMPTY, new Uint8Array([2]));
        const bad = Uint8Array.from(f1); bad[0] ^= 1;
        const r = cipher(suite);
        const res = await Promise.allSettled([r.decryptWithAd(EMPTY, bad), r.decryptWithAd(EMPTY, f2)]);
        assert.deepEqual(res.map((x) => x.status), ['rejected', 'rejected']);
        assert.equal(r.n, 0n);
    });
}

test('AES-GCM: the key is imported once per key, not once per frame', async () => {
    const realImport = crypto.subtle.importKey.bind(crypto.subtle);
    let aesImports = 0;
    crypto.subtle.importKey = (format, key, alg, ...rest) => {
        if (alg === 'AES-GCM' || (alg && alg.name === 'AES-GCM')) aesImports += 1;
        return realImport(format, key, alg, ...rest);
    };
    try {
        const s = cipher(m.NOISE_SUITE_AESGCM);
        const r = cipher(m.NOISE_SUITE_AESGCM);
        const pt = new Uint8Array(8);
        const cts = await Promise.all(Array.from({ length: 20 }, () => s.encryptWithAd(EMPTY, pt)));
        for (const ct of cts) await r.decryptWithAd(EMPTY, ct);
        assert.equal(aesImports, 2, 'one import per state, got ' + aesImports);
    } finally {
        crypto.subtle.importKey = realImport;
    }
});

test('AES-GCM: a new key replaces the cached key', async () => {
    const s = cipher(m.NOISE_SUITE_AESGCM);
    await s.encryptWithAd(EMPTY, new Uint8Array(8));  // caches the first key
    const k2 = new Uint8Array(32).fill(9);
    s.initializeKey(k2);
    const fresh = new m.NoiseCipherState(m.NOISE_SUITE_AESGCM);
    fresh.initializeKey(k2);
    const pt = new Uint8Array([4, 5, 6]);
    assert.equal(hex(await s.encryptWithAd(EMPTY, pt)), hex(await fresh.encryptWithAd(EMPTY, pt)));
});

for (const suite of suites) {
    test(suite + ': sends past the queue bound are rejected, and the queue recovers', async () => {
        const limit = m.NoiseCipherState.MAX_PENDING_SENDS;
        assert.ok(Number.isInteger(limit) && limit > 0, 'MAX_PENDING_SENDS is not set');
        const c = cipher(suite);
        const pt = new Uint8Array(4);
        const accepted = Array.from({ length: limit }, () => c.encryptWithAd(EMPTY, pt));
        await assert.rejects(c.encryptWithAd(EMPTY, pt), /send queue full/);
        const cts = await Promise.all(accepted);
        assert.equal(new Set(cts.map(hex)).size, limit);
        assert.equal(c.n, BigInt(limit));
        await c.encryptWithAd(EMPTY, pt);  // the queue drained, so a send works again
        assert.equal(c.n, BigInt(limit) + 1n);
    });
}
