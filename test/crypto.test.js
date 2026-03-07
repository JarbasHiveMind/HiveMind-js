'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { PasswordHandShake } = require('../static/js/hivemind.js');

const vectors = require('./vectors.json');

// ── Helpers (local copies — not imported from hivemind.js to keep tests self-contained) ──

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return arr;
}

// ─────────────────────────────────────────────────────────────────────────────

describe('PasswordHandShake', () => {

    test('createHsub: first 16 chars equal iv_hex (IV embedded at start)', async () => {
        const hs = new PasswordHandShake(vectors.hsub.password);
        const iv = fromHex(vectors.hsub.iv_hex);
        const hsub = await hs.createHsub(iv);
        assert.equal(hsub.slice(0, 16), vectors.hsub.iv_hex);
    });

    test('createHsub: output is 48 hex chars (default hsublen)', async () => {
        const hs = new PasswordHandShake(vectors.hsub.password);
        const iv = fromHex(vectors.hsub.iv_hex);
        const hsub = await hs.createHsub(iv);
        assert.equal(hsub.length, 48);
    });

    test('createHsub: matches known Python vector', async () => {
        const hs = new PasswordHandShake(vectors.hsub.password);
        const iv = fromHex(vectors.hsub.iv_hex);
        const hsub = await hs.createHsub(iv);
        assert.equal(hsub, vectors.hsub.expected_hsub);
    });

    test('matchHsub: returns true for correct password', async () => {
        const hs = new PasswordHandShake(vectors.hsub.password);
        const result = await hs.matchHsub(vectors.hsub.expected_hsub);
        assert.equal(result, true);
    });

    test('matchHsub: returns false for wrong password', async () => {
        const hs = new PasswordHandShake('definitely-wrong-password');
        const result = await hs.matchHsub(vectors.hsub.expected_hsub);
        assert.equal(result, false);
    });

    test('ivFromHsub: extracts correct 8-byte IV', () => {
        const hs = new PasswordHandShake(vectors.hsub.password);
        const iv = hs.ivFromHsub(vectors.hsub.expected_hsub);
        assert.equal(toHex(iv), vectors.hsub.iv_hex);
    });

    test('deriveSecret: both client and server derive identical 32-byte key', async () => {
        const password = 'shared-password';
        const client = new PasswordHandShake(password);
        const server = new PasswordHandShake(password);

        const { envelope: clientEnvelope } = await client.generateHandshake();
        const { envelope: serverEnvelope } = await server.generateHandshake();

        // Cross-receive: each side processes the other's envelope
        client.receiveHandshake(serverEnvelope);
        server.receiveHandshake(clientEnvelope);

        const clientKey = await client.deriveSecret();
        const serverKey = await server.deriveSecret();

        assert.equal(clientKey.length, 32, 'key must be 32 bytes');
        assert.equal(toHex(clientKey), toHex(serverKey), 'both sides must derive the same key');
    });

    test('deriveSecret: output matches known Python PBKDF2 vector', async () => {
        const hs = new PasswordHandShake(vectors.pbkdf2.password);
        // Inject the pre-computed salt directly (bypasses IV generation)
        hs.iv   = new Uint8Array(8);   // dummy — not used by deriveSecret
        hs.salt = fromHex(vectors.pbkdf2.salt_hex);
        const key = await hs.deriveSecret();
        assert.equal(toHex(key), vectors.pbkdf2.expected_key_hex);
    });

});
