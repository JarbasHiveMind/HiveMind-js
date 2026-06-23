'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { encryptAesGcm, decryptAesGcm } = require('../static/js/hivemind.js');

const vectors = require('./vectors.json');

function fromHex(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return arr;
}

// ─────────────────────────────────────────────────────────────────────────────

describe('AES-GCM', () => {

    test('encrypt/decrypt round-trip (random key)', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const plaintext = 'Hello, HiveMind!';
        const encrypted = await encryptAesGcm(key, plaintext);
        const decrypted = await decryptAesGcm(key, encrypted);
        assert.equal(decrypted, plaintext);
    });

    test('output has {ciphertext, tag, nonce} fields as hex strings', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const result = await encryptAesGcm(key, 'test');
        assert.ok(typeof result.ciphertext === 'string', 'ciphertext must be a string');
        assert.ok(typeof result.tag        === 'string', 'tag must be a string');
        assert.ok(typeof result.nonce      === 'string', 'nonce must be a string');
        // All chars must be valid hex
        assert.ok(/^[0-9a-f]+$/.test(result.ciphertext));
        assert.ok(/^[0-9a-f]+$/.test(result.tag));
        assert.ok(/^[0-9a-f]+$/.test(result.nonce));
    });

    test('nonce is 16 bytes (32 hex chars)', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const result = await encryptAesGcm(key, 'test');
        assert.equal(result.nonce.length, 32);
    });

    test('tag is 16 bytes (32 hex chars)', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const result = await encryptAesGcm(key, 'test');
        assert.equal(result.tag.length, 32);
    });

    test('decryptAesGcm handles missing tag field (tag appended to ciphertext)', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const plaintext = 'compat test';
        const encrypted = await encryptAesGcm(key, plaintext);

        // Simulate old-style payload: tag appended to ciphertext, no separate tag field
        const combined = encrypted.ciphertext + encrypted.tag;
        const compat = { ciphertext: combined, nonce: encrypted.nonce }; // no tag field

        const decrypted = await decryptAesGcm(key, compat);
        assert.equal(decrypted, plaintext);
    });

    test('decryptAesGcm decrypts known Python-encrypted vector', async () => {
        const v = vectors.aes_gcm;
        const key = fromHex(v.key_hex);
        const payload = {
            ciphertext: v.ciphertext_hex,
            tag:        v.tag_hex,
            nonce:      v.nonce_hex
        };
        const decrypted = await decryptAesGcm(key, payload);
        assert.equal(decrypted, v.plaintext);
    });

});
