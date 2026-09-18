'use strict';
// A browser bundle that ships without @noble is a supported deployment: the
// client must stay in the Web-Crypto-only AES-GCM + PBKDF2 subset for its
// whole life. Consumers reproduce that shape (HiveMind-webchat
// tests/v3_negotiation.test.mjs loadClient(false)) by blocking
// require('@noble/...') while the client file loads, then restoring require.
// So the require() backend must resolve at load, not on first use.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('path');

const CLIENT = path.resolve(__dirname, '..', 'static', 'js', 'hivemind.js');

// Load a fresh copy of the client with require('@noble/...') blocked for the
// duration of the load only, exactly as the consumer suites do.
function loadClientWithoutNoble() {
    delete require.cache[CLIENT];
    delete globalThis.HiveMindNoble;
    const original = Module.prototype.require;
    Module.prototype.require = function (id, ...rest) {
        if (id.startsWith('@noble/')) {
            throw new Error(`blocked for test: ${id} (bundle without @noble)`);
        }
        return original.call(this, id, ...rest);
    };
    try {
        return require(CLIENT);
    } finally {
        Module.prototype.require = original;
        delete require.cache[CLIENT];
    }
}

test('a client loaded without @noble offers only the AES-GCM suite', () => {
    const hm = loadClientWithoutNoble();
    assert.deepEqual(hm.noiseSuitesJs(), ['25519_AESGCM_SHA256']);
    assert.deepEqual(hm.NOISE_SUITES_JS, ['25519_AESGCM_SHA256']);
    assert.equal(
        hm.selectNoiseOptions(['XXpsk2'], ['25519_ChaChaPoly_SHA256'], null), null,
        'a ChaChaPoly-only server must be declined');
});

test('a client loaded without @noble declines an argon2id v3 hub', async () => {
    const hm = loadClientWithoutNoble();
    const c = new hm.JarbasHiveMind();
    c._maxProtocolVersion = 3;
    c._password = 'super secret hive password';
    c._serverNodeId = 'HiveMind-Node';

    const psk = await c._resolveNoisePsk({
        node_id: 'HiveMind-Node',
        max_protocol_version: 3,
        noise: {
            patterns: ['XXpsk2', 'KKpsk0'],
            suites: ['25519_ChaChaPoly_SHA256', '25519_AESGCM_SHA256'],
            kdf: { name: 'argon2id' },
        },
    });
    assert.equal(psk, null, 'must decline v3 and fall back to legacy');
});

test('a client loaded without @noble cannot derive an argon2id PSK', async () => {
    const hm = loadClientWithoutNoble();
    await assert.rejects(
        () => hm.derivePskArgon2('super secret hive password', 'HiveMind-Node'),
        /argon2id unavailable/);
});

test('the normal load still has the @noble backend', () => {
    delete require.cache[CLIENT];
    delete globalThis.HiveMindNoble;
    const hm = require(CLIENT);
    assert.deepEqual(hm.noiseSuitesJs(),
        ['25519_ChaChaPoly_SHA256', '25519_AESGCM_SHA256']);
});
