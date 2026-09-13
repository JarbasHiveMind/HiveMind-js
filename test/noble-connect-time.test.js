'use strict';
// A browser page loads hivemind.js as a classic script before the module that
// sets globalThis.HiveMindNoble. The client must read the backend when it
// connects, not once at load. Here the file runs with no require(), like a
// browser, and the backend is set only after the load.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { chacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { argon2id } = require('@noble/hashes/argon2.js');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'static', 'js', 'hivemind.js'), 'utf8');

function loadLikeABrowser() {
    const sandbox = {
        console, crypto: globalThis.crypto, TextEncoder, TextDecoder,
        setTimeout, clearTimeout, Uint8Array, ArrayBuffer, DataView, BigInt,
        WebSocket: function () {}
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(SRC, sandbox, { filename: 'hivemind.js' });
    return sandbox;
}

const SERVER_SUITES = ['25519_ChaChaPoly_SHA256', '25519_AESGCM_SHA256'];

// The vm context is a second realm: an options object built inside it fails
// @noble's plain-object check. A browser page has one realm, so copy the
// options into this realm here only.
const realmSafeArgon2id = (password, salt, opts) => argon2id(password, salt, { ...opts });

test('without a backend only AES-GCM is offered and no argon2id PSK derives', () => {
    const g = loadLikeABrowser();
    assert.equal(typeof g.require, 'undefined');
    assert.equal(g.selectNoiseOptions(['XXpsk2'], SERVER_SUITES).suite, '25519_AESGCM_SHA256');
});

test('a backend set after the load is used at connect time', async () => {
    const g = loadLikeABrowser();
    g.HiveMindNoble = { chacha20poly1305, argon2id: realmSafeArgon2id };
    assert.equal(g.selectNoiseOptions(['XXpsk2'], SERVER_SUITES).suite, '25519_ChaChaPoly_SHA256',
        'the DEFAULT ChaCha suite must be picked once the backend exists');
    const psk = await g.derivePskArgon2('pw', 'node-1');
    assert.equal(psk.length, 32);
});

test('the connect path derives the argon2id PSK from a late backend', async () => {
    const g = loadLikeABrowser();
    const hm = new g.JarbasHiveMind();
    hm._password = 'pw';
    hm._serverNodeId = 'node-1';
    g.HiveMindNoble = { chacha20poly1305, argon2id: realmSafeArgon2id };
    const psk = await hm._resolveNoisePsk({
        max_protocol_version: 3,
        noise: { patterns: ['XXpsk2'], suites: SERVER_SUITES }
    });
    assert.ok(psk && psk.length === 32, 'no "argon2id is unavailable" with a late backend');
});
