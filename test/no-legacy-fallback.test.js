'use strict';

// HIVEMIND-CRYPTO-1 §3: "A server MUST reject a peer that cannot complete the
// Noise handshake ... rather than fall back to any unencrypted or legacy
// exchange", and a node MUST "run the mandatory Noise handshake on every
// connection ... with no cleartext or legacy fallback" (§5). When the server
// offers protocol v3, a client that cannot run it must refuse the connection
// with a clear error. It must not send the legacy handshake. The legacy path
// stays only for a server that does not offer Noise.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.sent = [];
        this.closed = false;
        MockWebSocket.last = this;
    }
    send(data) { this.sent.push(data); }
    close() { this.closed = true; if (this.onclose) this.onclose(); }
    inject(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        return this.onmessage ? this.onmessage({ data: str }) : Promise.resolve();
    }
    triggerOpen() { if (this.onopen) this.onopen(); }
}
globalThis.WebSocket = MockWebSocket;

const HIVEMIND_JS = require.resolve('../static/js/hivemind.js');

// Load hivemind.js as a browser bundle without @noble/hashes would run: the
// argon2id import fails, so a password alone cannot derive the Noise PSK.
function loadWithoutArgon2id() {
    const originalLoad = Module._load;
    Module._load = function (request, ...rest) {
        if (request === '@noble/hashes/argon2.js') throw new Error('Cannot find module ' + request);
        return originalLoad.call(this, request, ...rest);
    };
    try {
        delete require.cache[HIVEMIND_JS];
        return require(HIVEMIND_JS);
    } finally {
        Module._load = originalLoad;
        delete require.cache[HIVEMIND_JS];
    }
}

const V3_OFFER = {
    handshake: true, password: true,
    min_protocol_version: 2, max_protocol_version: 3,
    encodings: ['JSON-HEX'], ciphers: ['AES-GCM'],
    noise: { patterns: ['XXpsk2'], suites: ['25519_ChaChaPoly_SHA256', '25519_AESGCM_SHA256'] }
};

async function runHandshake(lib, handshakePayload, options) {
    const hm = new lib.JarbasHiveMind();
    const errors = [];
    hm.onHiveError = (err) => { errors.push(err); };
    hm.onHiveDisconnected = () => {};
    hm.connect('localhost', 5678, 'user', 'key', 'a-shared-password', options);
    const ws = MockWebSocket.last;
    ws.triggerOpen();
    await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
    await ws.inject({ msg_type: 'shake', payload: handshakePayload });
    const shakes = ws.sent
        .filter((frame) => typeof frame === 'string')
        .map((frame) => JSON.parse(frame))
        .filter((msg) => msg.msg_type === 'shake');
    return { hm, ws, errors, shakes, States: lib.States };
}

function assertRefused({ hm, ws, errors, shakes, States }, pattern) {
    assert.equal(shakes.length, 0,
        'no HANDSHAKE may be sent, and above all no legacy envelope: ' + JSON.stringify(shakes));
    assert.ok(ws.closed, 'the client must close the connection');
    assert.equal(hm._state, States.DISCONNECTED);
    assert.equal(errors.length, 1, 'exactly one error must reach onHiveError, got ' +
        errors.map((e) => e.message).join(' | '));
    assert.match(errors[0].message, pattern);
    assert.match(errors[0].message, /CRYPTO-1 §3/);
}

describe('server offers protocol v3: no legacy fallback (CRYPTO-1 §3)', () => {
    test('no PSK can be derived (argon2id unavailable): the client refuses', async () => {
        const lib = loadWithoutArgon2id();
        const result = await runHandshake(lib, V3_OFFER);
        assertRefused(result, /no PSK can be derived/);
    });

    test('no mutual Noise pattern or suite: the client refuses', async () => {
        const lib = require(HIVEMIND_JS);
        const offer = { ...V3_OFFER, noise: { patterns: ['XXpsk2'], suites: ['25519_Unknown_SHA512'] } };
        const result = await runHandshake(lib, offer, { psk: '11'.repeat(32) });
        assertRefused(result, /no mutual Noise pattern/);
    });
});

describe('server does not offer protocol v3: the legacy handshake still runs', () => {
    test('a v1 server without Noise parameters gets the legacy envelope', async () => {
        const lib = loadWithoutArgon2id();
        const { errors, shakes } = await runHandshake(lib, {
            handshake: true, password: true, max_protocol_version: 1,
            encodings: ['JSON-HEX'], ciphers: ['AES-GCM']
        });
        assert.equal(shakes.length, 1);
        assert.equal(typeof shakes[0].payload.envelope, 'string', 'legacy envelope expected');
        assert.equal(errors.length, 0);
    });
});
