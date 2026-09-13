'use strict';

const { test, describe, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// ── MockWebSocket ─────────────────────────────────────────────────────────────
// Installed as globalThis.WebSocket before loading hivemind.js so that
// JarbasHiveMind.connect() picks it up without a real network.

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url  = url;
        this.sent = [];
        this.onopen    = null;
        this.onmessage = null;
        this.onclose   = null;
        _lastMockWs = this;
    }

    send(data) {
        this.sent.push(data);
    }

    // Simulate a message arriving from the server.
    // Returns the Promise from the async onmessage handler so tests can await it.
    inject(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        if (this.onmessage) return this.onmessage({ data: str });
        return Promise.resolve();
    }

    triggerOpen()  { if (this.onopen)  this.onopen(); }
    triggerClose() { if (this.onclose) this.onclose(); }
}

// Install mock before requiring hivemind.js
globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind, PasswordHandShake, States } = require('../static/js/hivemind.js');

// ── Helpers ───────────────────────────────────────────────────────────────────

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return arr;
}

// Server-side helper: given the client's HANDSHAKE message (already sent),
// compute the server's response envelope.
async function buildServerHandshakeResponse(password, clientHsMsg) {
    const clientEnvelope = clientHsMsg.payload.envelope;
    const serverHs = new PasswordHandShake(password);
    const { envelope: serverEnvelope } = await serverHs.generateHandshake();
    serverHs.receiveHandshake(clientEnvelope);
    return {
        envelope: serverEnvelope,
        encoding: 'JSON-HEX',
        cipher:   'AES-GCM'
    };
}

// Run a full handshake from ws.open → READY and return the mockWs + hivemind.
async function fullHandshake(password) {
    const hm = new JarbasHiveMind();
    hm.connect('localhost', 5678, 'user', 'access-key', password, { legacyHub: true });
    const ws = _lastMockWs;

    // 1. WS open
    ws.triggerOpen();
    assert.equal(hm._state, States.CONNECTING);

    // 2. Server HELLO
    await ws.inject({ msg_type: 'hello', payload: { pubkey: 'srv-pub', node_id: 'node-1', peer: 'master:0.0.0.0' } });
    assert.equal(hm._state, States.HELLO_RECEIVED);

    // 3. Server HANDSHAKE request (no envelope = asking client to start)
    await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
    assert.equal(hm._state, States.HANDSHAKE_SENT);

    // 4. Parse client HANDSHAKE, build server response
    const clientHsMsg = JSON.parse(ws.sent[ws.sent.length - 1]);
    const serverResponse = await buildServerHandshakeResponse(password, clientHsMsg);

    // 5. Server HANDSHAKE response (has envelope)
    await ws.inject({ msg_type: 'shake', payload: serverResponse });
    assert.equal(hm._state, States.READY);

    return { hm, ws };
}

// ─────────────────────────────────────────────────────────────────────────────

describe('Connection state machine', () => {

    test('onHiveConnected NOT called on ws open (state stays CONNECTING)', () => {
        let called = false;
        const hm = new JarbasHiveMind();
        hm.onHiveConnected = () => { called = true; };
        hm.connect('localhost', 5678, 'user', 'key', 'pw', { legacyHub: true });
        _lastMockWs.triggerOpen();
        assert.equal(called, false);
        assert.equal(hm._state, States.CONNECTING);
    });

    test('state advances to HELLO_RECEIVED after server HELLO', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1', peer: 'p' } });
        assert.equal(hm._state, States.HELLO_RECEIVED);
    });

    test('state advances to HANDSHAKE_SENT after server HANDSHAKE request', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1', peer: 'p' } });
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
        assert.equal(hm._state, States.HANDSHAKE_SENT);
    });

    test('client sends HANDSHAKE with envelope + encodings + ciphers', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'testpw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        const sentBefore = ws.sent.length;
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });

        assert.ok(ws.sent.length > sentBefore, 'client must have sent a HANDSHAKE message');
        const msg = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.equal(msg.msg_type, 'shake');
        assert.ok(typeof msg.payload.envelope === 'string', 'envelope must be present');
        assert.ok(Array.isArray(msg.payload.encodings), 'encodings must be an array');
        assert.ok(Array.isArray(msg.payload.ciphers),   'ciphers must be an array');
        assert.equal(msg.payload.envelope.length, 48, 'default hSub length is 48');
    });

    test('client sends encrypted HELLO after server HANDSHAKE response', async () => {
        const password = 'hello-test-pw';
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', password, { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
        const clientHsMsg = JSON.parse(ws.sent[ws.sent.length - 1]);
        const serverResponse = await buildServerHandshakeResponse(password, clientHsMsg);
        const sentBefore = ws.sent.length;
        await ws.inject({ msg_type: 'shake', payload: serverResponse });

        assert.ok(ws.sent.length > sentBefore, 'client must have sent an encrypted HELLO');
        const raw = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.ok(raw.ciphertext, 'encrypted HELLO must have ciphertext');
        assert.ok(raw.tag,        'encrypted HELLO must have tag');
        assert.ok(raw.nonce,      'encrypted HELLO must have nonce');
    });

    test('onHiveConnected called exactly once after full handshake', async () => {
        let callCount = 0;
        const password = 'once-test-pw';
        const hm = new JarbasHiveMind();
        hm.onHiveConnected = () => { callCount++; };
        hm.connect('localhost', 5678, 'user', 'key', password, { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
        const clientHsMsg = JSON.parse(ws.sent[ws.sent.length - 1]);
        const serverResponse = await buildServerHandshakeResponse(password, clientHsMsg);
        await ws.inject({ msg_type: 'shake', payload: serverResponse });

        assert.equal(callCount, 1, 'onHiveConnected must be called exactly once');
    });

    test('sendMessage before READY is rejected', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'pw', { legacyHub: true });
        _lastMockWs.triggerOpen();
        await assert.rejects(
            () => hm.sendMessage({ msg_type: 'bus', payload: {} }),
            /Not connected/
        );
    });

    test('after READY: sendMessage sends encrypted {ciphertext, tag, nonce}', async () => {
        const { hm, ws } = await fullHandshake('send-test-pw');
        const sentBefore = ws.sent.length;
        await hm.sendMessage(hm._wrap('bus', { type: 'recognizer_loop:utterance', data: {}, context: {} }));
        assert.ok(ws.sent.length > sentBefore);
        const raw = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.ok(raw.ciphertext, 'must have ciphertext');
        assert.ok(raw.tag,        'must have tag');
        assert.ok(raw.nonce,      'must have nonce');
    });

    test('after READY: incoming bus message dispatches to onMycroftMessage', async () => {
        const { hm, ws } = await fullHandshake('dispatch-test-pw');
        let received = null;
        hm.onMycroftMessage = (msg) => { received = msg; };

        const busPayload = { type: 'speak', data: { utterance: 'hello' }, context: {} };
        const hiveMsg = hm._wrap('bus', busPayload);
        const encrypted = await hm._encrypt(JSON.stringify(hiveMsg));
        await ws.inject(encrypted);

        assert.ok(received !== null, 'onMycroftMessage must have been called');
        assert.equal(received.type, 'speak');
    });

    test('onHiveDisconnected called on ws close', async () => {
        let called = false;
        const { hm, ws } = await fullHandshake('disconnect-test-pw');
        hm.onHiveDisconnected = () => { called = true; };
        ws.triggerClose();
        assert.equal(called, true);
        assert.equal(hm._state, States.DISCONNECTED);
    });

});
