'use strict';

// Errors must reach the caller through onHiveError. Before, an exception in
// an async message handler became an unhandled promise rejection, the reason
// a client aborted a connection was only logged, and a socket error event had
// no handler.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.sent = [];
        this.closed = false;
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        _lastMockWs = this;
    }
    send(data) { this.sent.push(data); }
    close() { this.closed = true; }
    inject(obj) {
        const data = typeof obj === 'string' ? obj : JSON.stringify(obj);
        return this.onmessage ? this.onmessage({ data }) : Promise.resolve();
    }
    triggerOpen() { if (this.onopen) this.onopen(); }
    triggerClose(event) { if (this.onclose) this.onclose(event || { code: 1006 }); }
}

globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind, PasswordHandShake, States, NOISE_SUITE_AESGCM } = require('../static/js/hivemind.js');

const LEGACY_SHAKE = { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] };

function errors(hm) {
    const list = [];
    hm.onHiveError = (e) => list.push(e.message);
    return list;
}

async function legacyReady(hm, key) {
    hm.connect('hub.example', 5678, 'user', key, 'pw', { legacyHub: true });
    const ws = _lastMockWs;
    ws.triggerOpen();
    await ws.inject({ msg_type: 'hello', payload: {} });
    await ws.inject({ msg_type: 'shake', payload: LEGACY_SHAKE });
    const clientHs = JSON.parse(ws.sent[ws.sent.length - 1]);
    const server = new PasswordHandShake('pw');
    const { envelope } = await server.generateHandshake();
    server.receiveHandshake(clientHs.payload.envelope);
    await ws.inject({ msg_type: 'shake', payload: { envelope, encoding: 'JSON-HEX', cipher: 'AES-GCM' } });
    assert.equal(hm._state, States.READY);
    return ws;
}

describe('Handler errors reach onHiveError', () => {
    test('an exception in a consumer hook after READY is reported, not rejected', async () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        const ws = await legacyReady(hm, 'key-hook');
        hm.onMycroftMessage = () => { throw new Error('consumer hook failed'); };

        const frame = await hm._encrypt(JSON.stringify(hm._wrap('bus', { type: 'x', data: {}, context: {} })));
        await assert.doesNotReject(ws.inject(frame));
        assert.deepEqual(seen, ['consumer hook failed']);
        assert.equal(hm._state, States.READY, 'a hook error does not drop the connection');
    });

    test('a handshake step that throws closes the connection and reports why', async () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        hm.connect('hub.example', 5678, 'user', 'key-shake', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: LEGACY_SHAKE });

        // a malformed server envelope makes the key derivation throw
        await assert.doesNotReject(ws.inject({ msg_type: 'shake', payload: { envelope: 12345 } }));
        assert.equal(ws.closed, true, 'the client closes a connection it cannot complete');
        assert.equal(hm._state, States.DISCONNECTED);

        ws.triggerClose({ code: 1000 });
        assert.equal(seen.length, 1);
        assert.match(seen[0], /aborted by the client: handshake failed/);
    });

    test('an exception thrown by onHiveError itself does not escape', async () => {
        const hm = new JarbasHiveMind();
        const ws = await legacyReady(hm, 'key-throwing-error-hook');
        hm.onMycroftMessage = () => { throw new Error('first'); };
        hm.onHiveError = () => { throw new Error('second'); };
        const frame = await hm._encrypt(JSON.stringify(hm._wrap('bus', { type: 'x', data: {}, context: {} })));
        await assert.doesNotReject(ws.inject(frame));
    });
});

describe('Abort reason', () => {
    test('the reason a Noise handshake was aborted reaches onHiveError', async () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        hm.connect('hub.example', 5678, 'user', 'key-abort', 'pw', { psk: '22'.repeat(32) });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: { node_id: 'n1' } });
        await ws.inject({ msg_type: 'shake', payload: {
            max_protocol_version: 3, binarize: false,
            noise: { patterns: ['XXpsk2'], suites: [NOISE_SUITE_AESGCM] },
        } });
        assert.equal(hm._state, States.HANDSHAKE_SENT);

        // garbage in place of Noise message 2: authentication fails
        await ws.inject({ msg_type: 'shake', payload: { noise: { msg: 'ab'.repeat(96) } } });
        assert.equal(ws.closed, true);
        ws.triggerClose({ code: 1000 });

        assert.equal(seen.length, 1);
        assert.match(seen[0], /aborted by the client/);
        assert.match(seen[0], /authentication failure/);
    });

    test('a later refused connection does not repeat an old abort reason', async () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        hm.connect('hub.example', 5678, 'user', 'key-reuse', 'pw', { legacyHub: true });
        _lastMockWs.triggerOpen();
        hm._abortNoise('old reason');
        hm.connect('hub.example', 5678, 'user', 'key-reuse', 'pw', { legacyHub: true });
        const ws2 = _lastMockWs;
        ws2.triggerOpen();
        ws2.triggerClose({ code: 1008, reason: 'bad key' });
        assert.equal(seen.length, 1);
        assert.doesNotMatch(seen[0], /old reason/);
        assert.match(seen[0], /1008/);
    });
});

describe('Socket error event', () => {
    test('a socket error after READY reaches onHiveError', async () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        const ws = await legacyReady(hm, 'key-sockerr');
        assert.equal(typeof ws.onerror, 'function', 'the client must handle socket errors');
        ws.onerror({ type: 'error' });
        assert.equal(seen.length, 1);
        assert.match(seen[0], /WebSocket error/);
    });

    test('a socket error before READY gives one error, from the close', () => {
        const hm = new JarbasHiveMind();
        const seen = errors(hm);
        hm.connect('hub.example', 5678, 'user', 'key-sockerr-2', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        assert.equal(typeof ws.onerror, 'function');
        ws.onerror({ type: 'error' });
        ws.triggerClose({ code: 1006 });
        assert.equal(seen.length, 1);
        assert.match(seen[0], /1006/);
    });
});
