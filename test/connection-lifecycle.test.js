'use strict';

// A connection that closes while the client derives keys must stay closed:
// onHiveConnected must not fire after onHiveDisconnected, and no handshake
// frame may go out on the dead socket. A socket from an earlier connect()
// must not change the state of the next connection.

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
        return this.onmessage ? this.onmessage({ data: JSON.stringify(obj) }) : Promise.resolve();
    }
    triggerOpen() { if (this.onopen) this.onopen(); }
    triggerClose(event) { if (this.onclose) this.onclose(event || { code: 1006 }); }
}

globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind, PasswordHandShake, States, NOISE_SUITE_AESGCM } = require('../static/js/hivemind.js');

const LEGACY_SHAKE = { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] };

function recorder(hm) {
    const events = [];
    hm.onHiveConnected = () => events.push('connected');
    hm.onHiveDisconnected = () => events.push('disconnected');
    hm.onHiveError = (e) => events.push('error');
    return events;
}

async function serverResponse(password, ws) {
    const clientHs = JSON.parse(ws.sent[ws.sent.length - 1]);
    const server = new PasswordHandShake(password);
    const { envelope } = await server.generateHandshake();
    server.receiveHandshake(clientHs.payload.envelope);
    return { envelope, encoding: 'JSON-HEX', cipher: 'AES-GCM' };
}

describe('Connection generation', () => {
    test('a close during legacy key derivation never fires onHiveConnected', async () => {
        const hm = new JarbasHiveMind();
        const events = recorder(hm);
        hm.connect('hub.example', 5678, 'user', 'key-legacy', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: LEGACY_SHAKE });
        const response = await serverResponse('pw', ws);
        const sentBefore = ws.sent.length;

        const pending = ws.inject({ msg_type: 'shake', payload: response });  // PBKDF2 starts
        ws.triggerClose({ code: 1006 });                                       // socket drops
        await pending;

        assert.deepEqual(events, ['error', 'disconnected']);
        assert.equal(hm._state, States.DISCONNECTED);
        assert.equal(hm._sessionKey, null);
        assert.equal(ws.sent.length, sentBefore, 'no HELLO on a closed socket');
    });

    test('a close during PSK resolution does not start the Noise handshake', async () => {
        const hm = new JarbasHiveMind();
        const events = recorder(hm);
        hm.connect('hub.example', 5678, 'user', 'key-noise', 'pw', { psk: '11'.repeat(32) });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: { node_id: 'n1' } });
        const sentBefore = ws.sent.length;

        const pending = ws.inject({ msg_type: 'shake', payload: {
            max_protocol_version: 3, binarize: false,
            noise: { patterns: ['XXpsk2'], suites: [NOISE_SUITE_AESGCM] },
        } });
        ws.triggerClose({ code: 1006 });
        await pending;

        assert.equal(hm._state, States.DISCONNECTED);
        assert.equal(hm._noiseHandshake, null);
        assert.equal(ws.sent.length, sentBefore, 'no Noise message 1 on a closed socket');
        assert.deepEqual(events, ['error', 'disconnected']);
    });

    test('a finished connection is not revived by a second close event', async () => {
        const hm = new JarbasHiveMind();
        const events = recorder(hm);
        hm.connect('hub.example', 5678, 'user', 'key-twice', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        ws.triggerClose({ code: 1006 });
        ws.triggerClose({ code: 1006 });
        assert.deepEqual(events, ['error', 'disconnected']);
    });
});

describe('Stale socket from an earlier connect()', () => {
    test('connect() detaches and closes the previous socket', () => {
        const hm = new JarbasHiveMind();
        hm.connect('hub.example', 5678, 'user', 'key-a', 'pw', { legacyHub: true });
        const ws1 = _lastMockWs;
        ws1.triggerOpen();
        hm.connect('hub.example', 5678, 'user', 'key-a', 'pw', { legacyHub: true });
        assert.equal(ws1.closed, true);
        assert.equal(ws1.onclose, null);
        assert.equal(ws1.onmessage, null);
        assert.equal(ws1.onopen, null);
    });

    test('a late close of the old socket does not reset the new connection', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('hub.example', 5678, 'user', 'key-b', 'pw', { legacyHub: true });
        const ws1 = _lastMockWs;
        ws1.triggerOpen();
        const staleClose = ws1.onclose;      // a real socket may still fire this
        const staleMessage = ws1.onmessage;

        hm.connect('hub.example', 5678, 'user', 'key-b', 'pw', { legacyHub: true });
        const ws2 = _lastMockWs;
        const events = recorder(hm);
        ws2.triggerOpen();
        await ws2.inject({ msg_type: 'hello', payload: { node_id: 'n2' } });
        assert.equal(hm._state, States.HELLO_RECEIVED);

        staleClose({ code: 1006 });
        await staleMessage({ data: JSON.stringify({ msg_type: 'hello', payload: { node_id: 'stale' } }) });

        assert.equal(hm._state, States.HELLO_RECEIVED);
        assert.equal(hm._serverNodeId, 'n2');
        assert.deepEqual(events, []);
    });

    test('a derivation started on the old socket does not write into the new one', async () => {
        const hm = new JarbasHiveMind();
        const events = recorder(hm);
        hm.connect('hub.example', 5678, 'user', 'key-c', 'pw', { legacyHub: true });
        const ws1 = _lastMockWs;
        ws1.triggerOpen();
        await ws1.inject({ msg_type: 'hello', payload: {} });
        await ws1.inject({ msg_type: 'shake', payload: LEGACY_SHAKE });
        const response = await serverResponse('pw', ws1);
        const handshake1 = hm._handshake;

        const pending = ws1.inject({ msg_type: 'shake', payload: response });
        hm.connect('hub.example', 5678, 'user', 'key-c', 'pw', { legacyHub: true });
        const ws2 = _lastMockWs;
        ws2.triggerOpen();
        await pending;

        assert.notEqual(hm._handshake, handshake1);
        assert.equal(hm._state, States.CONNECTING);
        assert.equal(hm._sessionKey, null);
        assert.equal(ws2.sent.length, 0);
        assert.deepEqual(events, []);
    });

    test('sendMessage rejects when the socket closes during encryption', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('hub.example', 5678, 'user', 'key-d', 'pw', { legacyHub: true });
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: LEGACY_SHAKE });
        await ws.inject({ msg_type: 'shake', payload: await serverResponse('pw', ws) });
        assert.equal(hm._state, States.READY);
        const sentBefore = ws.sent.length;

        const pending = hm.sendMessage(hm._wrap('bus', { type: 'x', data: {}, context: {} }));
        ws.triggerClose({ code: 1000 });
        await assert.rejects(pending, /Not connected/);
        assert.equal(ws.sent.length, sentBefore);
    });
});
