'use strict';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// ── MockWebSocket ─────────────────────────────────────────────────────────────

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url  = url;
        this.sent = [];
        this.binaryType = 'blob';
        this.onopen    = null;
        this.onmessage = null;
        this.onclose   = null;
        _lastMockWs = this;
    }

    send(data) { this.sent.push(data); }

    inject(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        if (this.onmessage) return this.onmessage({ data: str });
        return Promise.resolve();
    }

    injectBinary(buffer) {
        const ab = buffer instanceof Uint8Array ? buffer.buffer : buffer;
        if (this.onmessage) return this.onmessage({ data: ab });
        return Promise.resolve();
    }

    triggerOpen()  { if (this.onopen)  this.onopen(); }
    triggerClose() { if (this.onclose) this.onclose(); }
}

globalThis.WebSocket = MockWebSocket;

const {
    JarbasHiveMind, PasswordHandShake, States,
    encryptAesGcmBin, decryptAesGcmBin,
    encodeBitstring, decodeBitstring,
    BIN_TYPES, MSG_TYPE_TO_INT
} = require('../static/js/hivemind.js');

const vectors = require('./vectors.json');

// ── Helpers ───────────────────────────────────────────────────────────────────

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return arr;
}

async function buildServerHandshakeResponse(password, clientHsMsg) {
    const clientEnvelope = clientHsMsg.payload.envelope;
    const serverHs = new PasswordHandShake(password);
    const { envelope: serverEnvelope } = await serverHs.generateHandshake();
    serverHs.receiveHandshake(clientEnvelope);
    return { envelope: serverEnvelope, encoding: 'JSON-HEX', cipher: 'AES-GCM' };
}

// Full handshake without binarize (standard text path)
async function fullHandshake(password) {
    const hm = new JarbasHiveMind();
    hm.connect('localhost', 5678, 'user', 'access-key', password);
    const ws = _lastMockWs;
    ws.triggerOpen();
    await ws.inject({ msg_type: 'hello', payload: { pubkey: 'srv-pub', node_id: 'node-1', peer: 'master:0.0.0.0' } });
    await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
    const clientHsMsg = JSON.parse(ws.sent[ws.sent.length - 1]);
    const serverResponse = await buildServerHandshakeResponse(password, clientHsMsg);
    await ws.inject({ msg_type: 'shake', payload: serverResponse });
    assert.equal(hm._state, States.READY);
    return { hm, ws };
}

// Full handshake with binarize:true (binary frame path)
async function fullHandshakeBinarize(password) {
    const hm = new JarbasHiveMind();
    hm.connect('localhost', 5678, 'user', 'access-key', password);
    const ws = _lastMockWs;
    ws.triggerOpen();
    await ws.inject({ msg_type: 'hello', payload: { pubkey: 'srv-pub', node_id: 'node-1', peer: 'master:0.0.0.0' } });
    await ws.inject({ msg_type: 'shake', payload: { handshake: true, password: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'], binarize: true } });
    const clientHsMsg = JSON.parse(ws.sent[ws.sent.length - 1]);
    const serverResponse = await buildServerHandshakeResponse(password, clientHsMsg);
    await ws.inject({ msg_type: 'shake', payload: serverResponse });
    assert.equal(hm._state, States.READY);
    return { hm, ws };
}

// ─────────────────────────────────────────────────────────────────────────────

describe('Bitstring codec', () => {

    test('encode/decode round-trip — BUS type, string payload', async () => {
        const payload = '{"type":"recognizer_loop:utterance","data":{"utterances":["hello"]}}';
        const encoded = encodeBitstring('bus', payload, {});
        const decoded = await decodeBitstring(encoded);
        assert.equal(decoded.msgType, 'bus');
        assert.equal(decoded.payload, payload);
        assert.deepEqual(decoded.metadata, {});
    });

    test('encode/decode round-trip — BINARY type, Uint8Array payload', async () => {
        const payload = new Uint8Array([0x52, 0x49, 0x46, 0x46]);  // 'RIFF'
        const encoded = encodeBitstring('bin', payload, { sample_rate: 16000 }, BIN_TYPES.RAW_AUDIO);
        const decoded = await decodeBitstring(encoded);
        assert.equal(decoded.msgType, 'bin');
        assert.ok(decoded.payload instanceof Uint8Array);
        assert.deepEqual(Array.from(decoded.payload), Array.from(payload));
        assert.equal(decoded.binType, BIN_TYPES.RAW_AUDIO);
        assert.deepEqual(decoded.metadata, { sample_rate: 16000 });
    });

    test('first set bit in encoded output is 1 (pad marker after leading zeros)', () => {
        const encoded = encodeBitstring('bus', 'hello', {});
        // Find the first 1 bit
        let found = false;
        for (const byte of encoded) {
            for (let bit = 7; bit >= 0; bit--) {
                if ((byte >> bit) & 1) { found = true; break; }
            }
            if (found) break;
        }
        assert.ok(found, 'pad marker must be present');
        // Also verify: decoded correctly skips padding
        // (already covered by round-trip tests)
    });

    test('MSG_TYPE_TO_INT covers all 13 known types', () => {
        const expected = ['shake','bus','shared_bus','broadcast','propagate','escalate',
                          'hello','query','cascade','ping','rendezvous','3rdparty','bin'];
        for (const t of expected) {
            assert.ok(MSG_TYPE_TO_INT[t] !== undefined, `${t} must be in MSG_TYPE_TO_INT`);
        }
        assert.equal(Object.keys(MSG_TYPE_TO_INT).length, 13);
    });

    test('BIN_TYPES.RAW_AUDIO === 1', () => {
        assert.equal(BIN_TYPES.RAW_AUDIO, 1);
    });

    test('decode handles versioned=true header', async () => {
        const payload = '{"type":"test"}';
        const encoded = encodeBitstring('bus', payload, {}, 0, true);
        const decoded = await decodeBitstring(encoded);
        assert.equal(decoded.msgType, 'bus');
        assert.equal(decoded.payload, payload);
    });

    test('encode matches known Python vector from vectors.json', async () => {
        const v = vectors.bitstring;
        const encoded = encodeBitstring(v.msg_type, v.payload, v.metadata, 0, v.versioned);
        assert.equal(toHex(encoded), v.expected_hex);
    });

});

describe('Binary encryption', () => {

    test('encryptAesGcmBin/decryptAesGcmBin round-trip', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const plaintext = new TextEncoder().encode('hello binary world');
        const frame = await encryptAesGcmBin(key, plaintext);
        const recovered = await decryptAesGcmBin(key, frame);
        assert.equal(new TextDecoder().decode(recovered), 'hello binary world');
    });

    test('binary frame layout: first 16 bytes = nonce, remainder = ciphertext+tag', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const plaintext = new Uint8Array([1, 2, 3, 4]);
        const frame = await encryptAesGcmBin(key, plaintext);
        // frame = nonce(16) + ciphertext(4) + tag(16) = 36 bytes
        assert.equal(frame.length, 16 + 4 + 16);
    });

});

describe('Binarize handshake + messaging', () => {

    test('client sends binarize:true when server advertises binarize:true', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'pw');
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, binarize: true, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
        const msg = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.equal(msg.payload.binarize, true);
    });

    test('client sends binarize:false when server advertises binarize:false', async () => {
        const hm = new JarbasHiveMind();
        hm.connect('localhost', 5678, 'user', 'key', 'pw');
        const ws = _lastMockWs;
        ws.triggerOpen();
        await ws.inject({ msg_type: 'hello', payload: {} });
        await ws.inject({ msg_type: 'shake', payload: { handshake: true, binarize: false, encodings: ['JSON-HEX'], ciphers: ['AES-GCM'] } });
        const msg = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.equal(msg.payload.binarize, false);
    });

    test('_binarize flag is true after full handshake with binarize server', async () => {
        const { hm } = await fullHandshakeBinarize('binarize-flag-test-pw');
        assert.equal(hm._binarize, true);
    });

    test('_binarize flag is false after full handshake with non-binarize server', async () => {
        const { hm } = await fullHandshake('no-binarize-pw');
        assert.equal(hm._binarize, false);
    });

    test('after READY (binarize): sendMessage sends ArrayBuffer, not string', async () => {
        const { hm, ws } = await fullHandshakeBinarize('binarize-send-pw');
        const sentBefore = ws.sent.length;
        await hm.sendMessage(hm._wrap('bus', { type: 'test', data: {}, context: {} }));
        assert.ok(ws.sent.length > sentBefore);
        const lastSent = ws.sent[ws.sent.length - 1];
        assert.ok(lastSent instanceof ArrayBuffer, 'must be ArrayBuffer in binarize mode');
    });

    test('after READY (binarize): incoming binary frame dispatches to onMycroftMessage', async () => {
        const { hm, ws } = await fullHandshakeBinarize('binarize-recv-pw');
        let received = null;
        hm.onMycroftMessage = (msg) => { received = msg; };

        const busPayload = { type: 'speak', data: { utterance: 'hello' }, context: {} };
        const bitFrame = encodeBitstring('bus', JSON.stringify(busPayload), {});
        const encrypted = await encryptAesGcmBin(hm._sessionKey, bitFrame);

        await ws.injectBinary(encrypted);
        // Give any microtask queue a chance to settle
        await new Promise(resolve => setTimeout(resolve, 0));

        assert.ok(received !== null, 'onMycroftMessage must have been called');
        assert.equal(received.type, 'speak');
    });

    test('after READY (no binarize): sendMessage still sends JSON string', async () => {
        const { hm, ws } = await fullHandshake('text-path-pw');
        assert.equal(hm._binarize, false);
        const sentBefore = ws.sent.length;
        await hm.sendMessage(hm._wrap('bus', { type: 'test', data: {}, context: {} }));
        assert.ok(ws.sent.length > sentBefore);
        const lastSent = ws.sent[ws.sent.length - 1];
        assert.ok(typeof lastSent === 'string', 'must be string in text mode');
    });

});
