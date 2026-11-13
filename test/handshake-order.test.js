'use strict';

// hivemind-core sends HELLO and HANDSHAKE back to back, without waiting for the
// client in between, and handling a frame awaits (PSK derivation, Web Crypto).
// The client handles frames in arrival order. A plaintext frame still cannot
// replace the salt, the PSK inputs or the key (HIVEMIND-CRYPTO-1 §3.5).
//
// "Back to back" here means each frame is handed to the socket handler without
// awaiting the one before it, which is how a socket delivers frames that
// arrive in one read.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

let lastWs = null;
class MockWebSocket {
    constructor(url) { this.url = url; this.sent = []; this.readyState = 1; lastWs = this; }
    send(data) { this.sent.push(data); }
    close() { this.readyState = 3; if (this.onclose) this.onclose({ code: 1000 }); }
}
globalThis.WebSocket = MockWebSocket;

const m = require('../static/js/hivemind.js');
const { JarbasHiveMind, PasswordHandShake, States } = m;

const quiet = () => {};
console.log = quiet; console.warn = quiet; console.error = quiet;

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'noise_vectors.json'), 'utf-8'));
const PASSWORD = 'the-shared-password';

const inject = (ws, obj) => ws.onmessage({ data: JSON.stringify(obj) });
const injectBinary = (ws, hex) => ws.onmessage({ data: Uint8Array.from(Buffer.from(hex, 'hex')).buffer });
const textFrames = (ws) => ws.sent.filter((f) => typeof f === 'string').map((f) => JSON.parse(f));
const shakesSent = (ws) => textFrames(ws).filter((f) => f.msg_type === 'shake');
const sameKey = (a, b) => Buffer.from(a).equals(Buffer.from(b));

function track(h) {
    const log = [];
    h.onHiveConnected = () => log.push('connected');
    h.onHiveDisconnected = () => log.push('disconnected');
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onMycroftMessage = (msg) => log.push('bus:' + msg.type + (msg.data && msg.data.utterance ? ':' + msg.data.utterance : ''));
    return log;
}

function connectV3(v) {
    const h = new JarbasHiveMind();
    const log = track(h);
    h.connect('hub', 5678, 'user', 'key', 'unused-password', {
        psk: v.psk_hex,
        noiseStaticKey: v.initiator_static_hex,
        _noiseEphemeralKey: v.initiator_ephemeral_hex
    });
    const ws = lastWs;
    ws.onopen();
    return { h, ws, log };
}

function connectLegacy() {
    const h = new JarbasHiveMind();
    const log = track(h);
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    return { h, ws, log };
}

for (const vkey of ['xxpsk2', 'xxpsk2_chacha']) {
    test('v3 (' + vkey + '): HELLO and HANDSHAKE back to back, as the hub sends them, reach READY', async () => {
        const v = vectors[vkey];
        const { h, ws, log } = connectV3(v);

        await Promise.all([
            inject(ws, { msg_type: 'hello', payload: v.hello_payload }),
            inject(ws, { msg_type: 'shake', payload: v.handshake_payload }),
        ]);
        assert.deepEqual(log, [], 'no frame may be refused');
        const shakes = shakesSent(ws);
        assert.equal(shakes.length, 1, JSON.stringify(shakes));
        assert.equal(shakes[0].payload.noise.msg, v.msg1_hex, 'Noise message 1 must match the reference');

        await inject(ws, { msg_type: 'shake', payload: { noise: { msg: v.msg2_hex } } });
        assert.equal(shakesSent(ws)[1].payload.noise.msg, v.msg3_hex);
        assert.equal(h._state, States.READY);
        assert.deepEqual(log, ['connected']);

        await injectBinary(ws, v.server_transport_frame_hex);
        assert.deepEqual(log, ['connected', 'bus:speak:hello from python']);
    });
}

test('v3 with a password only: the argon2id PSK is derived from the HELLO delivered just before', async () => {
    const av = vectors.argon2id_psk;
    const h = new JarbasHiveMind();
    const log = track(h);
    h.connect('hub', 5678, 'user', 'key', av.password);
    const ws = lastWs;
    ws.onopen();

    await Promise.all([
        inject(ws, { msg_type: 'hello', payload: { node_id: av.node_id } }),
        inject(ws, { msg_type: 'shake', payload: {
            max_protocol_version: 3, binarize: false,
            encodings: ['JSON-HEX'], ciphers: ['AES-GCM'],
            noise: { patterns: ['XXpsk2'], suites: ['25519_ChaChaPoly_SHA256', '25519_AESGCM_SHA256'] }
        } }),
    ]);
    assert.deepEqual(log, []);
    assert.equal(shakesSent(ws).length, 1);
    assert.equal(Buffer.from(h._noiseHandshake.psk).toString('hex'), av.expected_psk_hex);
});

test('legacy: HELLO and HANDSHAKE back to back reach READY', async () => {
    const { h, ws, log } = connectLegacy();
    await Promise.all([
        inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } }),
        inject(ws, { msg_type: 'shake', payload: { binarize: false } }),
    ]);
    assert.deepEqual(log, []);
    const shakes = shakesSent(ws);
    assert.equal(shakes.length, 1);

    const hub = new PasswordHandShake(PASSWORD);
    const { envelope } = await hub.generateHandshake();
    hub.receiveHandshake(shakes[0].payload.envelope);
    await inject(ws, { msg_type: 'shake', payload: { envelope } });
    assert.ok(sameKey(h._sessionKey, await hub.deriveSecret()));
    assert.deepEqual(log, ['connected']);
});

test('legacy: an encrypted frame right behind the hub envelope is delivered once the key exists', async () => {
    const { ws, log } = connectLegacy();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const hub = new PasswordHandShake(PASSWORD);
    const { envelope } = await hub.generateHandshake();
    hub.receiveHandshake(shakesSent(ws)[0].payload.envelope);
    const key = await hub.deriveSecret();
    const speak = await m.encryptAesGcm(key,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'speak', data: { utterance: 'hi' } } }));

    await Promise.all([inject(ws, { msg_type: 'shake', payload: { envelope } }), inject(ws, speak)]);
    assert.deepEqual(log, ['connected', 'bus:speak:hi']);
});

test('v3: a second plaintext HANDSHAKE queued behind the hub one is refused and replaces nothing', async () => {
    const v = vectors.xxpsk2;
    const { h, ws, log } = connectV3(v);
    const attackerShake = { msg_type: 'shake', payload: {
        max_protocol_version: 3,
        noise: { patterns: ['XXpsk2'], suites: ['25519_ChaChaPoly_SHA256'], kdf: { name: 'PBKDF2', iterations: 1 } }
    } };

    await Promise.all([
        inject(ws, { msg_type: 'hello', payload: v.hello_payload }),
        inject(ws, { msg_type: 'shake', payload: v.handshake_payload }),
        inject(ws, attackerShake),
        inject(ws, { msg_type: 'hello', payload: { node_id: 'attacker-node' } }),
    ]);
    assert.equal(log.filter((l) => /^error:.*refused a handshake frame/.test(l)).length, 2, JSON.stringify(log));
    assert.equal(shakesSent(ws).length, 1, 'only one Noise message 1 may be sent');
    assert.equal(shakesSent(ws)[0].payload.noise.msg, v.msg1_hex);

    await inject(ws, { msg_type: 'shake', payload: { noise: { msg: v.msg2_hex } } });
    assert.equal(h._state, States.READY, 'the genuine reply must still complete the handshake');
    assert.ok(log.includes('connected'));
});

test('legacy: a second plaintext HANDSHAKE queued behind the hub one cannot replace the salt', async () => {
    const { h, ws, log } = connectLegacy();
    await Promise.all([
        inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } }),
        inject(ws, { msg_type: 'shake', payload: { binarize: false } }),
        inject(ws, { msg_type: 'shake', payload: { binarize: true } }),
    ]);
    assert.ok(log.some((l) => /^error:.*refused a handshake frame/.test(l)), JSON.stringify(log));
    const shakes = shakesSent(ws);
    assert.equal(shakes.length, 1, 'a second envelope means a second salt');
    const hub = new PasswordHandShake(PASSWORD);
    const { envelope } = await hub.generateHandshake();
    hub.receiveHandshake(shakes[0].payload.envelope);
    await inject(ws, { msg_type: 'shake', payload: { envelope } });
    assert.ok(sameKey(h._sessionKey, await hub.deriveSecret()), 'the key must follow the first salt');
});

test('v3: plaintext HANDSHAKE frames after the key is set cannot replace the transport', async () => {
    const v = vectors.xxpsk2;
    const { h, ws, log } = connectV3(v);
    await inject(ws, { msg_type: 'hello', payload: v.hello_payload });
    await inject(ws, { msg_type: 'shake', payload: v.handshake_payload });
    await inject(ws, { msg_type: 'shake', payload: { noise: { msg: v.msg2_hex } } });
    const transport = h._noiseTransport;
    const sentBefore = ws.sent.length;

    await Promise.all([
        inject(ws, { msg_type: 'shake', payload: v.handshake_payload }),
        inject(ws, { msg_type: 'shake', payload: { noise: { msg: v.msg2_hex } } }),
        inject(ws, { msg_type: 'hello', payload: { node_id: 'attacker-node' } }),
    ]);
    assert.equal(h._noiseTransport, transport, 'the Noise transport was replaced');
    assert.equal(ws.sent.length, sentBefore, 'no handshake frame may be answered');
    assert.equal(log.filter((l) => /^error:.*unencrypted text frame/.test(l)).length, 3, JSON.stringify(log));

    await injectBinary(ws, v.server_transport_frame_hex);
    assert.ok(log.includes('bus:speak:hello from python'), JSON.stringify(log));
});

test('legacy: an attacker HANDSHAKE after the key is set cannot replace the key', async () => {
    const { h, ws, log } = connectLegacy();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const clientEnvelope = shakesSent(ws)[0].payload.envelope;
    const hub = new PasswordHandShake(PASSWORD);
    const { envelope } = await hub.generateHandshake();
    hub.receiveHandshake(clientEnvelope);
    await inject(ws, { msg_type: 'shake', payload: { envelope } });
    const goodKey = await hub.deriveSecret();

    // the attacker knows the password and answers the same client envelope
    const attacker = new PasswordHandShake(PASSWORD);
    const { envelope: attackerEnvelope } = await attacker.generateHandshake();
    attacker.receiveHandshake(clientEnvelope);
    const attackerKey = await attacker.deriveSecret();
    const sentBefore = ws.sent.length;

    await Promise.all([
        inject(ws, { msg_type: 'shake', payload: { binarize: false } }),
        inject(ws, { msg_type: 'shake', payload: { envelope: attackerEnvelope } }),
    ]);
    assert.ok(sameKey(h._sessionKey, goodKey), 'the session key was replaced');
    assert.equal(ws.sent.length, sentBefore, 'no handshake frame may be answered');

    await inject(ws, await m.encryptAesGcm(attackerKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'attacker.injected' } })));
    await inject(ws, await m.encryptAesGcm(goodKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'speak', data: { utterance: 'ok' } } })));
    assert.ok(!log.some((l) => l.startsWith('bus:attacker')), JSON.stringify(log));
    assert.ok(log.includes('bus:speak:ok'), JSON.stringify(log));
});
