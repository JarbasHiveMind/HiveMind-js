'use strict';

// HIVEMIND-CRYPTO-1 §3.5: after the key exists, a peer MUST reject a message
// that is not encrypted. An injected plaintext text frame must not reach the app.

const { test } = require('node:test');
const assert = require('node:assert/strict');

let lastWs = null;
class MockWebSocket {
    constructor(url) { this.url = url; this.sent = []; this.readyState = 1; lastWs = this; }
    send(data) { this.sent.push(data); }
    close() { this.readyState = 3; if (this.onclose) this.onclose({ code: 1000 }); }
}
globalThis.WebSocket = MockWebSocket;

const m = require('../static/js/hivemind.js');
const { JarbasHiveMind, PasswordHandShake } = m;

const quiet = () => {};
console.log = quiet; console.warn = quiet; console.error = quiet;

const PASSWORD = 'the-shared-password';
const inject = (ws, obj) => ws.onmessage({ data: JSON.stringify(obj) });

async function connectLegacy(binarize) {
    const log = [];
    const h = new JarbasHiveMind();
    h.onHiveConnected = () => log.push('connected');
    h.onHiveDisconnected = () => log.push('disconnected');
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onMycroftMessage = (msg) => log.push('bus:' + msg.type);
    // the legacy password handshake is opt-in since #20 (HIVEMIND-CRYPTO-1 §3)
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize } });
    const clientShake = JSON.parse(ws.sent[ws.sent.length - 1]);
    const server = new PasswordHandShake(PASSWORD);
    const { envelope } = await server.generateHandshake();
    server.receiveHandshake(clientShake.payload.envelope);
    await inject(ws, { msg_type: 'shake', payload: { envelope } });
    const key = await server.deriveSecret();
    assert.deepEqual(log.splice(0), ['connected']);
    return { h, ws, log, key };
}

for (const binarize of [false, true]) {
    test('legacy session (binarize=' + binarize + '): injected plaintext frame is dropped and reported', async () => {
        const { ws, log } = await connectLegacy(binarize);
        await inject(ws, { msg_type: 'bus', payload: { type: 'injected.plaintext' } });
        assert.ok(!log.includes('bus:injected.plaintext'), JSON.stringify(log));
        assert.equal(log.length, 1);
        assert.match(log[0], /^error:.*unencrypted text frame/);
    });
}

test('legacy session: an encrypted text frame from the hub is still delivered', async () => {
    const { ws, log, key } = await connectLegacy(false);
    const inner = JSON.stringify({ msg_type: 'bus', payload: { type: 'speak', data: {} } });
    await inject(ws, await m.encryptAesGcm(key, inner));
    assert.deepEqual(log, ['bus:speak']);
});

test('Noise session: any text frame is dropped and reported', async () => {
    const { h, ws, log, key } = await connectLegacy(false);
    h._noiseTransport = { decryptFrame: async () => { throw new Error('unused'); } };
    await inject(ws, { msg_type: 'bus', payload: { type: 'plain.in.noise' } });
    await inject(ws, await m.encryptAesGcm(key, JSON.stringify({ msg_type: 'bus', payload: { type: 'legacy.in.noise' } })));
    assert.ok(!log.some((l) => l.startsWith('bus:')), JSON.stringify(log));
    assert.equal(log.filter((l) => l.startsWith('error:')).length, 2);
});

// The key exists from KEY_DERIVED on, while the encrypted HELLO is still being
// built. The guard must hold in that window, not only once READY is set.
// _encrypt is held on a gate so the window stays open for the injected frame.
async function openKeyDerivedWindow(attackerPassword) {
    const log = [];
    const h = new JarbasHiveMind();
    h.onHiveConnected = () => log.push('connected');
    h.onHiveDisconnected = () => log.push('disconnected');
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onMycroftMessage = (msg) => log.push('bus:' + msg.type);
    // the legacy password handshake is opt-in since #20 (HIVEMIND-CRYPTO-1 §3)
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const clientShake = JSON.parse(ws.sent[ws.sent.length - 1]).payload.envelope;

    const hub = new PasswordHandShake(PASSWORD);
    const { envelope: hubEnvelope } = await hub.generateHandshake();
    hub.receiveHandshake(clientShake);
    const goodKey = await hub.deriveSecret();

    const attacker = new PasswordHandShake(attackerPassword);
    const { envelope: attackerEnvelope } = await attacker.generateHandshake();
    attacker.receiveHandshake(clientShake);
    const attackerKey = await attacker.deriveSecret();

    let release;
    const gate = new Promise((r) => { release = r; });
    const realEncrypt = h._encrypt.bind(h);
    h._encrypt = async (s) => { await gate; return realEncrypt(s); };

    const pending = inject(ws, { msg_type: 'shake', payload: { envelope: hubEnvelope } });
    while (h._state !== 4) await new Promise((r) => setImmediate(r));  // KEY_DERIVED

    await inject(ws, { msg_type: 'shake', payload: { envelope: attackerEnvelope } });
    release();
    await pending;
    return { h, ws, log, goodKey, attackerKey };
}

const sameKey = (a, b) => Buffer.from(a).equals(Buffer.from(b));

test('B3: a plaintext shake in the KEY_DERIVED window cannot replace the session key', async () => {
    const { h, ws, log, goodKey, attackerKey } = await openKeyDerivedWindow(PASSWORD);
    assert.ok(sameKey(h._sessionKey, goodKey), 'the session key was replaced');
    assert.ok(log.some((l) => /^error:.*unencrypted text frame/.test(l)), JSON.stringify(log));

    await inject(ws, await m.encryptAesGcm(attackerKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'attacker.injected' } })));
    assert.ok(!log.includes('bus:attacker.injected'), JSON.stringify(log));
});

test('B4: an injected shake without the password does not leave a deaf connection', async () => {
    const { h, ws, log, goodKey } = await openKeyDerivedWindow('not-the-password');
    assert.ok(sameKey(h._sessionKey, goodKey), 'the session key was replaced');

    await inject(ws, await m.encryptAesGcm(goodKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'speak', data: {} } })));
    assert.ok(log.includes('bus:speak'), JSON.stringify(log));
});

test('legacy session: a binary frame that fails to decrypt is dropped and reported', async () => {
    const { ws, log } = await connectLegacy(true);
    await ws.onmessage({ data: new Uint8Array(48).fill(7).buffer });
    assert.ok(!log.some((l) => l.startsWith('bus:')), JSON.stringify(log));
    assert.equal(log.length, 1, JSON.stringify(log));
    assert.match(log[0], /^error:.*binary frame/);
});

// The earlier window: _sessionKey is only assigned after deriveSecret (PBKDF2)
// resolves. While it runs, _sessionKey is null and _state is HANDSHAKE_SENT, so
// the key guard alone does not hold. These tests inject in that window.
async function startLegacyHandshake(log) {
    const h = new JarbasHiveMind();
    h.onHiveConnected = () => log.push('connected');
    h.onHiveDisconnected = () => log.push('disconnected');
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onMycroftMessage = (msg) => log.push('bus:' + msg.type);
    // the legacy password handshake is opt-in since #20 (HIVEMIND-CRYPTO-1 §3)
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const clientShake = JSON.parse(ws.sent[ws.sent.length - 1]).payload.envelope;
    return { h, ws, clientShake };
}

async function envelopeAndKey(password, clientShake) {
    const peer = new PasswordHandShake(password);
    const { envelope } = await peer.generateHandshake();
    peer.receiveHandshake(clientShake);
    return { envelope, key: await peer.deriveSecret() };
}

async function injectDuringDerive(attackerPassword) {
    const log = [];
    const { h, ws, clientShake } = await startLegacyHandshake(log);
    const hub = await envelopeAndKey(PASSWORD, clientShake);
    const attacker = await envelopeAndKey(attackerPassword, clientShake);

    let release;
    let deriving = false;
    const gate = new Promise((r) => { release = r; });
    const realDerive = h._handshake.deriveSecret.bind(h._handshake);
    h._handshake.deriveSecret = async () => { deriving = true; await gate; return realDerive(); };

    const pending = inject(ws, { msg_type: 'shake', payload: { envelope: hub.envelope } });
    while (!deriving) await new Promise((r) => setImmediate(r));
    assert.equal(h._sessionKey, null, 'the window under test is the one before the key is assigned');

    await inject(ws, { msg_type: 'shake', payload: { envelope: attacker.envelope } });
    release();
    await pending;
    return { h, ws, log, goodKey: hub.key, attackerKey: attacker.key };
}

test('B3 (pre-derive): a plaintext shake while PBKDF2 runs cannot replace the session key', async () => {
    const { h, ws, log, goodKey, attackerKey } = await injectDuringDerive(PASSWORD);
    assert.ok(sameKey(h._sessionKey, goodKey), 'the session key was replaced');
    assert.ok(log.some((l) => /^error:.*handshake frame/.test(l)), JSON.stringify(log));
    assert.equal(log.filter((l) => l === 'connected').length, 1, JSON.stringify(log));

    await inject(ws, await m.encryptAesGcm(attackerKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'attacker.injected' } })));
    assert.ok(!log.includes('bus:attacker.injected'), JSON.stringify(log));
});

test('B4 (pre-derive): a shake without the password while PBKDF2 runs does not leave a deaf connection', async () => {
    const { h, ws, log, goodKey } = await injectDuringDerive('not-the-password');
    assert.ok(sameKey(h._sessionKey, goodKey), 'the session key was replaced');

    await inject(ws, await m.encryptAesGcm(goodKey,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'speak', data: {} } })));
    assert.ok(log.includes('bus:speak'), JSON.stringify(log));
});

test('back-to-back plaintext shakes, nothing stubbed: the first envelope keys the session', async () => {
    const log = [];
    const { h, ws, clientShake } = await startLegacyHandshake(log);
    const hub = await envelopeAndKey(PASSWORD, clientShake);
    const attacker = await envelopeAndKey(PASSWORD, clientShake);

    // two frames handed to the socket handler without awaiting the first
    const first = inject(ws, { msg_type: 'shake', payload: { envelope: hub.envelope } });
    const second = inject(ws, { msg_type: 'shake', payload: { envelope: attacker.envelope } });
    await Promise.all([first, second]);

    assert.ok(sameKey(h._sessionKey, hub.key), 'the session key was replaced');
    assert.equal(log.filter((l) => l === 'connected').length, 1, JSON.stringify(log));
    await inject(ws, await m.encryptAesGcm(attacker.key,
        JSON.stringify({ msg_type: 'bus', payload: { type: 'attacker.injected' } })));
    assert.ok(!log.includes('bus:attacker.injected'), JSON.stringify(log));
});

test('a legacy handshake response during a Noise handshake is refused instead of throwing', async () => {
    const log = [];
    const h = new JarbasHiveMind();
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onHiveConnected = () => log.push('connected');
    // the legacy password handshake is opt-in since #20 (HIVEMIND-CRYPTO-1 §3)
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    // a Noise handshake is in flight and no legacy IV was generated
    h._noiseHandshake = {};
    h._state = 3;
    const peer = new PasswordHandShake(PASSWORD);
    const { envelope } = await peer.generateHandshake();

    await inject(ws, { msg_type: 'shake', payload: { envelope } });  // must not reject

    assert.equal(h._sessionKey, null);
    assert.ok(!log.includes('connected'), JSON.stringify(log));
    assert.ok(log.some((l) => /^error:.*did not ask for/.test(l)), JSON.stringify(log));
});

// A malformed legacy envelope, sent after this client sent its HANDSHAKE. A
// non-string threw in ivFromHsub; an empty or short string reached READY on a
// degenerate salt. Each is refused, with no key and no connection.
for (const [label, envelope] of [['123', 123], ['null', null], ['{}', {}], ['true', true],
                                  ['[]', []], ['""', ''], ['"zz"', 'zz']]) {
    test('a malformed legacy envelope (' + label + ') is refused, not used', async () => {
        const log = [];
        const { h, ws } = await startLegacyHandshake(log);

        await inject(ws, { msg_type: 'shake', payload: { envelope } });  // must not reject

        assert.equal(h._sessionKey, null);
        assert.ok(!log.includes('connected'), JSON.stringify(log));
        assert.ok(log.some((l) => /^error:.*malformed legacy handshake envelope/.test(l)), JSON.stringify(log));
    });
}

test('a malformed envelope does not end the process under --unhandled-rejections=strict', () => {
    const { spawnSync } = require('node:child_process');
    const script = `
        class WS { constructor() { this.sent = []; this.readyState = 1; globalThis.lastWs = this; }
                   send(d) { this.sent.push(d); } close() { this.readyState = 3; } }
        globalThis.WebSocket = WS;
        console.log = () => {}; console.warn = () => {}; console.error = () => {};
        const { JarbasHiveMind } = require(${JSON.stringify(require.resolve('../static/js/hivemind.js'))});
        (async () => {
            const h = new JarbasHiveMind();
            h.onHiveError = () => {};
            h.connect('hub', 5678, 'user', 'key', 'pw', { legacyHub: true });
            const ws = globalThis.lastWs;
            ws.onopen();
            await ws.onmessage({ data: JSON.stringify({ msg_type: 'hello', payload: { node_id: 'n' } }) });
            await ws.onmessage({ data: JSON.stringify({ msg_type: 'shake', payload: { binarize: false } }) });
            ws.onmessage({ data: JSON.stringify({ msg_type: 'shake', payload: { envelope: 123 } }) });  // not awaited
            setTimeout(() => { process.stdout.write('alive'); process.exit(0); }, 300);
        })();
    `;
    const r = spawnSync(process.execPath, ['--unhandled-rejections=strict', '-e', script], { encoding: 'utf8' });
    assert.equal(r.status, 0, 'the process ended: ' + r.stderr);
    assert.equal(r.stdout, 'alive');
});

test('a handshake step that throws keeps the guard set and closes, and connect() clears it', async () => {
    const log = [];
    const { h, ws, clientShake } = await startLegacyHandshake(log);
    const hub = await envelopeAndKey(PASSWORD, clientShake);
    const attacker = await envelopeAndKey(PASSWORD, clientShake);
    h._handshake.deriveSecret = async () => { throw new Error('derive failed'); };

    await inject(ws, { msg_type: 'shake', payload: { envelope: hub.envelope } });  // must not reject

    assert.equal(h._sessionKey, null);
    assert.equal(h._handshakeInProgress, true, 'a failed derivation must not reopen the handler');
    assert.equal(ws.readyState, 3, 'the connection must be closed');
    assert.ok(log.some((l) => /^error:.*handshake failed/.test(l)), JSON.stringify(log));

    // a second frame on the same connection cannot start a fresh handshake
    await inject(ws, { msg_type: 'shake', payload: { envelope: attacker.envelope } });
    assert.equal(h._sessionKey, null);
    assert.ok(!log.includes('connected'), JSON.stringify(log));

    // the legacy password handshake is opt-in since #20 (HIVEMIND-CRYPTO-1 §3)
    h.connect('hub', 5678, 'user', 'key', PASSWORD, { legacyHub: true });
    assert.equal(h._handshakeInProgress, false, 'a new connection starts with the guard clear');
});
