'use strict';

// Legacy password handshake: the client must verify the server hSub envelope
// before it derives a key and reports a connection.

const { test } = require('node:test');
const assert = require('node:assert/strict');

let lastWs = null;
class MockWebSocket {
    constructor(url) { this.url = url; this.sent = []; this.readyState = 1; lastWs = this; }
    send(data) { this.sent.push(data); }
    close() { this.readyState = 3; if (this.onclose) this.onclose({ code: 1000 }); }
}
globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind, PasswordHandShake } = require('../static/js/hivemind.js');

const quiet = () => {};
console.log = quiet; console.warn = quiet; console.error = quiet;

function makeClient(log) {
    const h = new JarbasHiveMind();
    h.onHiveConnected = () => log.push('connected');
    h.onHiveDisconnected = () => log.push('disconnected');
    h.onHiveError = (e) => log.push('error:' + e.message);
    h.onMycroftMessage = (m) => log.push('bus:' + m.type);
    return h;
}

const inject = (ws, obj) => ws.onmessage({ data: JSON.stringify(obj) });

async function runHandshake(serverPassword) {
    const log = [];
    const h = makeClient(log);
    h.connect('hub', 5678, 'user', 'key', 'the-client-password', { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const clientShake = JSON.parse(ws.sent[ws.sent.length - 1]);
    const server = new PasswordHandShake(serverPassword);
    const { envelope } = await server.generateHandshake();
    server.receiveHandshake(clientShake.payload.envelope);
    const sentBefore = ws.sent.length;
    await inject(ws, { msg_type: 'shake', payload: { envelope } });
    return { h, ws, log, sentAfterShake: ws.sent.length - sentBefore };
}

test('a server envelope made with the wrong password never reaches onHiveConnected', async () => {
    const { h, log, sentAfterShake } = await runHandshake('a-different-password');
    assert.ok(!log.includes('connected'), 'connected with a wrong-password server: ' + JSON.stringify(log));
    assert.ok(log.some((l) => l.startsWith('error:') && l.includes('does not match the password')), JSON.stringify(log));
    assert.equal(h._sessionKey, null);
    assert.equal(sentAfterShake, 0, 'the client sent HELLO to an unverified server');
});

test('a server envelope made with the correct password still connects', async () => {
    const { h, log, sentAfterShake } = await runHandshake('the-client-password');
    assert.deepEqual(log, ['connected']);
    assert.ok(h._sessionKey && h._sessionKey.length === 32);
    assert.equal(sentAfterShake, 1);
});

test('a malformed server envelope is refused', async () => {
    const log = [];
    const h = makeClient(log);
    h.connect('hub', 5678, 'user', 'key', 'the-client-password', { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    await inject(ws, { msg_type: 'shake', payload: { envelope: 'zz'.repeat(24) } });
    assert.ok(!log.includes('connected'), JSON.stringify(log));
});

// Documents a known limit, not a guarantee: matchHsub proves that an envelope
// matches its own IV under the password, not that the server knows the password.
// A server that echoes the client's envelope passes, and the salt collapses to
// zero. The key is still derived from the password, so the echoing server
// cannot read the traffic. The Python reference (poorman_handshake 2.0.1a1
// match_hsub) behaves the same way.
test('an echo of the client envelope passes the check, with an all-zero salt', async () => {
    const log = [];
    const h = makeClient(log);
    h.connect('hub', 5678, 'user', 'key', 'the-client-password', { legacyHub: true });
    const ws = lastWs;
    ws.onopen();
    await inject(ws, { msg_type: 'hello', payload: { node_id: 'hub-node' } });
    await inject(ws, { msg_type: 'shake', payload: { binarize: false } });
    const clientEnvelope = JSON.parse(ws.sent[ws.sent.length - 1]).payload.envelope;

    await inject(ws, { msg_type: 'shake', payload: { envelope: clientEnvelope } });

    assert.deepEqual(log, ['connected']);
    assert.deepEqual(Array.from(h._handshake.salt), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert.ok(h._sessionKey && h._sessionKey.length === 32);
});
