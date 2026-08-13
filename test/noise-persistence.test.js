'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

// ── MockWebSocket ─────────────────────────────────────────────────────────────
// Same minimal pattern as test/handshake.test.js — no real network needed for
// these tests, which only exercise connect()'s key-persistence bookkeeping and
// the pre-READY close → onHiveError path.

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

    send(data) { this.sent.push(data); }

    triggerOpen()  { if (this.onopen)  this.onopen(); }
    triggerClose(event) { if (this.onclose) this.onclose(event); }
}

globalThis.WebSocket = MockWebSocket;

// ── Fake localStorage ──────────────────────────────────────────────────────────

class FakeLocalStorage {
    constructor() { this._map = new Map(); }
    getItem(key) { return this._map.has(key) ? this._map.get(key) : null; }
    setItem(key, value) { this._map.set(key, value); }
    removeItem(key) { this._map.delete(key); }
}

class ThrowingLocalStorage {
    getItem()  { throw new Error('storage disabled (private mode)'); }
    setItem()  { throw new Error('storage disabled (private mode)'); }
}

const { JarbasHiveMind } = require('../static/js/hivemind.js');

describe('Noise static key persistence', () => {
    test('a stored key is reused on a second connect (browser localStorage path)', () => {
        globalThis.localStorage = new FakeLocalStorage();
        try {
            const hm1 = new JarbasHiveMind();
            hm1.connect('hub.example', 5678, 'user', 'access-key-1', 'pw');
            const firstKey = hm1._noiseStaticKey;
            assert.ok(firstKey instanceof Uint8Array);
            assert.equal(firstKey.length, 32);

            const hm2 = new JarbasHiveMind();
            hm2.connect('hub.example', 5678, 'user', 'access-key-1', 'pw');
            const secondKey = hm2._noiseStaticKey;

            assert.deepEqual(Array.from(secondKey), Array.from(firstKey));
        } finally {
            delete globalThis.localStorage;
        }
    });

    test('different access keys on the same origin do not collide', () => {
        globalThis.localStorage = new FakeLocalStorage();
        try {
            const hmA = new JarbasHiveMind();
            hmA.connect('hub.example', 5678, 'user', 'access-key-A', 'pw');

            const hmB = new JarbasHiveMind();
            hmB.connect('hub.example', 5678, 'user', 'access-key-B', 'pw');

            assert.notDeepEqual(Array.from(hmA._noiseStaticKey), Array.from(hmB._noiseStaticKey));
        } finally {
            delete globalThis.localStorage;
        }
    });

    test('an explicit noiseStaticKey overrides the stored one, and is persisted for later', () => {
        globalThis.localStorage = new FakeLocalStorage();
        try {
            const hm1 = new JarbasHiveMind();
            hm1.connect('hub.example', 5678, 'user', 'access-key-2', 'pw');
            const storedKey = hm1._noiseStaticKey;

            const explicitKey = new Uint8Array(32).fill(0x42);
            const hm2 = new JarbasHiveMind();
            hm2.connect('hub.example', 5678, 'user', 'access-key-2', 'pw', { noiseStaticKey: explicitKey });

            assert.deepEqual(Array.from(hm2._noiseStaticKey), Array.from(explicitKey));
            assert.notDeepEqual(Array.from(hm2._noiseStaticKey), Array.from(storedKey));

            // The explicit key must now be what gets reused, since it was persisted too.
            const hm3 = new JarbasHiveMind();
            hm3.connect('hub.example', 5678, 'user', 'access-key-2', 'pw');
            assert.deepEqual(Array.from(hm3._noiseStaticKey), Array.from(explicitKey));
        } finally {
            delete globalThis.localStorage;
        }
    });

    test('unavailable/throwing localStorage does not break connecting', () => {
        globalThis.localStorage = new ThrowingLocalStorage();
        try {
            const hm = new JarbasHiveMind();
            assert.doesNotThrow(() => {
                hm.connect('hub.example', 5678, 'user', 'access-key-3', 'pw');
            });
            assert.ok(hm._noiseStaticKey instanceof Uint8Array);
            assert.equal(hm._noiseStaticKey.length, 32);
        } finally {
            delete globalThis.localStorage;
        }
    });

    test('Node.js path (no localStorage) reuses a per-process in-memory key', () => {
        assert.equal(typeof globalThis.localStorage, 'undefined');

        const hm1 = new JarbasHiveMind();
        hm1.connect('hub.example', 5678, 'user', 'access-key-node', 'pw');
        const firstKey = hm1._noiseStaticKey;

        const hm2 = new JarbasHiveMind();
        hm2.connect('hub.example', 5678, 'user', 'access-key-node', 'pw');
        const secondKey = hm2._noiseStaticKey;

        assert.deepEqual(Array.from(secondKey), Array.from(firstKey));
    });
});

describe('Pre-READY close is surfaced', () => {
    test('a close before the handshake reaches READY calls onHiveError, not just onHiveDisconnected', () => {
        const hm = new JarbasHiveMind();
        let errorMessage = null;
        let connectedCalled = false;
        hm.onHiveError = (err) => { errorMessage = err && err.message; };
        hm.onHiveConnected = () => { connectedCalled = true; };

        hm.connect('hub.example', 5678, 'user', 'access-key', 'pw');
        const ws = _lastMockWs;
        ws.triggerOpen();

        ws.triggerClose({ code: 1008, reason: 'invalid credentials' });

        assert.ok(errorMessage, 'onHiveError should have been called');
        assert.match(errorMessage, /1008/);
        assert.match(errorMessage, /refused/i);
        assert.equal(connectedCalled, false);
        assert.notEqual(hm._state, undefined);
    });

    test('a close after READY does not call onHiveError (normal disconnect)', () => {
        // We don't run a full handshake here — just assert that the guard is
        // state-based: forcing _state to READY before the close means no
        // spurious error for an ordinary post-handshake disconnect.
        const { States } = require('../static/js/hivemind.js');
        const hm = new JarbasHiveMind();
        let errorCalled = false;
        hm.onHiveError = () => { errorCalled = true; };

        hm.connect('hub.example', 5678, 'user', 'access-key', 'pw');
        const ws = _lastMockWs;
        ws.triggerOpen();
        hm._state = States.READY;

        ws.triggerClose({ code: 1000, reason: 'normal closure' });

        assert.equal(errorCalled, false);
    });
});
