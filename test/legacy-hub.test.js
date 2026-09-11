'use strict';

// HIVEMIND-CRYPTO-1 §3: "The handshake is mandatory on every connection: there
// is no cleartext, pre-shared-key, or password alternative and no
// protocol-version ladder to negotiate down." A client must never downgrade to
// the legacy handshake by itself; only an operator explicitly setting
// legacyHub may allow it, and doing so logs one warning naming the removal
// version.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.sent = [];
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        this.closed = false;
        _lastMockWs = this;
    }
    send(data) { this.sent.push(data); }
    close(code, reason) {
        this.closed = true;
        if (this.onclose) this.onclose({ code: code || 1000, reason: reason || '' });
    }
    inject(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        if (this.onmessage) return this.onmessage({ data: str });
        return Promise.resolve();
    }
    triggerOpen() { if (this.onopen) this.onopen(); }
}

globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind, HM_VERSION, HM_LEGACY_HUB_REMOVAL_VERSION } =
    require('../static/js/hivemind.js');

const NO_NOISE_HANDSHAKE_REQUEST = {
    handshake: true, password: true, max_protocol_version: 1,
    encodings: ['JSON-HEX'], ciphers: ['AES-GCM']
};

function connectClient(options) {
    const hm = new JarbasHiveMind();
    hm.connect('localhost', 5678, 'user', 'access-key', 'a-password', options);
    const ws = _lastMockWs;
    ws.triggerOpen();
    return { hm, ws };
}

describe('legacyHub gate', () => {

    test('computed removal version is next major of package.json version', () => {
        const pkg = JSON.parse(
            fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
        assert.equal(HM_VERSION, pkg.version,
            'the hivemind.js version constant must match package.json (no drift)');
        const nextMajor = parseInt(pkg.version.split('.')[0], 10) + 1;
        assert.equal(HM_LEGACY_HUB_REMOVAL_VERSION, nextMajor + '.0.0');
    });

    test('without legacyHub: no legacy shake envelope is sent when the hub cannot do v3', async () => {
        const { hm, ws } = connectClient();
        await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
        const sentBefore = ws.sent.length;
        await ws.inject({ msg_type: 'shake', payload: NO_NOISE_HANDSHAKE_REQUEST });

        // No new outbound envelope with a legacy `envelope` field was sent.
        for (let i = sentBefore; i < ws.sent.length; i++) {
            const msg = JSON.parse(ws.sent[i]);
            assert.ok(!(msg.msg_type === 'shake' && 'envelope' in (msg.payload || {})),
                'a legacy handshake envelope must never be sent without legacyHub');
        }
    });

    test('without legacyHub: the connection is refused and surfaced as an error', async () => {
        const { hm, ws } = connectClient();
        let error = null;
        hm.onHiveError = (err) => { error = err; };
        await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
        await ws.inject({ msg_type: 'shake', payload: NO_NOISE_HANDSHAKE_REQUEST });

        assert.ok(ws.closed, 'the connection must be closed rather than downgraded');
        assert.ok(error, 'onHiveError must be called');
    });

    test('with legacyHub: the legacy handshake proceeds', async () => {
        const { hm, ws } = connectClient({ legacyHub: true });
        await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
        await ws.inject({ msg_type: 'shake', payload: NO_NOISE_HANDSHAKE_REQUEST });

        const msg = JSON.parse(ws.sent[ws.sent.length - 1]);
        assert.equal(msg.msg_type, 'shake');
        assert.ok(typeof msg.payload.envelope === 'string',
            'legacyHub must let the legacy envelope handshake through');
    });

    test('with legacyHub: exactly one warning is logged naming the removal version', async () => {
        const originalWarn = console.warn;
        const warnings = [];
        console.warn = (...args) => { warnings.push(args.join(' ')); };
        try {
            const { hm, ws } = connectClient({ legacyHub: true });
            await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
            await ws.inject({ msg_type: 'shake', payload: NO_NOISE_HANDSHAKE_REQUEST });
        } finally {
            console.warn = originalWarn;
        }
        const legacyWarnings = warnings.filter((w) => w.indexOf('legacyHub is set') !== -1);
        assert.equal(legacyWarnings.length, 1, 'exactly one legacyHub warning per connection');
        assert.ok(legacyWarnings[0].indexOf(HM_LEGACY_HUB_REMOVAL_VERSION) !== -1,
            'the warning must name the computed removal version');
    });

    test('with legacyHub: the warning does not repeat per subsequent message', async () => {
        const originalWarn = console.warn;
        const warnings = [];
        console.warn = (...args) => { warnings.push(args.join(' ')); };
        try {
            const { hm, ws } = connectClient({ legacyHub: true });
            await ws.inject({ msg_type: 'hello', payload: { pubkey: 'pk', node_id: 'n1' } });
            await ws.inject({ msg_type: 'shake', payload: NO_NOISE_HANDSHAKE_REQUEST });
            hm._warnLegacyHub(); // simulate any later call in the same connection
            hm._warnLegacyHub();
        } finally {
            console.warn = originalWarn;
        }
        const legacyWarnings = warnings.filter((w) => w.indexOf('legacyHub is set') !== -1);
        assert.equal(legacyWarnings.length, 1);
    });
});
