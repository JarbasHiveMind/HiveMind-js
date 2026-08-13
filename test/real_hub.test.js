'use strict';

// Three ways this client could not talk to a hub that actually exists.
// All three were observed against the live hub at hivemind.openvoiceos.pt.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.sent = [];
        _lastMockWs = this;
    }
    send(data) { this.sent.push(data); }
    close() {}
}

globalThis.WebSocket = MockWebSocket;
const { JarbasHiveMind } = require('../static/js/hivemind.js');

function connect(host, options) {
    const hm = new JarbasHiveMind();
    hm.connect(host, 443, 'user', 'key', 'password', options);
    return _lastMockWs.url;
}

describe('reaching a hub behind TLS', () => {
    test('a wss:// host keeps its scheme', () => {
        // Hardcoding ws:// made every public hub unreachable, and a browser on
        // an HTTPS page refuses a ws:// socket as mixed content.
        const url = connect('wss://hivemind.openvoiceos.pt');
        assert.ok(url.startsWith('wss://hivemind.openvoiceos.pt:443'),
                  `scheme was rewritten: ${url}`);
        assert.ok(!url.includes('ws://wss'), `scheme was doubled: ${url}`);
    });

    test('options.ssl selects wss for a bare host', () => {
        const url = connect('hivemind.openvoiceos.pt', { ssl: true });
        assert.ok(url.startsWith('wss://'), url);
    });

    test('a bare host still defaults to plain ws', () => {
        // Local hubs are the common case and have no certificate.
        const url = connect('127.0.0.1');
        assert.ok(url.startsWith('ws://127.0.0.1:443'), url);
    });
});

describe('hearing the answer', () => {
    function speakSeenFor(type) {
        const hm = new JarbasHiveMind();
        let heard = null;
        hm.onMycroftSpeak = (m) => { heard = m.data.utterance; };
        hm._handleUserMessage({
            msg_type: 'bus',
            payload: { type, data: { utterance: 'Hello world' } },
        });
        return heard;
    }

    test('the spec topic ovos.utterance.speak fires onMycroftSpeak', () => {
        // OVOS-PIPELINE-1 §9.6. This is what a current hub emits, and matching
        // only the legacy name meant the callback never fired at all.
        assert.equal(speakSeenFor('ovos.utterance.speak'), 'Hello world');
    });

    test('the legacy topic speak still fires it', () => {
        assert.equal(speakSeenFor('speak'), 'Hello world');
    });

    test('an unrelated bus message does not', () => {
        assert.equal(speakSeenFor('ovos.utterance.handled'), null);
    });
});

describe('importing the package', () => {
    test('the documented ESM import resolves', () => {
        // package.json advertised an "import" condition pointing at a
        // CommonJS file, so `import { JarbasHiveMind } from 'hivemind-js'`
        // threw "Named export not found".
        const entry = path.join(__dirname, '..', 'static', 'js', 'hivemind.mjs');
        const out = execFileSync(process.execPath, [
            '--input-type=module', '-e',
            `import { JarbasHiveMind } from ${JSON.stringify(entry)};
             if (typeof JarbasHiveMind !== 'function') { throw new Error('not a constructor'); }
             console.log('ok');`,
        ], { encoding: 'utf8' });
        assert.equal(out.trim(), 'ok');
    });
});
