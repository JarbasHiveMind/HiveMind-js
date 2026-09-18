'use strict';

// The Noise static key is stored in localStorage. The storage key name must
// not carry the access key in clear text: any script on the origin can list
// key names. A key stored under the old name must stay readable, so a client
// that upgrades keeps its pinned identity.
//
// Hex input (psk, noiseStaticKey) must be real hex. Before, a bad digit
// parsed as 0 and an odd length dropped the last digit, with no error.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');

class MockWebSocket {
    constructor(url) { this.url = url; }
    send() {}
    close() {}
}
globalThis.WebSocket = MockWebSocket;

class FakeLocalStorage {
    constructor() { this._map = new Map(); }
    getItem(key) { return this._map.has(key) ? this._map.get(key) : null; }
    setItem(key, value) { this._map.set(key, String(value)); }
    removeItem(key) { this._map.delete(key); }
    keys() { return Array.from(this._map.keys()); }
}

const { JarbasHiveMind } = require('../static/js/hivemind.js');

const ACCESS_KEY = 'ivf1NQSkQNogWYyr';

function withStorage(fn) {
    const storage = new FakeLocalStorage();
    globalThis.localStorage = storage;
    try { return fn(storage); } finally { delete globalThis.localStorage; }
}

describe('Noise static key storage name', () => {
    test('no stored key name contains the access key', () => {
        withStorage((storage) => {
            new JarbasHiveMind().connect('hub.example', 5678, 'user', ACCESS_KEY, 'pw');
            assert.equal(storage.keys().length, 1);
            for (const name of storage.keys()) {
                assert.ok(!name.includes(ACCESS_KEY), 'key name leaks the access key: ' + name);
            }
        });
    });

    test('the name is bound to host, port and access key (no collisions)', () => {
        withStorage((storage) => {
            new JarbasHiveMind().connect('hub.example', 5678, 'user', 'key-A', 'pw');
            new JarbasHiveMind().connect('hub.example', 5678, 'user', 'key-B', 'pw');
            new JarbasHiveMind().connect('hub.example', 5679, 'user', 'key-A', 'pw');
            new JarbasHiveMind().connect('other.example', 5678, 'user', 'key-A', 'pw');
            assert.equal(new Set(storage.keys()).size, 4);
        });
    });

    test('a key stored under the old name is reused and moved to the new name', () => {
        withStorage((storage) => {
            const legacyName = 'hivemind:noise-static-key:hub.example:5678:' + ACCESS_KEY;
            const legacyHex = '42'.repeat(32);
            storage.setItem(legacyName, legacyHex);

            const hm = new JarbasHiveMind();
            hm.connect('hub.example', 5678, 'user', ACCESS_KEY, 'pw');
            assert.equal(Buffer.from(hm._noiseStaticKey).toString('hex'), legacyHex);
            assert.equal(storage.getItem(legacyName), null, 'old name must be removed');
            assert.equal(storage.keys().length, 1);
            assert.equal(storage.getItem(storage.keys()[0]), legacyHex);

            const hm2 = new JarbasHiveMind();
            hm2.connect('hub.example', 5678, 'user', ACCESS_KEY, 'pw');
            assert.equal(Buffer.from(hm2._noiseStaticKey).toString('hex'), legacyHex);
        });
    });

    test('the name digest is SHA-256 of host, port and access key', () => {
        withStorage((storage) => {
            new JarbasHiveMind().connect('hub.example', 5678, 'user', ACCESS_KEY, 'pw');
            const digest = nodeCrypto.createHash('sha256')
                .update(JSON.stringify(['hub.example', '5678', ACCESS_KEY]), 'utf8').digest('hex');
            assert.deepEqual(storage.keys(), ['hivemind:noise-static-key:v2:' + digest]);
        });
    });

    test('the digest is correct for inputs that span several SHA-256 blocks', () => {
        for (const len of [0, 40, 41, 55, 56, 64, 119, 120, 1000]) {
            withStorage((storage) => {
                const host = 'h'.repeat(len);
                new JarbasHiveMind().connect(host, 1, 'user', 'kä', 'pw');
                const digest = nodeCrypto.createHash('sha256')
                    .update(JSON.stringify([host, '1', 'kä']), 'utf8').digest('hex');
                assert.deepEqual(storage.keys(), ['hivemind:noise-static-key:v2:' + digest], 'len ' + len);
            });
        }
    });

    test('a colon in the access key cannot make two hubs share a name', () => {
        withStorage((storage) => {
            new JarbasHiveMind().connect('a', 1, 'user', '2:k', 'pw');
            new JarbasHiveMind().connect('a:1', 2, 'user', 'k', 'pw');
            assert.equal(new Set(storage.keys()).size, 2);
        });
    });
});

describe('Hex option parsing', () => {
    const cases = {
        'a non-hex digit': 'zz' + '00'.repeat(31),
        'an odd length': '0'.repeat(63),
        'a sign character': '+1' + '00'.repeat(31),
        'whitespace': ' 1' + '00'.repeat(31),
    };
    for (const [label, hex] of Object.entries(cases)) {
        test('psk with ' + label + ' is refused', () => {
            assert.throws(() => new JarbasHiveMind().connect('h', 1, 'u', 'k-psk', 'pw', { psk: hex }),
                /hex/i);
        });
        test('noiseStaticKey with ' + label + ' is refused', () => {
            assert.throws(() => new JarbasHiveMind().connect('h', 1, 'u', 'k-static', 'pw',
                { noiseStaticKey: hex }), /hex/i);
        });
    }

    test('valid upper- and lower-case hex is still accepted', () => {
        const hm = new JarbasHiveMind();
        hm.connect('h', 1, 'u', 'k-ok', 'pw', { psk: 'aB'.repeat(32) });
        assert.deepEqual(Array.from(hm._psk), new Array(32).fill(0xab));
    });
});
