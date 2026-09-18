'use strict';

// The authorization query value must survive the hub's decoding. The hub
// (hivemind-websocket-protocol, Tornado get_query_argument) percent-decodes the
// query, so a raw "+" in the base64 token arrives as a space, and then decodes
// the base64 as UTF-8. The token must be UTF-8 base64, percent-encoded.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

let _lastMockWs = null;

class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        _lastMockWs = this;
    }
    send() {}
    close() {}
}

globalThis.WebSocket = MockWebSocket;

const { JarbasHiveMind } = require('../static/js/hivemind.js');

// Decode the way the hub does: form-style query parsing ("+" is a space,
// %XX is percent-decoded), then strict base64, then UTF-8.
function hubDecode(url) {
    const query = url.slice(url.indexOf('?') + 1);
    const value = new URLSearchParams(query).get('authorization');
    assert.match(value, /^[A-Za-z0-9+/]*={0,2}$/, 'token must be strict base64 after decoding');
    return Buffer.from(value, 'base64').toString('utf8');
}

describe('Authorization token encoding', () => {
    test('a token whose base64 contains "+" and "/" reaches the hub unchanged', () => {
        const username = 'ab';
        const accessKey = '~~~?>?';
        const raw = Buffer.from(username + ':' + accessKey, 'utf8').toString('base64');
        assert.ok(raw.includes('+') && raw.includes('/'), 'fixture must exercise "+" and "/"');

        const hm = new JarbasHiveMind();
        hm.connect('hub.example', 5678, username, accessKey, 'pw');
        assert.equal(hubDecode(_lastMockWs.url), username + ':' + accessKey);
    });

    test('a username outside Latin-1 does not throw and decodes as UTF-8', () => {
        const username = 'Jørgen 日本 🐝';
        const accessKey = 'access-key';
        const hm = new JarbasHiveMind();
        assert.doesNotThrow(() => hm.connect('hub.example', 5678, username, accessKey, 'pw'));
        assert.equal(hubDecode(_lastMockWs.url), username + ':' + accessKey);
    });

    test('a plain ASCII token keeps the same base64 value as before', () => {
        const hm = new JarbasHiveMind();
        hm.connect('hub.example', 5678, 'HivemindWebChat', 'ivf1NQSkQNogWYyr', 'pw');
        const expected = Buffer.from('HivemindWebChat:ivf1NQSkQNogWYyr').toString('base64');
        assert.ok(_lastMockWs.url.endsWith('?authorization=' + encodeURIComponent(expected)));
    });
});
