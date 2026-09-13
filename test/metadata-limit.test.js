'use strict';

// WIRE-1 §4.1: the metadata-length field of a binary frame is 8 bits. A
// metadata block longer than 255 bytes must be refused. Before, the length
// wrapped modulo 256 and the frame decoded to wrong metadata and payload.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { encodeBitstring, decodeBitstring, BIN_TYPES } = require('../static/js/hivemind.js');

// JSON.stringify({ k: 'x'.repeat(n) }) is n + 8 bytes
function metaOfBytes(total) {
    const meta = { k: 'x'.repeat(total - 8) };
    assert.equal(new TextEncoder().encode(JSON.stringify(meta)).length, total);
    return meta;
}

describe('Bitstring metadata length limit', () => {
    test('255 bytes of metadata round-trip unchanged', async () => {
        const meta = metaOfBytes(255);
        const payload = new Uint8Array([1, 2, 3, 4]);
        const frame = encodeBitstring('bin', payload, meta, BIN_TYPES.RAW_AUDIO);
        const decoded = await decodeBitstring(frame);
        assert.deepEqual(decoded.metadata, meta);
        assert.deepEqual(Array.from(decoded.payload), [1, 2, 3, 4]);
    });

    test('256 bytes of metadata are refused, not wrapped into a corrupt frame', () => {
        const meta = metaOfBytes(256);
        assert.throws(
            () => encodeBitstring('bin', new Uint8Array([1, 2, 3]), meta, BIN_TYPES.RAW_AUDIO),
            /metadata is 256 bytes/);
    });

    test('multi-byte UTF-8 metadata is measured in bytes, not characters', () => {
        // 124 two-byte characters + 8 bytes of JSON = 256 bytes, 132 characters
        const meta = { k: 'é'.repeat(124) };
        assert.throws(() => encodeBitstring('bus', '{}', meta), /metadata is 256 bytes/);
    });
});
