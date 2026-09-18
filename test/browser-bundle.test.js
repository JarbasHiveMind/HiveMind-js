'use strict';

// A browser bundler must be able to bundle the client. esbuild with
// --platform=browser refuses a require() of a Node built-in module such as
// 'zlib'. The @noble packages are ordinary npm modules and must still resolve.
// A compressed frame (Python zlib, RFC 1950) must still decode in Node.js.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const zlib = require('node:zlib');

const esbuild = require('esbuild');

const { decodeBitstring, MSG_TYPE_TO_INT } = require('../static/js/hivemind.js');

const ENTRY = path.join(__dirname, '..', 'static', 'js', 'hivemind.js');

// Build a compressed WIRE-1 frame the way the Python reference does:
// [pad 0s][1][versioned=0][type:5][compressed=1][metalen:8][meta][payload]
function compressedFrame(msgType, metaObj, payloadStr) {
    const meta = zlib.deflateSync(Buffer.from(JSON.stringify(metaObj)));
    const payload = zlib.deflateSync(Buffer.from(payloadStr));
    const bits = [1, 0];
    const push = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1); };
    push(MSG_TYPE_TO_INT[msgType], 5);
    push(1, 1);
    push(meta.length, 8);
    for (const b of meta) push(b, 8);
    for (const b of payload) push(b, 8);
    const padded = new Array((8 - bits.length % 8) % 8).fill(0).concat(bits);
    const out = new Uint8Array(padded.length / 8);
    for (let i = 0; i < out.length; i++) {
        for (let j = 0; j < 8; j++) out[i] = (out[i] << 1) | padded[i * 8 + j];
    }
    return out;
}

describe('Browser bundle', () => {
    test('esbuild bundles hivemind.js for the browser with no errors', async () => {
        let result;
        try {
            result = await esbuild.build({
                entryPoints: [ENTRY],
                bundle: true,
                platform: 'browser',
                format: 'iife',
                write: false,
                logLevel: 'silent',
            });
        } catch (e) {
            const messages = (e.errors || []).map(m => m.text).join('; ');
            assert.fail('esbuild failed: ' + (messages || e.message));
        }
        assert.deepEqual(result.errors, []);
        const code = result.outputFiles[0].text;
        assert.ok(!/require\(["']zlib["']\)/.test(code), 'bundle must not require zlib');
        assert.ok(code.includes('chacha20poly1305'), '@noble ciphers must be bundled');
    });

    test('a zlib-compressed frame still decodes in Node.js', async () => {
        const payload = JSON.stringify({ type: 'speak', data: { utterance: 'hello '.repeat(20) } });
        const frame = compressedFrame('bus', { source: 'hub' }, payload);
        const decoded = await decodeBitstring(frame);
        assert.equal(decoded.msgType, 'bus');
        assert.deepEqual(decoded.metadata, { source: 'hub' });
        assert.equal(decoded.payload, payload);
    });
});

// Same layout as compressedFrame, with the compressed metadata and payload
// bytes given directly, so a test can hand in a damaged zlib stream.
function rawCompressedFrame(msgType, metaBytes, payloadBytes) {
    const bits = [1, 0];
    const push = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1); };
    push(MSG_TYPE_TO_INT[msgType], 5);
    push(1, 1);
    push(metaBytes.length, 8);
    for (const b of metaBytes) push(b, 8);
    for (const b of payloadBytes) push(b, 8);
    const padded = new Array((8 - bits.length % 8) % 8).fill(0).concat(bits);
    const out = new Uint8Array(padded.length / 8);
    for (let i = 0; i < out.length; i++) {
        for (let j = 0; j < 8; j++) out[i] = (out[i] << 1) | padded[i * 8 + j];
    }
    return out;
}

function malformedFrames() {
    const goodMeta = zlib.deflateSync(Buffer.from(JSON.stringify({ source: 'hub' })));
    const goodPayload = zlib.deflateSync(Buffer.from(JSON.stringify({ type: 'speak', data: { utterance: 'x'.repeat(200) } })));
    const flipLast = (buf) => { const c = Buffer.from(buf); c[c.length - 1] ^= 0xff; return c; };
    return {
        TRUNCATED: rawCompressedFrame('bus', goodMeta, goodPayload.subarray(0, goodPayload.length - 6)),
        CORRUPT: rawCompressedFrame('bus', goodMeta, flipLast(goodPayload)),
        GARBAGE: rawCompressedFrame('bus', goodMeta, Buffer.from('this is not a zlib stream at all')),
        'CORRUPT-META': rawCompressedFrame('bus', flipLast(goodMeta), goodPayload),
    };
}

describe('Malformed compressed frames', () => {
    for (const [label, frame] of Object.entries(malformedFrames())) {
        test(label + ': decodeBitstring rejects with a readable zlib error', async () => {
            await assert.rejects(decodeBitstring(frame), (e) => {
                assert.match(e.message, /zlib decompression failed: \S/);
                return true;
            });
        });
    }

    test('no malformed frame ends the process under --unhandled-rejections=strict', () => {
        const { spawnSync } = require('node:child_process');
        const frames = Object.fromEntries(Object.entries(malformedFrames()).map(([k, v]) => [k, Buffer.from(v).toString('hex')]));
        const script = `
            const { decodeBitstring } = require(${JSON.stringify(ENTRY)});
            const frames = ${JSON.stringify(frames)};
            (async () => {
                for (const hex of Object.values(frames)) {
                    try { await decodeBitstring(Uint8Array.from(Buffer.from(hex, 'hex'))); } catch (_) {}
                }
                setTimeout(() => { process.stdout.write('alive'); process.exit(0); }, 200);
            })();
        `;
        const r = spawnSync(process.execPath, ['--unhandled-rejections=strict', '-e', script], { encoding: 'utf8' });
        assert.equal(r.status, 0, 'the process ended: ' + r.stderr);
        assert.equal(r.stdout, 'alive');
    });
});
