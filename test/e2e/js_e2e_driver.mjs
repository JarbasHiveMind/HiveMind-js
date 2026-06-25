#!/usr/bin/env node
/**
 * @file js_e2e_driver.mjs
 * @description Node.js end-to-end driver for the HiveMind JavaScript client.
 *
 * Loads the actual JarbasHiveMind client from this repository, connects to a
 * real (loopback) hivemind-core hub over a real WebSocket, performs the full
 * Protocol V1 password handshake (PBKDF2 session-key derivation), sends an
 * encrypted `recognizer_loop:utterance`, then exits.
 *
 * It is driven by `loopback_hub.py`, which boots the hub and asserts the hub
 * actually received the utterance. The exit code reports the JS side:
 *   0 = connected, handshook and sent successfully
 *   1 = failure (timeout, disconnect, or send error)
 *
 * Usage:
 *   node js_e2e_driver.mjs <hub_url> <name> <key> <password> <utterance>
 *
 * Environment:
 *   HIVEMIND_JS_PATH  override the path to hivemind.js (defaults to this repo)
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// hivemind.js expects a browser-style WebSocket global; Node has none.
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
globalThis.WebSocket = WebSocket;

// Load the real client straight from this repository (../../static/js/hivemind.js),
// unless an explicit override is supplied.
const hivemindPath = process.env.HIVEMIND_JS_PATH
    ? resolve(process.env.HIVEMIND_JS_PATH)
    : resolve(__dirname, '../../static/js/hivemind.js');
const { JarbasHiveMind } = require(hivemindPath);

const args = process.argv.slice(2);
if (args.length < 5) {
    console.error('Usage: js_e2e_driver.mjs <hub_url> <name> <key> <password> <utterance>');
    process.exit(1);
}

const [hubUrl, name, key, password, utterance] = args;
const timeout = 15000;

async function main() {
    const client = new JarbasHiveMind();

    const url = new URL(hubUrl);
    const host = url.hostname;
    const port = parseInt(url.port, 10) || 5678;

    console.log(`[*] Connecting to ${host}:${port} as ${name}`);

    const connectedPromise = new Promise((resolvePromise, reject) => {
        const timer = setTimeout(() => reject(new Error('Handshake timeout')), timeout);
        client.onHiveConnected = () => {
            clearTimeout(timer);
            console.log('[+] Handshake complete, connected');
            resolvePromise();
        };
        client.onHiveDisconnected = () => {
            clearTimeout(timer);
            reject(new Error('Disconnected during handshake'));
        };
    });

    // Triggers HELLO -> HANDSHAKE -> key derivation -> encrypted HELLO.
    client.connect(host, port, name, key, password);
    await connectedPromise;

    console.log(`[*] Sending utterance: "${utterance}"`);
    await client.sendUtterance(utterance);

    // Give the hub a moment to receive and record the message.
    await new Promise(r => setTimeout(r, 1000));

    console.log('[+] Test PASSED: utterance sent successfully');
    client.ws.close();
    process.exit(0);
}

main().catch(err => {
    console.error('[E] Test FAILED:', err.message);
    process.exit(1);
});
