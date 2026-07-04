# HiveMind JS

![logo](./hivemindjs.png)

JavaScript client for HiveMind — Protocol V1. Runs in the browser and in Node.js 18+.

No external dependencies. Uses the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`crypto.subtle`), available in all modern browsers and Node.js 18+.

## Install

```bash
npm install hivemind-js
```

Or just drop [`static/js/hivemind.js`](static/js/hivemind.js) into a page with a `<script>` tag — there is nothing to build and no runtime dependency.

## Quick start (browser)

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HiveMind JS Demo</title>
    <!-- No extra crypto libraries needed — Web Crypto is built into the browser -->
    <script src="static/js/hivemind.js"></script>
</head>
<body>
<script>
    const hivemind = new JarbasHiveMind();

    // Override event hooks before connecting
    hivemind.onHiveConnected = function () {
        // Fires only after the full handshake completes — not on socket open
        window.alert("Connected to HiveMind!");
    };

    hivemind.onMycroftSpeak = function (mycroft_message) {
        window.alert(mycroft_message.data.utterance);
    };

    hivemind.onHiveDisconnected = function () {
        window.alert("HiveMind connection lost.");
    };

    // connect(host, port, username, accessKey, password)
    // The 5th argument is the V1 shared password used for PBKDF2 key derivation.
    hivemind.connect("127.0.0.1", 5678, "HivemindWebChat", "ivf1NQSkQNogWYyr", "mypassword");

    // sendUtterance / sendMessage are async — safe to call after onHiveConnected fires
    hivemind.onHiveConnected = async function () {
        await hivemind.sendUtterance("tell me a joke");
    };
</script>
</body>
</html>
```

## Quick start (Node.js)

In Node.js, supply a WebSocket implementation on `globalThis` (the client uses the
browser `WebSocket` global). Any standard implementation such as [`ws`](https://www.npmjs.com/package/ws) works:

```javascript
// CommonJS
const { JarbasHiveMind } = require('hivemind-js');
globalThis.WebSocket = require('ws');

// or ESM
// import { JarbasHiveMind } from 'hivemind-js';
// import WebSocket from 'ws';
// globalThis.WebSocket = WebSocket;

const hivemind = new JarbasHiveMind();

hivemind.onHiveConnected = async () => {
    console.log('connected');
    await hivemind.sendUtterance('tell me a joke');
};

hivemind.onMycroftSpeak = (msg) => console.log('speak:', msg.data.utterance);

// connect(host, port, username, accessKey, password)
hivemind.connect('127.0.0.1', 5678, 'HivemindNode', 'ivf1NQSkQNogWYyr', 'mypassword');
```

`ws` is the only dependency Node needs, and only because Node lacks a built-in
`WebSocket` global; the crypto and protocol code have no dependencies at all.

## API reference

### `connect(host, port, username, accessKey, password, options?)`

Opens a WebSocket connection and runs the handshake automatically. When the
server offers protocol v3 (Noise) and a PSK is available, the Noise handshake
is used; otherwise the legacy Protocol V1 handshake runs.

| Argument | Type | Description |
|----------|------|-------------|
| `host` | string | Server hostname or IP |
| `port` | number | Server port (default HiveMind port: 5678) |
| `username` | string | Client name / user-agent string |
| `accessKey` | string | Access key issued to the client |
| `password` | string | Shared password for PBKDF2 session-key derivation |
| `options` | object | Optional — protocol v3 (Noise) settings, see below |

`options` fields (all optional):

| Field | Type | Description |
|-------|------|-------------|
| `psk` | `Uint8Array` or hex string | Provisioned 32-byte Noise PSK — equal to the server's `argon2id(password, SHA-256(node_id))`, computed once on a capable host |
| `serverNoiseKey` | hex string | Pinned server static X25519 public key; enables `KKpsk0` and aborts on mismatch (TOFU pinning) |
| `noiseStaticKey` | `Uint8Array` or hex string | This node's static X25519 private key — persist it to keep a stable node identity across connections |
| `maxProtocolVersion` | number | Cap the negotiated protocol version (default `3`) |

Returns the raw `WebSocket` instance.

### `sendUtterance(utterance)` → `Promise`

Sends a `recognizer_loop:utterance` bus message. Must be called after `onHiveConnected`.

### `sendMessage(hiveMessage)` → `Promise`

Sends an arbitrary pre-built HiveMessage (plain object). Encrypts it with the session key. Throws if called before `onHiveConnected`.

Use `_wrap(msg_type, payload)` to build a correctly-shaped HiveMessage envelope.

### Event hooks

Override these on your instance before calling `connect()`:

| Hook | When it fires |
|------|---------------|
| `onHiveConnected()` | Handshake complete — safe to call `sendMessage` |
| `onHiveDisconnected()` | WebSocket closed |
| `onMycroftMessage(msg)` | Any `bus` message received |
| `onMycroftSpeak(msg)` | `bus` message with type `speak` |
| `onHiveBroadcast(msg)` | `broadcast` message received |
| `onHivePropagate(msg)` | `propagate` message received |
| `onHiveIntercom(msg)` | `intercom` message received |
| `onHivePing(msg)` | `ping` message received |

## Binary / binarize mode

When the server advertises `binarize: true` in its HANDSHAKE, the client opts in and both sides switch to binary WebSocket frames. Every frame is an AES-GCM-encrypted payload using the bitstring wire format.

```javascript
// Sending a raw audio frame
const metadata = { sample_rate: 16000, sample_width: 2 };
const frame = encodeBitstring('bin', wavBytes, metadata, BIN_TYPES.RAW_AUDIO);
await hivemind._sendEncryptedBinary(frame);

// Handling incoming binary frames (e.g. TTS audio)
const orig = hivemind._handleBinaryWsMessage.bind(hivemind);
hivemind._handleBinaryWsMessage = async function(buffer) {
    const decrypted = await decryptAesGcmBin(this._sessionKey, new Uint8Array(buffer));
    const decoded   = await decodeBitstring(decrypted);
    if (decoded.binType === BIN_TYPES.TTS_AUDIO) {
        // play audio...
        return;
    }
    await orig(buffer);
};
```

Available globals (after loading `hivemind.js`): `encodeBitstring`, `decodeBitstring`, `encryptAesGcmBin`, `decryptAesGcmBin`, `BIN_TYPES`.

See [`docs/binary.md`](docs/binary.md) for the full frame layout, bitstring format, and API reference.

## Protocol v3 — Noise handshake

When the server advertises `max_protocol_version >= 3` together with its Noise
`patterns`/`suites`, the client runs an authenticated key exchange built on the
[Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34)
instead of the legacy handshake — see HIVEMIND-CRYPTO-1 §3.4. It provides
mutual static-key authentication, forward secrecy, password authentication
without an offline-attackable artifact on the wire, and transcript binding
(any tampering with the negotiation aborts the handshake).

Web Crypto has no ChaCha20-Poly1305, so this client implements the spec's
optional AES-GCM suite — still with no external dependencies:

- `Noise_XXpsk2_25519_AESGCM_SHA256` — general case (static keys exchanged in
  the handshake, TOFU-then-pin)
- `Noise_KKpsk0_25519_AESGCM_SHA256` — pre-provisioned static keys (pass
  `serverNoiseKey`)

The suite is only selected when the server offers it; a server that only
offers ChaCha20-Poly1305 falls back to the legacy v0–v2 handshake.

After the handshake, **all** session traffic travels as Noise transport
messages (binary WebSocket frames) under per-direction cipher states with
strictly sequential 64-bit counter nonces — replayed, reordered or tampered
messages fail authentication and terminate the session.

### The PSK — provisioning vs password

The shared site password enters the handshake as a 32-byte Noise PSK. The
server derives it as `argon2id(password, SHA-256(node_id))` by default, and
**Web Crypto has no argon2id**, so a browser/Node client is a *constrained*
peer (HIVEMIND-CRYPTO-1 §3.4.4):

- **Provisioned PSK (recommended):** compute the PSK once on a capable host
  and pass it as `options.psk`. With the Python stack:

  ```python
  from poorman_handshake.noise import derive_psk
  psk = derive_psk("site password", node_id="<server node_id>")
  print(psk.hex())  # -> options.psk
  ```

- **Password via PBKDF2:** if the server advertises `PBKDF2` as its PSK KDF in
  the handshake parameters, the client derives
  `PBKDF2-HMAC-SHA256(password, SHA-256(node_id), >=100000, 32)` on-device.

With an argon2id server and no provisioned PSK the client logs a clear
operator error and falls back to the legacy handshake.

Requires `X25519` support in Web Crypto: all modern browsers, Node.js 20+.

## Protocol V1 overview

Connection flow:

```
WebSocket open  →  Server HELLO  →  Server HANDSHAKE (request)
→  Client HANDSHAKE (envelope)  →  Server HANDSHAKE (response + envelope)
→  (both sides derive session key via PBKDF2)
→  Client HELLO (encrypted)  →  onHiveConnected()  →  normal encrypted traffic
```

Key points:
- `onHiveConnected` fires **after** the full handshake, not on WebSocket `open`
- All regular messages are encrypted with AES-GCM (JSON-HEX encoding by default)
- The session key is derived fresh per-connection — the password is never transmitted

See [`docs/handshake.md`](docs/handshake.md), [`docs/encryption.md`](docs/encryption.md), [`docs/protocol.md`](docs/protocol.md), and [`docs/binary.md`](docs/binary.md) for details.

## Running the tests

Requires Node.js 18+. No npm install needed.

```bash
cd HiveMind-js
node --test test/*.test.js
# or via package.json script:
npm test
```

Test suite (~40 tests across 4 files):

| File | What it covers |
|------|----------------|
| `test/crypto.test.js` | `PasswordHandShake`: hSub creation, IV extraction, PBKDF2 key derivation, cross-compat with Python vectors |
| `test/encryption.test.js` | AES-GCM encrypt/decrypt, wire format, Python-vector round-trip |
| `test/handshake.test.js` | Full connection state machine with a `MockWebSocket` |
| `test/binary.test.js` | Bitstring codec, binary encryption, binarize handshake negotiation, binary send/receive |
| `test/noise.test.js` | Protocol v3 Noise handshake: byte-level interop against Python `noiseprotocol` responder fixtures (XXpsk2 + KKpsk0), wrong-PSK/tampered-prologue failure, transport replay rejection, PBKDF2 PSK, client negotiation + v0-v2 fallback |

To regenerate the cross-language test vectors, run `test/generate_vectors.py` in a
Python environment that has `hivemind-bus-client` and `poorman_handshake` installed.
The vectors prove the JS crypto (hSub, PBKDF2 key derivation, AES-GCM, bitstring
encoding) is byte-for-byte identical to the Python reference implementation:

```bash
python3 test/generate_vectors.py
```

The protocol v3 (Noise) vectors are generated separately by
`test/generate_noise_vectors.py`, which drives the Python `noiseprotocol`
library (the engine `poorman_handshake.noise` wraps) as the server-role
responder with fixed keys and records every handshake and transport byte:

```bash
python3 test/generate_noise_vectors.py   # needs: pip install noiseprotocol
```

### Live end-to-end test

This repo ships a self-contained, hermetic interop test under
[`test/e2e/`](test/e2e/). It boots a real Python `hivemind-core` hub on an
in-process loopback transport, launches the Node driver
([`test/e2e/js_e2e_driver.mjs`](test/e2e/js_e2e_driver.mjs)) which loads the actual
`static/js/hivemind.js`, connects over a real WebSocket, performs the full V1
handshake, and sends an encrypted utterance. The Python side then asserts the hub
received that exact utterance with a real session id — so the wire behaviour, not
just the vectors, is verified end to end. No external network or fixed ports.

```bash
# one-time: install the loopback-hub deps (test-only Python packages) and ws
pip install -r test/e2e/requirements.txt
npm install
# run it
npm run test:e2e          # == python3 test/e2e/loopback_hub.py
```

The same scenario also runs in the
[HiveMind test harness](https://github.com/JarbasHiveMind/hivemind-test-harness)
(`tests/test_js_e2e.py`), which drives this client as part of the cross-client
conformance suite.

## File layout

```
HiveMind-js/
├── static/js/
│   └── hivemind.js          # Main client — Protocol V1
├── test/
│   ├── crypto.test.js       # PasswordHandShake unit tests
│   ├── encryption.test.js   # AES-GCM unit tests
│   ├── handshake.test.js    # State machine integration tests
│   ├── binary.test.js       # Bitstring codec + binarize mode tests
│   ├── generate_vectors.py  # Python script — regenerates vectors.json
│   ├── noise.test.js        # protocol v3 Noise interop tests
│   ├── noise_vectors.json   # Noise interop vectors (from Python noiseprotocol)
│   ├── generate_noise_vectors.py  # regenerates noise_vectors.json
│   ├── vectors.json         # Cross-compat test vectors (Python ↔ JS)
│   └── e2e/
│       ├── loopback_hub.py      # Boots a real hivemind-core loopback hub + asserts
│       ├── js_e2e_driver.mjs    # Node driver — connects the real client to the hub
│       └── requirements.txt     # Test-only Python deps for the hub
├── docs/
│   ├── protocol.md          # HiveMessage wire format reference
│   ├── handshake.md         # Handshake flow and PasswordHandShake spec
│   ├── encryption.md        # Encryption wire format and Web Crypto notes
│   ├── binary.md            # Binary/binarize mode: bitstring format, BIN_TYPES, JS API
│   └── e2e.md               # End-to-end interop test: how the hub is provided
└── package.json
```
