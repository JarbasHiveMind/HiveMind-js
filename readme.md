# HiveMind JS

![logo](./hivemindjs.png)

JavaScript client for HiveMind — Protocol V1.

No external dependencies. Uses the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`crypto.subtle`), available in all modern browsers and Node.js 18+.

## Quick start

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

## API reference

### `connect(host, port, username, accessKey, password)`

Opens a WebSocket connection and runs the Protocol V1 handshake automatically.

| Argument | Type | Description |
|----------|------|-------------|
| `host` | string | Server hostname or IP |
| `port` | number | Server port (default HiveMind port: 5678) |
| `username` | string | Client name / user-agent string |
| `accessKey` | string | Access key issued to the client |
| `password` | string | Shared password for PBKDF2 session-key derivation |

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

To regenerate the cross-language test vectors (requires workspace venv):

```bash
"/home/miro/PycharmProjects/HiveMind Workspace/.venv/bin/python" test/generate_vectors.py
```

## File layout

```
HiveMind-js/
├── static/js/
│   └── hivemind.js          # Main client — Protocol V1
├── test/
│   ├── crypto.test.js       # PasswordHandShake unit tests
│   ├── encryption.test.js   # AES-GCM unit tests
│   ├── handshake.test.js    # State machine integration tests
│   ├── generate_vectors.py  # Python script — regenerates vectors.json
│   └── vectors.json         # Cross-compat test vectors (Python ↔ JS)
├── docs/
│   ├── protocol.md          # HiveMessage wire format reference
│   ├── handshake.md         # Handshake flow and PasswordHandShake spec
│   ├── encryption.md        # Encryption wire format and Web Crypto notes
│   └── binary.md            # Binary/binarize mode: bitstring format, BIN_TYPES, JS API
└── package.json
```
