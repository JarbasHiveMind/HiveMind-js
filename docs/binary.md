# Binary / Binarize Mode

When `binarize: true` is negotiated during the handshake, both sides send and receive raw WebSocket binary frames instead of JSON text. This reduces message overhead and is required for audio streaming.

## Negotiation

The server advertises binary support in its HANDSHAKE request:

```json
{ "binarize": true, "ciphers": ["AES-GCM"], "encodings": ["JSON-HEX"] }
```

The client echoes it back:

```json
{ "binarize": true, "ciphers": ["AES-GCM"], "encodings": ["JSON-HEX"], "envelope": "..." }
```

After the handshake, both sides set `_binarize = true` and switch to binary frames. The client also sets `ws.binaryType = 'arraybuffer'`.

## Binary frame layout

Every binary WebSocket frame is an AES-GCM encrypted payload:

```
| nonce (16 bytes) | ciphertext (variable) | tag (16 bytes) |
```

No JSON wrapper, raw bytes only.

## Bitstring wire format

The **plaintext** inside the encrypted frame uses a compact bit-level serialization:

```
| 0…0 (padding to align to byte boundary) | 1 (pad marker) |
| versioned: 1 bit                         |
| [protocol version: 8 bits]               | (only if versioned=1)
| msg_type: 5 bits                         |
| compressed: 1 bit                        |
| metadata length: 8 bits                  |
| metadata: N bytes (JSON)                 |
| [bin_type: 4 bits]                       | (only if msg_type = bin)
| payload: remaining bytes                 |
```

The leading 1 bit (`pad marker`) terminates the byte-alignment padding. Bits are written MSB-first within each byte.

### Message type encoding

| Value | Name |
|-------|------|
| 0 | `shake` |
| 1 | `bus` |
| 2 | `shared_bus` |
| 3 | `broadcast` |
| 4 | `propagate` |
| 5 | `escalate` |
| 6 | `hello` |
| 7 | `query` |
| 8 | `cascade` |
| 9 | `ping` |
| 10 | `rendezvous` |
| 12 | `bin` |

### Binary sub-types (`bin_type`)

Only present when `msg_type = bin` (value 12):

| Value | Name | Description |
|-------|------|-------------|
| 0 | `UNDEFINED` | Unspecified binary payload |
| 1 | `RAW_AUDIO` | Raw PCM or WAV audio bytes |
| 2 | `NUMPY_IMAGE` | NumPy-serialized image array |
| 3 | `FILE` | Generic file transfer |
| 4 | `STT_AUDIO_TRANSCRIBE` | Audio to transcribe (STT-only) |
| 5 | `STT_AUDIO_HANDLE` | Audio to transcribe and handle (full pipeline) |
| 6 | `TTS_AUDIO` | TTS synthesis output (audio response) |

## JS API

### `encodeBitstring(msgType, payload, metadata, binType, versioned)` → `Uint8Array`

Encodes a message into the bitstring wire format.

```javascript
// Send a bus message as binary
const frame = encodeBitstring('bus', JSON.stringify(myMessage), {});
await hivemind._sendEncryptedBinary(frame);

// Send raw audio
const metadata = { sample_rate: 16000, sample_width: 2 };
const frame = encodeBitstring('bin', wavBytes, metadata, BIN_TYPES.RAW_AUDIO);
await hivemind._sendEncryptedBinary(frame);
```

| Argument | Type | Default |
|----------|------|---------|
| `msgType` | string | required |
| `payload` | `Uint8Array` or `string` | required |
| `metadata` | plain object | `{}` |
| `binType` | number | `BIN_TYPES.UNDEFINED` (0) |
| `versioned` | boolean | `false` |

### `async decodeBitstring(bytes)` → `{msgType, payload, metadata, binType}`

Decodes a bitstring back into its constituent parts.

```javascript
const decoded = await decodeBitstring(decryptedBytes);
console.log(decoded.msgType);   // 'bus' | 'bin' | ...
console.log(decoded.binType);   // 0-6 for bin messages
console.log(decoded.metadata);  // parsed JSON object
// decoded.payload is Uint8Array for binary, TextDecoder for bus
```

Handles incoming `compressed=true` payloads via `decompressZlib`.

### `async encryptAesGcmBin(keyBytes, plaintext)` → `Uint8Array`

Encrypts raw bytes to the binary frame format:

```javascript
const frame = await encryptAesGcmBin(sessionKey, plaintextBytes);
// frame = nonce(16) + ciphertext + tag(16)
ws.send(frame.buffer);
```

### `async decryptAesGcmBin(keyBytes, frame)` → `Uint8Array`

Decrypts a binary frame:

```javascript
const plaintext = await decryptAesGcmBin(sessionKey, new Uint8Array(event.data));
```

### `async _sendEncryptedBinary(plaintextBytes)`

Encrypts and sends raw bytes as a binary WebSocket frame. Requires `_binarize = true` and an established session key.

### `BIN_TYPES` constant

```javascript
const BIN_TYPES = {
    UNDEFINED:             0,
    RAW_AUDIO:             1,
    NUMPY_IMAGE:           2,
    FILE:                  3,
    STT_AUDIO_TRANSCRIBE:  4,
    STT_AUDIO_HANDLE:      5,
    TTS_AUDIO:             6,
};
```

## BitWriter / BitReader (internal)

`BitWriter` and `BitReader` are internal helper classes used by `encodeBitstring` / `decodeBitstring`. They are not part of the public API.

- `BitWriter.writeUint(value, nBits)`, write an unsigned integer using exactly `nBits` bits
- `BitWriter.writeBytes(uint8Array)`, write raw bytes
- `BitWriter.toUint8Array()`, prepend 0-padding to reach byte alignment, return the result
- `BitReader.readUint(nBits)`, read an unsigned integer
- `BitReader.readBytes(nBytes)`, read raw bytes
- `BitReader.remaining`, number of bits left

## Incoming binary frame handling

`JarbasHiveMind._onWsMessage` checks `event.data instanceof ArrayBuffer`. If true, it calls `_handleBinaryWsMessage`, which:

1. Decrypts the frame with `decryptAesGcmBin`
2. Decodes the bitstring with `decodeBitstring`
3. Routes the message: `bus` → `_handleUserMessage`, `bin` → binary payload dispatch

Override `_handleBinaryWsMessage` on your instance to intercept specific binary subtypes (e.g. TTS audio):

```javascript
const orig = hivemind._handleBinaryWsMessage.bind(hivemind);
hivemind._handleBinaryWsMessage = async function(buffer) {
    const bytes     = new Uint8Array(buffer);
    const decrypted = await decryptAesGcmBin(this._sessionKey, bytes);
    const decoded   = await decodeBitstring(decrypted);
    if (decoded.binType === BIN_TYPES.TTS_AUDIO) {
        // handle TTS audio
        return;
    }
    await orig(buffer);
};
```

## Cross-language compatibility

The bitstring format is defined by `hivemind-websocket-client` (`serialization.py`). Test vectors in `test/vectors.json` include a `"bitstring"` key generated by the Python reference:

```bash
# Regenerate all test vectors (including bitstring)
"/path/to/.venv/bin/python" test/generate_vectors.py
```

---
[← Encryption](encryption.md) · [Home](../readme.md) · [End-to-end →](e2e.md)
