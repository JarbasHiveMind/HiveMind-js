# HiveMind Encryption

After the handshake completes, all messages are encrypted using the negotiated session key, cipher, and encoding. `HELLO` and `HANDSHAKE` (`shake`) messages sent **by the server** are exempt; the client's HELLO is sent encrypted once the key is established.

## Session key

- 32 bytes, derived via PBKDF2-HMAC-SHA256 during the handshake
- See [handshake.md](./handshake.md) for derivation details

## Supported ciphers

### AES-GCM (default)

- Key size: 16, 24, or 32 bytes (handshake always produces 32-byte keys)
- Nonce size: **16 bytes**
- Tag (authentication tag) size: **16 bytes**

### CHACHA20-POLY1305

- Key size: **32 bytes** (required)
- Nonce size: **12 bytes** (per RFC 7539)
- Tag size: **16 bytes**

Note: ChaCha20-Poly1305 is not available natively in the Web Crypto API. It requires a third-party JS library (e.g. `libsodium-wrappers`, `tweetnacl`, or a pure-JS implementation).

## JSON wire format

When not using binary mode, encrypted messages are JSON objects:

```json
{
  "ciphertext": "<encoded bytes>",
  "tag": "<encoded bytes>",
  "nonce": "<encoded bytes>"
}
```

All three fields (`ciphertext`, `tag`, `nonce`) are encoded with the negotiated encoding (default: `JSON-HEX`).

### Encoding order for each message

1. Encrypt plaintext → produces `nonce`, `ciphertext`, `tag` as raw bytes
2. Encode each field using the negotiated encoding
3. JSON-stringify the result and send over the WebSocket

### Decoding order

1. JSON-parse the received message
2. Decode `nonce`, `ciphertext`, `tag` using the negotiated encoding
3. Decrypt `ciphertext` using `nonce` and `tag`

## Supported encodings

The encoding applies to each binary field in the JSON output.

| Value | Encoding |
|-------|----------|
| `JSON-HEX` | Hexadecimal (Base16) — **default** |
| `JSON-B64` | Standard Base64 |
| `JSON-URLSAFE-B64` | URL-safe Base64 |
| `JSON-B32` | Base32 |
| `JSON-B91` | Base91 |
| `JSON-Z85B` | Z85B variant |
| `JSON-Z85P` | Z85P variant |

The client should prefer `JSON-HEX` as it is always available in browsers without extra libraries.

## Binary wire format (binarize mode)

When `binarize: true` is negotiated, the payload is sent as raw WebSocket binary frames:

```
[ nonce (16 or 12 bytes) | ciphertext (variable) | tag (16 bytes) ]
```

No encoding step — raw bytes are sent directly as a WebSocket binary message.

## Web Crypto API compatibility note

The Python side sends a separate `tag` field. The Web Crypto API for AES-GCM **appends the tag to the ciphertext** instead of returning it separately.

This means:

- **When encrypting in JS:** The `ciphertext` from `crypto.subtle.encrypt` already has the 16-byte tag appended. You can either:
  - Omit the `tag` field entirely (Python's `decrypt_from_json` handles this as a fallback by splitting the last 16 bytes off `ciphertext`)
  - Or split the tag off manually: `tag = ciphertext[-16:]`, `ciphertext = ciphertext[:-16]`

- **When decrypting in JS:** If the Python side sends `{ciphertext, tag, nonce}`, you must concatenate `ciphertext + tag` before passing to `crypto.subtle.decrypt`.

### Preferred JS approach for interoperability

For outgoing messages (JS → Python), send both fields to be explicit:

```javascript
// AES-GCM via Web Crypto
const iv = crypto.getRandomValues(new Uint8Array(16));
const encrypted = await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, plaintext);
const encBytes = new Uint8Array(encrypted);
// Web Crypto appends tag to ciphertext
const ciphertext = encBytes.slice(0, -16);
const tag = encBytes.slice(-16);

const message = {
    nonce: toHexString(iv),
    ciphertext: toHexString(ciphertext),
    tag: toHexString(tag)
};
```

For incoming messages (Python → JS), concatenate before decrypting:

```javascript
const nonce = fromHexString(msg.nonce);
const ciphertext = fromHexString(msg.ciphertext);
const tag = msg.tag ? fromHexString(msg.tag) : new Uint8Array(0);
// Web Crypto expects nonce separately; ciphertext+tag concatenated
const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
ciphertextWithTag.set(ciphertext);
ciphertextWithTag.set(tag, ciphertext.length);

const decrypted = await crypto.subtle.decrypt({name: "AES-GCM", iv: nonce}, key, ciphertextWithTag);
```

## Full encryption example (AES-GCM, JSON-HEX)

These are the actual implementations from `static/js/hivemind.js`.

### Encrypting a HiveMessage for sending

```javascript
async function encryptAesGcm(keyBytes, plaintext) {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    // Web Crypto appends the 16-byte GCM tag to the ciphertext buffer
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        new TextEncoder().encode(plaintext)
    );
    const buf = new Uint8Array(encrypted);
    const ciphertext = buf.slice(0, buf.length - 16);
    const tag = buf.slice(buf.length - 16);
    return {
        ciphertext: toHex(ciphertext),
        tag: toHex(tag),
        nonce: toHex(nonce)
    };
}
```

### Decrypting a received message

```javascript
async function decryptAesGcm(keyBytes, payload) {
    let ciphertextBytes = fromHex(payload.ciphertext);
    let tagBytes;
    if (payload.tag) {
        tagBytes = fromHex(payload.tag);
    } else {
        // web-crypto compat: tag appended to ciphertext when tag field is absent
        tagBytes = ciphertextBytes.slice(ciphertextBytes.length - 16);
        ciphertextBytes = ciphertextBytes.slice(0, ciphertextBytes.length - 16);
    }
    const nonce = fromHex(payload.nonce);
    // Web Crypto expects ciphertext + tag concatenated
    const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combined.set(ciphertextBytes);
    combined.set(tagBytes, ciphertextBytes.length);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        combined
    );
    return new TextDecoder().decode(decrypted);
}
```

## Key format

The session key from `PasswordHandShake.deriveSecret()` is a `Uint8Array` of 32 bytes. Pass it directly to `crypto.subtle.importKey` as `"raw"`.
