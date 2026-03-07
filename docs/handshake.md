# HiveMind Handshake Protocol

Protocol V1 uses a server-initiated handshake. `onHiveConnected` fires only after the handshake is fully complete — **not** on WebSocket `open`.

## Full flow (password mode)

```
Client                                          Server
  |                                               |
  |  <-- TCP/WebSocket connect                    |
  |                                               |
  |  <-- HELLO {pubkey, peer, node_id}            |  (server sends first)
  |                                               |
  |  <-- HANDSHAKE {handshake, binarize,          |  (server requests handshake)
  |        preshared_key, password,               |
  |        crypto_required, encodings,            |
  |        ciphers, min/max_protocol_version}     |
  |                                               |
  |  HANDSHAKE {binarize, encodings,  -->         |  (client responds with envelope)
  |    ciphers, envelope}                         |
  |                                               |
  |  <-- HANDSHAKE {envelope, encoding, cipher}   |  (server responds, negotiation done)
  |                                               |
  |  (derive session key on both sides)           |  (derive session key on both sides)
  |                                               |
  |  HELLO {pubkey, session, site_id}  -->        |  (encrypted — handshake complete)
  |                                               |
  |  <onHiveConnected fires here>                 |
  |                                               |
  |  <-- BUS / BROADCAST / etc. (encrypted)       |
  |  BUS / ESCALATE / etc. (encrypted)  -->       |
```

## Step-by-step details

### 1. Server sends HELLO (unencrypted)

```json
{
  "msg_type": "hello",
  "payload": {
    "pubkey": "<server public key>",
    "peer": "HiveMind::xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "node_id": "master:0.0.0.0"
  },
  ...
}
```

Client should save:
- `payload.pubkey` — server's public key (can be used to verify later)
- `payload.node_id` — how the server refers to itself on the OVOS bus

### 2. Server sends HANDSHAKE (unencrypted)

```json
{
  "msg_type": "shake",
  "payload": {
    "handshake": true,
    "min_protocol_version": 1,
    "max_protocol_version": 1,
    "binarize": false,
    "preshared_key": false,
    "password": true,
    "crypto_required": true,
    "encodings": ["JSON-HEX", "JSON-B64", ...],
    "ciphers": ["AES-GCM", "CHACHA20-POLY1305"]
  },
  ...
}
```

Key fields:
- `password: true` — server has a password for this client; use `PasswordHandShake`
- `preshared_key: true` — server has a pre-shared key (Protocol V0 fallback)
- `handshake: false` — no handshake needed (server will accept unencrypted messages)
- `crypto_required: true` — client MUST complete handshake or will be disconnected
- `encodings` / `ciphers` — server's allowed options (client picks from these)

### 3. Client sends HANDSHAKE (unencrypted)

Client generates its hSub envelope and sends cipher/encoding preferences:

```json
{
  "msg_type": "shake",
  "payload": {
    "binarize": false,
    "encodings": ["JSON-HEX"],
    "ciphers": ["AES-GCM"],
    "envelope": "aabbccdd1122334455667788aabbccddeeff00112233445566"
  },
  ...
}
```

- `encodings` / `ciphers`: ordered by client preference; server picks the first it supports
- `envelope`: the client's hSub string (see PasswordHandShake below)

### 4. Server sends HANDSHAKE (unencrypted)

Server generates its own hSub envelope and reports the negotiated cipher/encoding:

```json
{
  "msg_type": "shake",
  "payload": {
    "envelope": "eeff00112233445566778899aabbccddeeff00112233445566",
    "encoding": "JSON-HEX",
    "cipher": "AES-GCM"
  },
  ...
}
```

Both sides now:
1. Verify the other party's envelope (confirms they share the same password)
2. Compute `salt = XOR(client_iv, server_iv)` (IVs extracted from envelopes)
3. Derive `session_key = PBKDF2-HMAC-SHA256(password, salt, 100000)` → 32 bytes

### 5. Client sends HELLO (encrypted)

After deriving the session key, client sends its session info encrypted with the new key:

```json
{
  "msg_type": "hello",
  "payload": {
    "pubkey": "<client public key or empty string>",
    "session": { "session_id": "...", "site_id": "..." },
    "site_id": "my-site"
  },
  ...
}
```

This is the last handshake message. After the server processes it, normal encrypted communication begins.

## PasswordHandShake (hSub protocol)

Source: `poorman_handshake/poorman_handshake/symmetric/`
JS implementation: `static/js/hivemind.js` — `PasswordHandShake` class

### hSub format

An hSub (Hashed Subject) is a hex string:

```
| 8-byte IV (16 hex chars) | SHA256(IV + password) (32 bytes / 64 hex chars) |
```

Trimmed to 48 hex characters by default. The IV is always recoverable from the first 16 chars.

### `PasswordHandShake` class API

#### `new PasswordHandShake(password)`

Creates a new instance. `password` is the shared password string.

#### `generateIV()` → `Uint8Array(8)`

Returns 8 cryptographically random bytes.

#### `async createHsub(iv, hsublen=48)` → `string`

```
hashed    = SHA256(iv_bytes + utf8(password))
hsub_bytes = iv_bytes + hashed          // 8 + 32 = 40 bytes
return hex(hsub_bytes).slice(0, hsublen) // default: 48 hex chars
```

#### `ivFromHsub(hsub)` → `Uint8Array(8)`

Extracts the IV from an hSub: `fromHex(hsub.slice(0, 16))`.

#### `async matchHsub(hsub)` → `boolean`

Recomputes the hSub using the embedded IV and compares. Returns `false` if the password doesn't match or the hSub length is out of range (48–80).

#### `async generateHandshake()` → `{envelope, iv}`

Generates a fresh IV, computes the hSub envelope, stores the IV on the instance:

```javascript
this.iv = this.generateIV();
const envelope = await this.createHsub(this.iv);
return { envelope, iv: this.iv };
```

#### `receiveHandshake(theirEnvelope)`

Extracts the peer's IV from their envelope, computes `salt = XOR(this.iv, theirIV)`, stores it on the instance. Must be called after `generateHandshake()`.

#### `async deriveSecret()` → `Uint8Array(32)`

Derives the 32-byte session key from `this.password` and `this.salt`:

```javascript
PBKDF2-HMAC-SHA256(password, salt, iterations=100000, dklen=32)
```

### Full Web Crypto example

```javascript
const client = new PasswordHandShake('my-shared-password');
const server = new PasswordHandShake('my-shared-password');

// Each side generates its envelope
const { envelope: clientEnvelope } = await client.generateHandshake();
const { envelope: serverEnvelope } = await server.generateHandshake();

// Cross-exchange envelopes, then compute salt on each side
client.receiveHandshake(serverEnvelope);
server.receiveHandshake(clientEnvelope);

// Both calls return the same 32-byte key (XOR is commutative)
const clientKey = await client.deriveSecret();
const serverKey = await server.deriveSecret();
// clientKey deepEquals serverKey ✓
```

## RSA handshake mode (alternative to password)

If `password: false` in the server's HANDSHAKE but `handshake: true`, the server expects RSA key exchange instead. The JS client does not implement RSA mode — it requires password mode (`password: true`).
