# HiveMind-js — Implementation Status

All Protocol V1 features are implemented and tested. This file records what was done and what remains out of scope or future work.

---

## Completed

### Handshake (Protocol V1)

- [x] Handle server HELLO on connect — save `pubkey`, `node_id`, `peer`
- [x] Handle server HANDSHAKE request — parse `binarize`, `password`, `preshared_key`, `crypto_required`, `encodings`, `ciphers`
- [x] `PasswordHandShake` in JS — `generateIV`, `createHsub`, `ivFromHsub`, `matchHsub`, `receiveHandshake`, `deriveSecret` (PBKDF2-HMAC-SHA256)
- [x] Send client HANDSHAKE with envelope
- [x] Receive server HANDSHAKE response, derive session key
- [x] Send client HELLO (encrypted) — fire `onHiveConnected()` only after this step

### Encryption

- [x] AES-GCM encrypt/decrypt with session key
- [x] JSON-HEX encoding
- [x] Tag handling (Web Crypto: tag is appended to ciphertext by `subtle.encrypt`; split on receive)

### Message format

- [x] Full HiveMessage envelope (`msg_type`, `payload`, `metadata`, `route`, `node`, `target_site_id`, `target_pubkey`, `source_peer`)
- [x] Handler dispatch: `bus` → `onMycroftMessage`/`onMycroftSpeak`; `broadcast` → `onHiveBroadcast`; `propagate` → `onHivePropagate`; `intercom` → `onHiveIntercom`; `ping` → `onHivePing`

### Binary / binarize mode (Protocol V2)

- [x] `BitWriter` / `BitReader` helpers
- [x] `MSG_TYPE_TO_INT` / `INT_TO_MSG_TYPE` maps
- [x] `BIN_TYPES` constant
- [x] `encodeBitstring(msgType, payload, metadata, binType, versioned)` → `Uint8Array`
- [x] `decodeBitstring(bytes)` → `{msgType, payload, metadata, binType}`
- [x] `decompressZlib` — browser (`DecompressionStream`) and Node.js (`zlib.inflateSync`) paths
- [x] `encryptAesGcmBin` / `decryptAesGcmBin` — raw-bytes binary frame (nonce + ciphertext + tag)
- [x] `_sendEncryptedBinary(plaintextBytes)` on `JarbasHiveMind`
- [x] Binarize handshake negotiation (`_serverSupportsBinarize`, `_binarize` flag)
- [x] `_onWsMessage` binary branch → `_handleBinaryWsMessage`
- [x] `_handleBinaryWsMessage` — decrypt + decode + dispatch
- [x] `sendMessage` binary path — encode bitstring → encrypt → `ws.send(arraybuffer)` when `_binarize=true`
- [x] Cross-language test vectors (`test/vectors.json` — `bitstring` key, generated from Python reference)

### Tests (~40 total)

- [x] `test/crypto.test.js` — `PasswordHandShake` unit tests + Python vector cross-check
- [x] `test/encryption.test.js` — AES-GCM wire format + Python vector round-trip
- [x] `test/handshake.test.js` — full connection state machine with `MockWebSocket`
- [x] `test/binary.test.js` — bitstring codec, binary encryption, binarize handshake, send/receive

---

## Not planned / out of scope

- **CHACHA20-POLY1305** — not available in Web Crypto; requires a third-party JS library. The client excludes it from the `ciphers` list it sends.
- **RSA handshake mode** — password mode covers the browser use case. RSA would require generating/loading a key pair.
- **`preshared_key` mode** — handled implicitly (no handshake branch); not tested.

---

Reference docs: `docs/protocol.md`, `docs/handshake.md`, `docs/encryption.md`, `docs/binary.md`
