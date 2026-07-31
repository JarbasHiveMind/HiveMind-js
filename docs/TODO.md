# HiveMind-js: Implementation Status

All Protocol V1 features are implemented and tested. This file records what was done and what remains out of scope or future work.

---

## Completed

### Handshake (Protocol V1)

- [x] Handle server HELLO on connect, save `pubkey`, `node_id`, `peer`
- [x] Handle server HANDSHAKE request, parse `binarize`, `password`, `preshared_key`, `crypto_required`, `encodings`, `ciphers`
- [x] `PasswordHandShake` in JS, `generateIV`, `createHsub`, `ivFromHsub`, `matchHsub`, `receiveHandshake`, `deriveSecret` (PBKDF2-HMAC-SHA256)
- [x] Send client HANDSHAKE with envelope
- [x] Receive server HANDSHAKE response, derive session key
- [x] Send client HELLO (encrypted), fire `onHiveConnected()` only after this step

### Encryption

- [x] AES-GCM encrypt/decrypt with session key
- [x] JSON-HEX encoding
- [x] Tag handling (Web Crypto appends the tag to ciphertext in `subtle.encrypt`. The client splits it on receive)

### Message format

- [x] Full HiveMessage envelope (`msg_type`, `payload`, `metadata`, `route`, `node`, `target_site_id`, `target_pubkey`, `source_peer`)
- [x] Handler dispatch: `bus` routes to `onMycroftMessage`/`onMycroftSpeak`, `broadcast` to `onHiveBroadcast`, `propagate` to `onHivePropagate`, `intercom` to `onHiveIntercom`, `ping` to `onHivePing`

### Binary / binarize mode (Protocol V2)

- [x] `BitWriter` / `BitReader` helpers
- [x] `MSG_TYPE_TO_INT` / `INT_TO_MSG_TYPE` maps
- [x] `BIN_TYPES` constant
- [x] `encodeBitstring(msgType, payload, metadata, binType, versioned)` → `Uint8Array`
- [x] `decodeBitstring(bytes)` → `{msgType, payload, metadata, binType}`
- [x] `decompressZlib`, browser (`DecompressionStream`) and Node.js (`zlib.inflateSync`) paths
- [x] `encryptAesGcmBin` / `decryptAesGcmBin`, raw-bytes binary frame (nonce + ciphertext + tag)
- [x] `_sendEncryptedBinary(plaintextBytes)` on `JarbasHiveMind`
- [x] Binarize handshake negotiation (`_serverSupportsBinarize`, `_binarize` flag)
- [x] `_onWsMessage` binary branch → `_handleBinaryWsMessage`
- [x] `_handleBinaryWsMessage`, decrypt + decode + dispatch
- [x] `sendMessage` binary path, encode bitstring → encrypt → `ws.send(arraybuffer)` when `_binarize=true`
- [x] Cross-language test vectors (`test/vectors.json`, `bitstring` key, generated from Python reference)

### Tests (~40 total)

- [x] `test/crypto.test.js`, `PasswordHandShake` unit tests + Python vector cross-check
- [x] `test/encryption.test.js`, AES-GCM wire format + Python vector round-trip
- [x] `test/handshake.test.js`, full connection state machine with `MockWebSocket`
- [x] `test/binary.test.js`, bitstring codec, binary encryption, binarize handshake, send/receive

### End-to-end (real hub)

- [x] `test/e2e/loopback_hub.py` + `test/e2e/js_e2e_driver.mjs` drive the real client against a real `hivemind-core` loopback hub over a real WebSocket, and assert the utterance round-trips with a real session id (see `docs/e2e.md`)
- [x] CI job `.github/workflows/e2e.yml` runs the e2e on PRs/pushes to `dev`/`master`

---

## Not planned / out of scope

- **CHACHA20-POLY1305** in Protocol V1 mode: not available in Web Crypto, and needs a third-party JS library. The client excludes it from the `ciphers` list it sends.
- **RSA handshake mode**: password mode covers the browser use case. RSA would need generating and loading a key pair.
- **`preshared_key` mode**: handled implicitly, with no handshake branch, and not tested.

---

Reference docs: `docs/protocol.md`, `docs/handshake.md`, `docs/encryption.md`, `docs/binary.md`

---
[← End-to-end](e2e.md) · [Home](../readme.md)
