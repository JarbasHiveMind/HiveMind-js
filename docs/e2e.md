# End-to-end interop test

The unit tests (`test/*.test.js`) prove the crypto and protocol code byte-for-byte
against Python-generated vectors. The end-to-end test goes one step further: it
drives the **actual** client against a **real** `hivemind-core` hub over a real
WebSocket, so the wire behaviour, handshake timing, framing, encryption, message
dispatch, is exercised exactly as it would be against a production hub.

It lives in [`../test/e2e/`](../test/e2e/) and is hermetic: no external network,
no fixed ports, no published registry.

## How the hub is provided

The hub is a genuine `hivemind-core` server, booted on an **in-process loopback
transport** by [`hivescope`](https://github.com/JarbasHiveMind/hivescope), the same
mechanism the HiveMind test harness uses. `loopback_hub.py`:

1. builds a topology with one loopback master (`TopologyBuilder().add_master(use_loopback=True)`),
2. registers a satellite (`name="js-sat"`, `password="js-password"`) allowed to send
   `recognizer_loop:utterance`,
3. starts the hub and reads its bound `ws://127.0.0.1:<random-port>/` URL.

Because the transport is loopback and the port is OS-assigned, the test never touches
the network and never collides on a fixed port.

## What the JS side does

`loopback_hub.py` launches `js_e2e_driver.mjs` as a Node subprocess, passing the hub
URL, name, key, password and an utterance. The driver:

1. polyfills `globalThis.WebSocket` with the [`ws`](https://www.npmjs.com/package/ws)
   package (Node has no browser `WebSocket`),
2. loads the real client from `static/js/hivemind.js` (override with
   `HIVEMIND_JS_PATH`),
3. calls `connect(host, port, name, key, password)` and waits for `onHiveConnected`
  , which only fires after the full Protocol V1 handshake (HELLO → HANDSHAKE →
   PBKDF2 key derivation → encrypted HELLO),
4. calls `sendUtterance(...)` to emit an AES-GCM-encrypted `recognizer_loop:utterance`,
5. exits `0` on success, `1` on any timeout/disconnect/send error.

## What is asserted

After the driver exits, the Python side inspects the hub and asserts:

- the driver exited `0` (the JS handshake + send succeeded),
- the hub received a `recognizer_loop:utterance` from the client,
- the utterance **text** round-tripped intact (proving decrypt + decode on the hub),
- a real `session_id` was propagated in the message context (not the `default`
  fallback).

## Running it

```bash
pip install -r test/e2e/requirements.txt   # hivemind-core, hivescope, bus-client
npm install                                # the ws devDependency
npm run test:e2e                           # == python3 test/e2e/loopback_hub.py
```

It also exposes a pytest entry point (`test_js_client_roundtrip_through_real_hub`)
that skips cleanly when Node or the hub deps are absent, so it can be collected
alongside a Python test suite.

CI runs it on every PR/push to `dev` and `master` via
[`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml).

---
[← Binary](binary.md) · [Home](../readme.md) · [Implementation Status →](TODO.md)
