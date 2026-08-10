# HiveMind Wire Protocol

## Connection URL

```
ws://host:port?authorization=BASE64(useragent:key)
wss://host:port?authorization=BASE64(useragent:key)
```

- `useragent`: a human-readable client name (e.g. `"JarbasHivemindJsV0.2"`)
- `key`: the access key issued to the client
- The combined string is Base64-encoded (standard, not URL-safe) and passed as the `authorization` query parameter

Example:
```
ws://localhost:5678?authorization=SmFyYmFzSGl2ZU1pbmRKc1YwLjE6bXlzZWNyZXRrZXk=
```

## HiveMessage JSON format

Every message exchanged over the WebSocket (when not binarized) is a JSON object with the following top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | string | Message type, see table below |
| `payload` | object \| string \| null | Message body; content depends on `msg_type` |
| `metadata` | object | Arbitrary key/value metadata attached to the message |
| `route` | array | Hop list, each entry is `{source, targets}`; tracks message path through the hive |
| `node` | string \| null | Semi-unique node identifier of the sender node |
| `target_site_id` | string \| null | Restrict delivery to a specific site (satellite location) |
| `target_pubkey` | string \| null | Restrict delivery to a specific node identified by public key |
| `source_peer` | string \| null | Peer identifier of the sender (`"name::session_id"` format) |

### Minimal example

```json
{
  "msg_type": "bus",
  "payload": {
    "type": "recognizer_loop:utterance",
    "data": {"utterances": ["hello"]},
    "context": {}
  },
  "metadata": {},
  "route": [],
  "node": null,
  "target_site_id": null,
  "target_pubkey": null,
  "source_peer": null
}
```

## HiveMessageType values

| Value | Enum name | Direction | Description |
|-------|-----------|-----------|-------------|
| `"shake"` | `HANDSHAKE` | both | Crypto handshake negotiation |
| `"hello"` | `HELLO` | both | Node announcement and session sync |
| `"bus"` | `BUS` | both | Inject/receive an OVOS bus message |
| `"shared_bus"` | `SHARED_BUS` | slave→master | Passive sharing of slave device bus traffic |
| `"intercom"` | `INTERCOM` | satellite→satellite | Peer-to-peer message between satellites |
| `"broadcast"` | `BROADCAST` | master→slaves | Deliver message to all directly connected slaves |
| `"propagate"` | `PROPAGATE` | both | Forward to all slaves and masters (flood) |
| `"escalate"` | `ESCALATE` | slave→master | Forward up the authority chain to all masters |
| `"query"` | `QUERY` | slave→master | Like escalate, but stops once a node responds |
| `"cascade"` | `CASCADE` | master→slaves | Like propagate, expects responses from all nodes |
| `"ping"` | `PING` | both | Like cascade, used for network topology mapping |
| `"rendezvous"` | `RENDEZVOUS` | both | Reserved for rendezvous-nodes |
| `"bin"` | `BINARY` | both | Binary data container (payload is raw bytes, not JSON) |

## BUS payload format

When `msg_type` is `"bus"`, the payload is an OVOS/Mycroft message:

```json
{
  "type": "recognizer_loop:utterance",
  "data": {"utterances": ["hello world"]},
  "context": {
    "source": "javascript",
    "destination": "HiveMind",
    "platform": "JarbasHivemindJsV0.2"
  }
}
```

## Protocol versions

| Version | Features |
|---------|----------|
| 0 | JSON only, no handshake, no binary, pre-shared key only |
| 1 | Server-initiated handshake, negotiated cipher/encoding, PBKDF2 session keys |
| 2 | Binary (binarized) message support |

## HELLO payload format

**Server → Client (on connect):**
```json
{
  "pubkey": "<server RSA/PGP public key in ASCII armor>",
  "peer": "ServerName::session-uuid",
  "node_id": "master:0.0.0.0"
}
```

**Client → Server (after handshake completes):**
```json
{
  "pubkey": "<client public key>",
  "session": { "session_id": "...", "site_id": "...", ... },
  "site_id": "living-room"
}
```

## JS client capabilities

The `JarbasHiveMind` class in `static/js/hivemind.js` implements:

| Feature | Supported |
|---------|-----------|
| Protocol V1 (server-initiated handshake) | Yes |
| Password mode (`PasswordHandShake`) | Yes |
| AES-GCM cipher | Yes |
| JSON-HEX encoding | Yes |
| RSA key exchange | No |
| ChaCha20-Poly1305 cipher | No (not in Web Crypto) |
| Binary / binarize mode | Yes |

## HANDSHAKE payload formats

See [handshake.md](./handshake.md) for full handshake flow details.

**Server → Client (handshake request):**
```json
{
  "handshake": true,
  "min_protocol_version": 1,
  "max_protocol_version": 1,
  "binarize": false,
  "preshared_key": false,
  "password": true,
  "crypto_required": true,
  "encodings": ["JSON-HEX", "JSON-B64", "JSON-URLSAFE-B64", "JSON-B32", "JSON-B91", "JSON-Z85B", "JSON-Z85P"],
  "ciphers": ["AES-GCM", "CHACHA20-POLY1305"]
}
```

**Client → Server (handshake response, password mode):**
```json
{
  "binarize": false,
  "encodings": ["JSON-HEX", "JSON-B64"],
  "ciphers": ["AES-GCM"],
  "envelope": "aabbccdd1122...48hexchars"
}
```

**Server → Client (handshake completion):**
```json
{
  "envelope": "eeff00112233...48hexchars",
  "encoding": "JSON-HEX",
  "cipher": "AES-GCM"
}
```

---
[Home](../readme.md) · [Handshake →](handshake.md)
