// HiveMind Protocol V1 JavaScript client
// Browser-compatible (loaded via <script> tag); Node.js 18+ also supported.
//
// Consumer code keeps the same 5-arg connect() signature as V0:
//   connect(host, port, username, accessKey, password)
// where `password` is now the V1 shared password used for PBKDF2 key derivation.

// ─────────────────────────────────────────────────────────────────────────────
// Byte / hex utilities
// ─────────────────────────────────────────────────────────────────────────────

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return arr;
}

function xorBytes(a, b) {
    const result = new Uint8Array(Math.min(a.length, b.length));
    for (let i = 0; i < result.length; i++) result[i] = a[i] ^ b[i];
    return result;
}

function _randomUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    // Simple fallback for environments without randomUUID
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-GCM encryption helpers  (JSON-HEX encoding — hex strings for all fields)
//
// Binary layout matches Python's hivemind_bus_client.encryption:
//   encrypt_bin returns  nonce(16) + ciphertext + tag(16)
//   JSON output is       {ciphertext, tag, nonce}  all hex-encoded
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Binary AES-GCM helpers  (raw bytes — no hex encoding)
//
// Frame layout:  nonce(16) + ciphertext + tag(16)
// ─────────────────────────────────────────────────────────────────────────────

async function encryptAesGcmBin(keyBytes, plaintextBytes) {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        plaintextBytes
    );
    const buf = new Uint8Array(encrypted);  // ciphertext + tag (tag appended by WebCrypto)
    const result = new Uint8Array(16 + buf.length);
    result.set(nonce);
    result.set(buf, 16);
    return result;
}

async function decryptAesGcmBin(keyBytes, frame) {
    // frame = nonce(16) + ciphertext + tag(16)
    const nonce = frame.slice(0, 16);
    const combined = frame.slice(16);  // ciphertext + tag already concatenated for WebCrypto
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        combined
    );
    return new Uint8Array(decrypted);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bitstring codec — port of hivemind_bus_client.serialization
//
// Wire format (v1, no version header):
//   [0…0] [1] [versioned:1] ([proto:8]) [type:5] [compressed:1]
//   [metalen:8] [meta:metalen*8] ([bintype:4]) [payload…]
//   Leading 0s are padding to align to byte boundary.
// ─────────────────────────────────────────────────────────────────────────────

const MSG_TYPE_TO_INT = {
    shake: 0, bus: 1, shared_bus: 2, broadcast: 3, propagate: 4,
    escalate: 5, hello: 6, query: 7, cascade: 8, ping: 9,
    rendezvous: 10, '3rdparty': 11, bin: 12
};

const INT_TO_MSG_TYPE = Object.fromEntries(
    Object.entries(MSG_TYPE_TO_INT).map(([k, v]) => [v, k])
);

const BIN_TYPES = {
    UNDEFINED: 0, RAW_AUDIO: 1, NUMPY_IMAGE: 2, FILE: 3,
    STT_AUDIO_TRANSCRIBE: 4, STT_AUDIO_HANDLE: 5, TTS_AUDIO: 6
};

// BitWriter — builds a bit array, prepends 0-padding to align, exports Uint8Array
class BitWriter {
    constructor() { this.bits = []; }

    writeUint(value, nBits) {
        for (let i = nBits - 1; i >= 0; i--) {
            this.bits.push((value >> i) & 1);
        }
    }

    writeBytes(uint8Array) {
        for (const byte of uint8Array) {
            this.writeUint(byte, 8);
        }
    }

    toUint8Array() {
        // Prepend 0 bits to align total length to byte boundary
        const pad = (8 - (this.bits.length % 8)) % 8;
        const padded = new Array(pad).fill(0).concat(this.bits);
        const bytes = new Uint8Array(padded.length / 8);
        for (let i = 0; i < bytes.length; i++) {
            let b = 0;
            for (let j = 0; j < 8; j++) {
                b = (b << 1) | padded[i * 8 + j];
            }
            bytes[i] = b;
        }
        return bytes;
    }
}

// BitReader — reads bits from Uint8Array (MSB first)
class BitReader {
    constructor(bytes) {
        this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        this.pos = 0;
    }

    readBit() {
        const byteIdx = this.pos >> 3;
        const bitIdx = 7 - (this.pos & 7);
        this.pos++;
        return (this.bytes[byteIdx] >> bitIdx) & 1;
    }

    readUint(nBits) {
        let val = 0;
        for (let i = 0; i < nBits; i++) {
            val = (val << 1) | this.readBit();
        }
        return val;
    }

    readBytes(nBytes) {
        const result = new Uint8Array(nBytes);
        for (let i = 0; i < nBytes; i++) {
            result[i] = this.readUint(8);
        }
        return result;
    }

    get remaining() {
        return this.bytes.length * 8 - this.pos;
    }
}

// encodeBitstring — port of _get_bitstring_v1; always compressed=false (JS never compresses)
// msgType: string key from MSG_TYPE_TO_INT
// payload: string (for non-bin) or Uint8Array (for bin)
// metadata: plain object (will be JSON-serialized)
// binType: integer (BIN_TYPES value) — only used when msgType === 'bin'
// versioned: boolean — whether to include the 8-bit protocol version field
function encodeBitstring(msgType, payload, metadata, binType, versioned) {
    metadata = metadata !== undefined ? metadata : {};
    binType  = binType  !== undefined ? binType  : 0;
    versioned = !!versioned;

    const w = new BitWriter();
    w.writeUint(1, 1);                  // pad marker
    w.writeUint(versioned ? 1 : 0, 1); // versioned flag
    if (versioned) {
        w.writeUint(1, 8);              // protocol version = 1
    }

    const msgTypeInt = MSG_TYPE_TO_INT[msgType] !== undefined ? MSG_TYPE_TO_INT[msgType] : 11;
    w.writeUint(msgTypeInt, 5);         // msg type
    w.writeUint(0, 1);                  // compressed = false

    const metaBytes = new TextEncoder().encode(JSON.stringify(metadata));
    w.writeUint(metaBytes.length, 8);   // meta length in bytes
    w.writeBytes(metaBytes);            // meta content

    if (msgType === 'bin') {
        w.writeUint(binType, 4);        // binary sub-type
        // payload must be a Uint8Array
        w.writeBytes(payload instanceof Uint8Array ? payload : new Uint8Array(payload));
    } else {
        const payloadBytes = typeof payload === 'string'
            ? new TextEncoder().encode(payload)
            : (payload instanceof Uint8Array ? payload : new Uint8Array(payload));
        w.writeBytes(payloadBytes);
    }

    return w.toUint8Array();
}

// decompressZlib — handles Python zlib format (RFC 1950)
async function decompressZlib(bytes) {
    if (typeof require === 'function') {
        // Node.js
        const zlib = require('zlib');
        return new Uint8Array(zlib.inflateSync(Buffer.from(bytes)));
    }
    // Browser — DecompressionStream('deflate') handles RFC 1950 zlib format
    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    writer.write(bytes);
    writer.close();
    const chunks = [];
    for (;;) {
        const { value, done } = await reader.read();
        if (value) chunks.push(value);
        if (done) break;
    }
    const total = chunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
}

// decodeBitstring — port of decode_bitstring + _decode_bitstring_v1
// Returns { msgType, payload, metadata, binType }
// payload is a string for non-binary types, Uint8Array for 'bin' type
async function decodeBitstring(bytes) {
    const r = new BitReader(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    const totalBits = r.bytes.length * 8;

    // Skip leading 0 bits until the pad marker (first 1 bit)
    let padFound = false;
    while (r.pos < totalBits) {
        if (r.readBit() === 1) { padFound = true; break; }
    }
    if (!padFound) throw new Error('decodeBitstring: pad marker not found');

    const versioned = r.readBit() === 1;
    if (versioned) {
        r.readUint(8); // proto version — consumed but not used (only v1 supported)
    }

    const msgTypeInt = r.readUint(5);
    const msgType = INT_TO_MSG_TYPE[msgTypeInt] || '3rdparty';
    const compressed = r.readBit() === 1;

    const metaLen = r.readUint(8);
    const metaRaw = r.readBytes(metaLen);
    let metadata;
    if (compressed) {
        metadata = JSON.parse(new TextDecoder().decode(await decompressZlib(metaRaw)));
    } else {
        metadata = JSON.parse(new TextDecoder().decode(metaRaw));
    }

    const isBin = msgType === 'bin';
    let binType = 0;
    if (isBin) {
        binType = r.readUint(4);
    }

    // Remaining bits are the payload (always a whole number of bytes)
    const payloadBytes = r.readBytes(Math.floor(r.remaining / 8));

    let payload;
    if (isBin) {
        payload = payloadBytes;
    } else if (compressed) {
        payload = new TextDecoder().decode(await decompressZlib(payloadBytes));
    } else {
        payload = new TextDecoder().decode(payloadBytes);
    }

    return { msgType, payload, metadata, binType };
}

// ─────────────────────────────────────────────────────────────────────────────
// PasswordHandShake — port of poorman_handshake/symmetric/
//
// hSub format (Python reference):
//   hashed  = SHA256(iv_bytes + password_bytes)
//   hsub    = (iv_bytes + hashed).hex()[:48]
//
// Salt for PBKDF2:  XOR(own_iv, peer_iv)   (commutative — both sides match)
// Session key:      PBKDF2-HMAC-SHA256(password, salt, 100000, dklen=32)
// ─────────────────────────────────────────────────────────────────────────────

function PasswordHandShake(password) {
    this.password = password;
    this.iv = null;    // Uint8Array(8) — own IV, set by generateHandshake()
    this.salt = null;  // Uint8Array(8) — XOR of own IV and peer IV
}

PasswordHandShake.prototype.generateIV = function () {
    return crypto.getRandomValues(new Uint8Array(8));
};

PasswordHandShake.prototype.createHsub = async function (iv, hsublen) {
    if (hsublen === undefined) hsublen = 48;
    const pwBytes = new TextEncoder().encode(this.password);
    const input = new Uint8Array(iv.length + pwBytes.length);
    input.set(iv);
    input.set(pwBytes, iv.length);
    const hashBuf = await crypto.subtle.digest('SHA-256', input);
    const hashBytes = new Uint8Array(hashBuf);
    // hsub_bytes = iv(8) + SHA256(iv+pw)(32) = 40 bytes → 80 hex chars, take first hsublen
    const combined = new Uint8Array(iv.length + hashBytes.length);
    combined.set(iv);
    combined.set(hashBytes, iv.length);
    return toHex(combined).slice(0, hsublen);
};

PasswordHandShake.prototype.ivFromHsub = function (hsub) {
    // IV is the first 8 bytes = first 16 hex chars of the hSub
    return fromHex(hsub.slice(0, 16));
};

PasswordHandShake.prototype.matchHsub = async function (hsub) {
    const hsublen = hsub.length;
    if (hsublen < 48 || hsublen > 80) return false;
    const iv = this.ivFromHsub(hsub);
    if (!iv || iv.length === 0) return false;
    const expected = await this.createHsub(iv, hsublen);
    return expected === hsub;
};

// Generates own IV, computes hSub envelope, stores IV on this instance.
PasswordHandShake.prototype.generateHandshake = async function () {
    this.iv = this.generateIV();
    const envelope = await this.createHsub(this.iv);
    return { envelope, iv: this.iv };
};

// Receives peer's hSub envelope; computes salt = XOR(own_iv, peer_iv).
PasswordHandShake.prototype.receiveHandshake = function (theirEnvelope) {
    const theirIV = this.ivFromHsub(theirEnvelope);
    this.salt = xorBytes(this.iv, theirIV);
};

// Derives 32-byte session key from password + salt via PBKDF2-HMAC-SHA256.
PasswordHandShake.prototype.deriveSecret = async function () {
    const pwBytes = new TextEncoder().encode(this.password);
    const baseKey = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: this.salt, iterations: 100000 },
        baseKey,
        256  // 32 bytes
    );
    return new Uint8Array(bits);
};

// ─────────────────────────────────────────────────────────────────────────────
// Connection states
// ─────────────────────────────────────────────────────────────────────────────

const States = {
    DISCONNECTED:    0,
    CONNECTING:      1,
    HELLO_RECEIVED:  2,
    HANDSHAKE_SENT:  3,
    KEY_DERIVED:     4,
    READY:           5
};

// ─────────────────────────────────────────────────────────────────────────────
// JarbasHiveMind — Protocol V1 client
// ─────────────────────────────────────────────────────────────────────────────

function JarbasHiveMind() {
    this._state = States.DISCONNECTED;
    this._password = null;
    this._sessionKey = null;   // Uint8Array(32) — derived after handshake
    this._encoding = 'JSON-HEX';
    this._cipher = 'AES-GCM';
    this._serverPeer = null;
    this._serverNodeId = null;
    this._serverPubKey = null;
    this._handshake = null;    // PasswordHandShake instance
    this._sessionId = null;    // random UUID per connection
    this._binarize = false;    // true after handshake if server+client agree on binary frames
    this._serverSupportsBinarize = false;
    this.ws = null;
}

// ── Public API ────────────────────────────────────────────────────────────────

// Same 5-arg signature as V0 for backward compat; `password` replaces crypto_key.
JarbasHiveMind.prototype.connect = function (host, port, username, accessKey, password) {
    this._password = password;
    this._sessionId = _randomUUID();
    this._handshake = new PasswordHandShake(password);
    this._state = States.DISCONNECTED;
    this._binarize = false;
    this._serverSupportsBinarize = false;

    var authToken = btoa(username + ':' + accessKey);
    var url = 'ws://' + host + ':' + port + '?authorization=' + authToken;
    this.ws = new WebSocket(url);
    this.ws.onopen    = this._onWsOpen.bind(this);
    this.ws.onmessage = this._onWsMessage.bind(this);
    this.ws.onclose   = this._onWsClose.bind(this);
    return this.ws;
};

// Sends an arbitrary HiveMessage after the handshake is complete.
// In binarize mode: encodes as bitstring → binary AES-GCM → ArrayBuffer WS frame.
// Otherwise: JSON → text AES-GCM hex frame.
JarbasHiveMind.prototype.sendMessage = async function (hiveMessage) {
    if (this._state < States.READY) {
        throw new Error('Not connected: handshake not complete');
    }
    if (this._binarize) {
        var payloadStr = JSON.stringify(hiveMessage.payload);
        var frame = encodeBitstring(hiveMessage.msg_type, payloadStr, hiveMessage.metadata || {});
        await this._sendEncryptedBinary(frame);
    } else {
        var encrypted = await this._encrypt(JSON.stringify(hiveMessage));
        this._send(encrypted);
    }
};

// Convenience: build and send a recognizer_loop:utterance bus message.
JarbasHiveMind.prototype.sendUtterance = async function (utterance) {
    var busMsg = {
        type: 'recognizer_loop:utterance',
        data: { utterances: [utterance] },
        context: {
            source: 'javascript',
            destination: 'HiveMind',
            platform: 'JarbasHivemindJsV0.2'
        }
    };
    var hiveMsg = this._wrap('bus', busMsg);
    await this.sendMessage(hiveMsg);
};

// Convenience: stream base64-encoded audio to the hub as a bus message.
// (ported from the V0 client's sendAudioB64, now routed through the V1
// encrypted/handshake send path.)
JarbasHiveMind.prototype.sendAudioB64 = async function (base64) {
    var busMsg = {
        type: 'recognizer_loop:b64_audio',
        data: { audio: base64 },
        context: {
            source: 'javascript',
            destination: 'HiveMind',
            platform: 'JarbasHivemindJsV0.2'
        }
    };
    var hiveMsg = this._wrap('bus', busMsg);
    await this.sendMessage(hiveMsg);
};

// ── Event hooks — override in consumer code ───────────────────────────────────

JarbasHiveMind.prototype.onHiveConnected    = function ()    { console.log('HiveMind connected'); };
JarbasHiveMind.prototype.onHiveDisconnected = function ()    { console.log('HiveMind disconnected'); };
JarbasHiveMind.prototype.onMycroftMessage   = function (msg) { console.log('mycroft message:', msg); };
JarbasHiveMind.prototype.onMycroftSpeak     = function (msg) { console.log('mycroft speak:', msg && msg.data && msg.data.utterance); };
JarbasHiveMind.prototype.onHiveBroadcast    = function (msg) { };
JarbasHiveMind.prototype.onHivePropagate    = function (msg) { };
JarbasHiveMind.prototype.onHiveIntercom     = function (msg) { };
JarbasHiveMind.prototype.onHivePing         = function (msg) { };

// ── WebSocket handlers ────────────────────────────────────────────────────────

JarbasHiveMind.prototype._onWsOpen = function () {
    // Do NOT call onHiveConnected here — wait until state reaches READY.
    this._state = States.CONNECTING;
    // Accept binary frames as ArrayBuffer (not Blob) for cross-env compatibility
    if (this.ws && typeof this.ws.binaryType !== 'undefined') {
        this.ws.binaryType = 'arraybuffer';
    }
};

JarbasHiveMind.prototype._onWsMessage = async function (event) {
    // Binary frame path (post-handshake binarize mode)
    if (event.data instanceof ArrayBuffer) {
        await this._handleBinaryWsMessage(event.data);
        return;
    }

    var msg;
    try {
        msg = JSON.parse(event.data);
    } catch (e) {
        console.error('HiveMind: failed to parse server message', e);
        return;
    }

    if (this._state < States.READY) {
        await this._handleHandshakeMessage(msg);
    } else {
        // Decrypt if the raw frame is an encrypted payload
        if (msg.ciphertext) {
            try {
                var plaintext = await this._decrypt(msg);
                msg = JSON.parse(plaintext);
            } catch (e) {
                console.error('HiveMind: decryption failed', e);
                return;
            }
        }
        this._handleUserMessage(msg);
    }
};

JarbasHiveMind.prototype._onWsClose = function () {
    this._state = States.DISCONNECTED;
    this._sessionKey = null;
    this.onHiveDisconnected();
};

// ── Handshake state machine ───────────────────────────────────────────────────

JarbasHiveMind.prototype._handleHandshakeMessage = async function (msg) {
    var msgType = msg.msg_type;
    var payload = msg.payload || {};

    if (msgType === 'hello') {
        await this._handleServerHello(payload);
    } else if (msgType === 'shake') {
        await this._handleServerHandshake(payload);
    }
};

JarbasHiveMind.prototype._handleServerHello = async function (payload) {
    console.log('HiveMind: HELLO received');
    this._serverPubKey  = payload.pubkey   || null;
    this._serverNodeId  = payload.node_id  || null;
    this._serverPeer    = payload.peer     || null;
    this._state = States.HELLO_RECEIVED;
};

JarbasHiveMind.prototype._handleServerHandshake = async function (payload) {
    if ('envelope' in payload) {
        // Server is responding to our HANDSHAKE with its own envelope
        await this._receiveHandshakeResponse(payload);
    } else {
        // Server is requesting that we start the handshake; store its binarize preference
        this._serverSupportsBinarize = !!payload.binarize;
        console.log('HiveMind: HANDSHAKE request received');
        await this._sendClientHandshake(payload);
    }
};

JarbasHiveMind.prototype._sendClientHandshake = async function (serverPayload) {
    var result = await this._handshake.generateHandshake();
    var hsMsg = this._wrap('shake', {
        envelope:  result.envelope,
        encodings: ['JSON-HEX'],
        ciphers:   ['AES-GCM'],
        binarize:  this._serverSupportsBinarize  // echo server's binarize flag
    });
    this._send(hsMsg);
    this._state = States.HANDSHAKE_SENT;
    console.log('HiveMind: HANDSHAKE sent');
};

JarbasHiveMind.prototype._receiveHandshakeResponse = async function (payload) {
    console.log('HiveMind: HANDSHAKE response received');
    var serverEnvelope = payload.envelope;
    this._encoding = payload.encoding || 'JSON-HEX';
    this._cipher   = payload.cipher   || 'AES-GCM';
    this._binarize = this._serverSupportsBinarize;

    // Compute salt = XOR(own_iv, server_iv) then derive 32-byte session key
    this._handshake.receiveHandshake(serverEnvelope);
    this._sessionKey = await this._handshake.deriveSecret();
    this._state = States.KEY_DERIVED;
    console.log('HiveMind: key derived, size:', this._sessionKey.length * 8, 'bit');

    await this._sendClientHello();
};

JarbasHiveMind.prototype._sendClientHello = async function () {
    var sess = { session_id: this._sessionId };
    var helloPayload = {
        pubkey:  '',
        session: sess,
        site_id: 'browser'
    };
    var hiveMsg = this._wrap('hello', helloPayload);
    // HELLO is sent encrypted (key is now established)
    var encrypted = await this._encrypt(JSON.stringify(hiveMsg));
    this._send(encrypted);
    this._state = States.READY;
    console.log('HiveMind: HELLO sent — Connected');
    this.onHiveConnected();
};

// ── Incoming message dispatch (post-handshake) ────────────────────────────────

JarbasHiveMind.prototype._handleUserMessage = function (msg) {
    var msgType = msg.msg_type;
    if (msgType === 'bus') {
        var mycMsg = msg.payload;
        this.onMycroftMessage(mycMsg);
        if (mycMsg && mycMsg.type === 'speak') {
            this.onMycroftSpeak(mycMsg);
        }
    } else if (msgType === 'broadcast') {
        this.onHiveBroadcast(msg);
    } else if (msgType === 'propagate') {
        this.onHivePropagate(msg);
    } else if (msgType === 'intercom') {
        this.onHiveIntercom(msg);
    } else if (msgType === 'ping') {
        this.onHivePing(msg);
    }
};

// ── Binary WebSocket frame handling ──────────────────────────────────────────

// Handles an incoming binary (ArrayBuffer) WebSocket frame:
// decrypt → decode bitstring → dispatch to _handleUserMessage.
JarbasHiveMind.prototype._handleBinaryWsMessage = async function (buffer) {
    var frame = new Uint8Array(buffer);
    var plaintext;
    try {
        plaintext = await decryptAesGcmBin(this._sessionKey, frame);
    } catch (e) {
        console.error('HiveMind: binary decrypt failed', e);
        return;
    }
    var decoded;
    try {
        decoded = await decodeBitstring(plaintext);
    } catch (e) {
        console.error('HiveMind: bitstring decode failed', e);
        return;
    }
    var msgPayload = decoded.payload;
    if (decoded.msgType !== 'bin' && typeof decoded.payload === 'string') {
        try { msgPayload = JSON.parse(decoded.payload); } catch (_) {}
    }
    var msg = {
        msg_type: decoded.msgType,
        payload:  msgPayload,
        metadata: decoded.metadata
    };
    if (decoded.msgType === 'bin') {
        msg.bin_type = decoded.binType;
    }
    this._handleUserMessage(msg);
};

// Encrypts plaintextBytes with binary AES-GCM and sends as an ArrayBuffer WS frame.
JarbasHiveMind.prototype._sendEncryptedBinary = async function (plaintextBytes) {
    var frame = await encryptAesGcmBin(this._sessionKey, plaintextBytes);
    this.ws.send(frame.buffer);
};

// ── Internal helpers ──────────────────────────────────────────────────────────

JarbasHiveMind.prototype._encrypt = async function (plaintext) {
    return await encryptAesGcm(this._sessionKey, plaintext);
};

JarbasHiveMind.prototype._decrypt = async function (payload) {
    return await decryptAesGcm(this._sessionKey, payload);
};

// Builds a full HiveMessage envelope with all required fields.
JarbasHiveMind.prototype._wrap = function (msgType, payload) {
    return {
        msg_type:        msgType,
        payload:         payload,
        metadata:        {},
        route:           [],
        node:            null,
        target_site_id:  null,
        target_pubkey:   null,
        source_peer:     null
    };
};

JarbasHiveMind.prototype._send = function (obj) {
    this.ws.send(JSON.stringify(obj));
};

// ─────────────────────────────────────────────────────────────────────────────
// Browser globals — expose codec helpers when loaded via <script> tag
// ─────────────────────────────────────────────────────────────────────────────

if (typeof globalThis !== 'undefined') {
    globalThis.encodeBitstring = encodeBitstring;
    globalThis.decodeBitstring = decodeBitstring;
    globalThis.BIN_TYPES = BIN_TYPES;
}

// ─────────────────────────────────────────────────────────────────────────────
// Node.js / CommonJS export
// ─────────────────────────────────────────────────────────────────────────────

if (typeof module !== 'undefined') {
    module.exports = {
        JarbasHiveMind, PasswordHandShake, States,
        encryptAesGcm, decryptAesGcm,
        encryptAesGcmBin, decryptAesGcmBin,
        encodeBitstring, decodeBitstring,
        BIN_TYPES, MSG_TYPE_TO_INT, INT_TO_MSG_TYPE
    };
}
