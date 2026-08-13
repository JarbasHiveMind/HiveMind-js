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
    rendezvous: 10, bin: 12
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
    const msgType = INT_TO_MSG_TYPE[msgTypeInt];
    if (msgType === undefined) {
        // WIRE-1 §4.2: reject an unassigned message-type code as malformed.
        // Code 11 was '3rdparty', which is removed; do not reuse it.
        throw new Error(`decodeBitstring: unassigned message type code ${msgTypeInt}`);
    }
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
// Protocol v3 — Noise handshake (HIVEMIND-CRYPTO-1 §3.4)
//
// Implements the Noise Protocol Framework (revision 34). X25519, SHA-256, HMAC
// and AES-256-GCM come from native Web Crypto; ChaCha20-Poly1305 (the DEFAULT
// AEAD) and argon2id (the DEFAULT PSK derivation) come from @noble. Full cipher
// parity with hivemind-core — both suites (HIVEMIND-CRYPTO-1 §3.4.1) across both
// patterns:
//
//   Noise_XXpsk2_25519_ChaChaPoly_SHA256   (DEFAULT, general case)
//   Noise_KKpsk0_25519_ChaChaPoly_SHA256   (DEFAULT, pre-provisioned keys)
//   Noise_XXpsk2_25519_AESGCM_SHA256       (Web-Crypto-native fallback)
//   Noise_KKpsk0_25519_AESGCM_SHA256       (Web-Crypto-native fallback)
//
// ChaChaPoly is preferred (matching the Python client's preference order); the
// suite is negotiated from the server's advertised list. When no mutual suite
// exists the client falls back to the legacy (v0–v2) PasswordHandShake path.
// ─────────────────────────────────────────────────────────────────────────────

// @noble crypto — the primitives Web Crypto lacks: ChaCha20-Poly1305 (AEAD for
// the DEFAULT Noise suite) and argon2id (the DEFAULT PSK derivation). Loaded via
// require() in Node; in the browser a bundle must expose them on
//   globalThis.HiveMindNoble = { chacha20poly1305, argon2id }
// (see the readme "Browser build" note). Both are pure-JS, audited (@noble by
// Paul Miller). When absent (a minimal browser deployment that skipped the
// bundle) the client degrades to the Web-Crypto-only AES-GCM + PBKDF2 subset.
let _chacha20poly1305 = null;
let _argon2id = null;
(function _loadNoble() {
    const g = (typeof globalThis !== 'undefined' && globalThis.HiveMindNoble) || null;
    if (g) { _chacha20poly1305 = g.chacha20poly1305 || null; _argon2id = g.argon2id || null; }
    if ((!_chacha20poly1305 || !_argon2id) && typeof require === 'function') {
        try {
            if (!_chacha20poly1305) _chacha20poly1305 = require('@noble/ciphers/chacha.js').chacha20poly1305;
            if (!_argon2id) _argon2id = require('@noble/hashes/argon2.js').argon2id;
        } catch (_) { /* optional — see note above */ }
    }
})();

const NOISE_PATTERN_XX = 'XXpsk2';
const NOISE_PATTERN_KK = 'KKpsk0';
const NOISE_SUITE_CHACHA = '25519_ChaChaPoly_SHA256'; // default (needs @noble/ciphers)
const NOISE_SUITE_AESGCM = '25519_AESGCM_SHA256';     // Web-Crypto-native fallback

// suites this client can run, in PREFERENCE order (matching the Python client:
// ChaCha20-Poly1305 first, AES-GCM for Web-Crypto-only situations). ChaCha is
// only offered when @noble/ciphers is available; AES-GCM is always available.
const NOISE_SUITES_JS = (_chacha20poly1305
    ? [NOISE_SUITE_CHACHA, NOISE_SUITE_AESGCM]
    : [NOISE_SUITE_AESGCM]);

// transport frame markers (first plaintext byte) — must match
// hivemind_bus_client.noise._FRAME_JSON / _FRAME_BINARY
const NOISE_FRAME_JSON = 0x00;
const NOISE_FRAME_BINARY = 0x01;

function concatBytes() {
    let total = 0;
    for (const a of arguments) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arguments) { out.set(a, off); off += a.length; }
    return out;
}

// canonicalJson — must produce byte-identical output to Python's
//   json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// (used for Noise prologue binding and handshake payloads; both peers must
// serialize the negotiation payloads identically)
function canonicalJson(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(canonicalJson).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function hmacSha256(keyBytes, dataBytes) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}

// Noise HKDF (Noise spec §4.3): chained HMACs, 2 or 3 outputs of 32 bytes
async function noiseHkdf(chainingKey, inputKeyMaterial, numOutputs) {
    const tempKey = await hmacSha256(chainingKey, inputKeyMaterial);
    const out1 = await hmacSha256(tempKey, new Uint8Array([0x01]));
    const out2 = await hmacSha256(tempKey, concatBytes(out1, new Uint8Array([0x02])));
    if (numOutputs === 2) return [out1, out2];
    const out3 = await hmacSha256(tempKey, concatBytes(out2, new Uint8Array([0x03])));
    return [out1, out2, out3];
}

// ── X25519 via Web Crypto ─────────────────────────────────────────────────────
// Private keys are handled as 32 raw bytes and wrapped in a fixed PKCS#8
// prefix for import (Web Crypto only imports raw *public* X25519 keys).

const X25519_PKCS8_PREFIX = fromHex('302e020100300506032b656e04220420');

function x25519GeneratePrivate() {
    return crypto.getRandomValues(new Uint8Array(32));
}

async function _x25519ImportPrivate(rawPriv, extractable) {
    return await crypto.subtle.importKey(
        'pkcs8', concatBytes(X25519_PKCS8_PREFIX, rawPriv),
        { name: 'X25519' }, extractable, ['deriveBits']);
}

function _b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// public key (32 raw bytes) for a raw private key
async function x25519PublicFromPrivate(rawPriv) {
    const key = await _x25519ImportPrivate(rawPriv, true);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return _b64urlToBytes(jwk.x);
}

// X25519 Diffie-Hellman: raw private (32B) x raw public (32B) -> 32B shared
async function x25519(rawPriv, rawPub) {
    const priv = await _x25519ImportPrivate(rawPriv, false);
    const pub = await crypto.subtle.importKey('raw', rawPub, { name: 'X25519' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
    return new Uint8Array(shared);
}

// ── Noise CipherState (AESGCM) ────────────────────────────────────────────────
// Nonce per the Noise spec's AESGCM rules: 12 bytes = 4 zero bytes followed by
// the 64-bit big-endian message counter.  Nonces are implicit (never sent) and
// strictly sequential, giving the v3 session replay resistance (§3.4.5).

class NoiseCipherState {
    constructor(suite) {
        this.suite = suite || NOISE_SUITE_AESGCM;
        this.k = null;      // Uint8Array(32) or null (no key yet)
        this.n = 0n;        // 64-bit message counter
    }

    initializeKey(k) { this.k = k; this.n = 0n; }
    hasKey() { return this.k !== null; }

    _nonce() {
        if (this.n >= 0xFFFFFFFFFFFFFFFFn) {
            // Noise reserved maximum — MUST rekey or reconnect before this
            throw new Error('Noise nonce exhausted');
        }
        const nonce = new Uint8Array(12);
        // 4-byte zero prefix + 64-bit counter. Byte order differs per suite
        // (Noise spec §12): AES-GCM big-endian, ChaCha20-Poly1305 little-endian.
        const littleEndian = this.suite === NOISE_SUITE_CHACHA;
        new DataView(nonce.buffer).setBigUint64(4, this.n, littleEndian);
        return nonce;
    }

    async encryptWithAd(ad, plaintext) {
        if (!this.hasKey()) return plaintext;
        const nonce = this._nonce();
        const aad = ad && ad.length ? ad : undefined;
        let ct;
        if (this.suite === NOISE_SUITE_CHACHA) {
            ct = _chacha20poly1305(this.k, nonce, aad).encrypt(plaintext); // ct || 16-byte tag
        } else {
            const key = await crypto.subtle.importKey('raw', this.k, 'AES-GCM', false, ['encrypt']);
            const params = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
            if (aad) params.additionalData = aad;
            ct = new Uint8Array(await crypto.subtle.encrypt(params, key, plaintext)); // ct || tag
        }
        this.n += 1n;
        return ct;
    }

    async decryptWithAd(ad, ciphertext) {
        if (!this.hasKey()) return ciphertext;
        const nonce = this._nonce();
        const aad = ad && ad.length ? ad : undefined;
        // throws on any AEAD failure — the counter is only advanced on success,
        // and a failed message MUST NOT be retried under another nonce (§3.4.5)
        let pt;
        if (this.suite === NOISE_SUITE_CHACHA) {
            pt = _chacha20poly1305(this.k, nonce, aad).decrypt(ciphertext);
        } else {
            const key = await crypto.subtle.importKey('raw', this.k, 'AES-GCM', false, ['decrypt']);
            const params = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
            if (aad) params.additionalData = aad;
            pt = new Uint8Array(await crypto.subtle.decrypt(params, key, ciphertext));
        }
        this.n += 1n;
        return pt;
    }
}

// ── Noise SymmetricState ──────────────────────────────────────────────────────

class NoiseSymmetricState {
    // protocolName: Uint8Array ; suite: string (selects the AEAD)
    static async create(protocolName, suite) {
        const st = new NoiseSymmetricState();
        st.suite = suite || NOISE_SUITE_AESGCM;
        if (protocolName.length <= 32) {
            st.h = new Uint8Array(32);
            st.h.set(protocolName);
        } else {
            st.h = await sha256(protocolName);
        }
        st.ck = st.h.slice();
        st.cipher = new NoiseCipherState(st.suite);
        return st;
    }

    async mixHash(data) {
        this.h = await sha256(concatBytes(this.h, data));
    }

    async mixKey(ikm) {
        const [ck, tempK] = await noiseHkdf(this.ck, ikm, 2);
        this.ck = ck;
        this.cipher.initializeKey(tempK);
    }

    async mixKeyAndHash(ikm) {
        const [ck, tempH, tempK] = await noiseHkdf(this.ck, ikm, 3);
        this.ck = ck;
        await this.mixHash(tempH);
        this.cipher.initializeKey(tempK);
    }

    async encryptAndHash(plaintext) {
        const ct = await this.cipher.encryptWithAd(this.h, plaintext);
        await this.mixHash(ct);
        return ct;
    }

    async decryptAndHash(ciphertext) {
        const pt = await this.cipher.decryptWithAd(this.h, ciphertext);
        await this.mixHash(ciphertext);
        return pt;
    }

    async split() {
        const [k1, k2] = await noiseHkdf(this.ck, new Uint8Array(0), 2);
        const c1 = new NoiseCipherState(this.suite); c1.initializeKey(k1);
        const c2 = new NoiseCipherState(this.suite); c2.initializeKey(k2);
        return [c1, c2];
    }
}

// ── Noise HandshakeState (initiator role only — the node is always the Noise
//    initiator per HIVEMIND-CRYPTO-1 §3.4.3) ──────────────────────────────────

// message token scripts (Noise spec pattern definitions, psk-modified)
const NOISE_MESSAGE_PATTERNS = {
    // -> e / <- e, ee, s, es, psk / -> s, se
    XXpsk2: { preMessages: [], messages: [['e'], ['e', 'ee', 's', 'es', 'psk'], ['s', 'se']] },
    // pre: -> s, <- s ;  -> psk, e, es, ss / <- e, ee, se
    KKpsk0: { preMessages: ['s', 'rs'], messages: [['psk', 'e', 'es', 'ss'], ['e', 'ee', 'se']] }
};

class NoiseHandshake {
    // opts: { pattern, suite, psk (Uint8Array 32), prologue (Uint8Array),
    //         remoteStaticPub (Uint8Array 32, required for KKpsk0),
    //         staticPriv / ephemeralPriv (Uint8Array 32 — test/persistence hooks) }
    static async create(opts) {
        const hs = new NoiseHandshake();
        hs.pattern = opts.pattern;
        hs.suite = opts.suite;
        if (NOISE_SUITES_JS.indexOf(hs.suite) === -1) {
            throw new Error('unsupported Noise suite: ' + hs.suite);
        }
        const script = NOISE_MESSAGE_PATTERNS[hs.pattern];
        if (!script) throw new Error('unsupported Noise pattern: ' + hs.pattern);
        if (!(opts.psk instanceof Uint8Array) || opts.psk.length !== 32) {
            throw new Error('Noise PSK must be exactly 32 bytes');
        }
        hs.psk = opts.psk;
        hs.messages = script.messages;
        hs.messageIndex = 0;
        hs.protocolName = 'Noise_' + hs.pattern + '_' + hs.suite;

        hs.sPriv = opts.staticPriv || x25519GeneratePrivate();
        hs.sPub = await x25519PublicFromPrivate(hs.sPriv);
        hs.ePriv = opts.ephemeralPriv || null;  // generated lazily on 'e'
        hs.ePub = null;
        hs.rs = opts.remoteStaticPub || null;   // remote static (learned in XX)
        hs.re = null;                            // remote ephemeral

        hs.symmetric = await NoiseSymmetricState.create(
            new TextEncoder().encode(hs.protocolName), hs.suite);
        await hs.symmetric.mixHash(opts.prologue || new Uint8Array(0));

        // pre-messages (KK): initiator's static, then responder's static
        for (const tok of script.preMessages) {
            if (tok === 's') await hs.symmetric.mixHash(hs.sPub);
            else if (tok === 'rs') {
                if (!hs.rs) throw new Error(hs.pattern + ' requires the remote static public key');
                await hs.symmetric.mixHash(hs.rs);
            }
        }

        hs.finished = false;
        hs.handshakeHash = null;
        hs.sendCipher = null;
        hs.recvCipher = null;
        return hs;
    }

    get expectsWrite() { return this.messageIndex % 2 === 0; }  // initiator

    // produce the next handshake message (initiator turn)
    async writeMessage(payload) {
        payload = payload || new Uint8Array(0);
        if (this.finished || !this.expectsWrite) throw new Error('Noise: not our turn to write');
        const parts = [];
        for (const tok of this.messages[this.messageIndex]) {
            if (tok === 'e') {
                if (!this.ePriv) this.ePriv = x25519GeneratePrivate();
                this.ePub = await x25519PublicFromPrivate(this.ePriv);
                parts.push(this.ePub);
                await this.symmetric.mixHash(this.ePub);
                // psk mode: 'e' additionally calls MixKey(e.public_key)
                await this.symmetric.mixKey(this.ePub);
            } else if (tok === 's') {
                parts.push(await this.symmetric.encryptAndHash(this.sPub));
            } else if (tok === 'psk') {
                await this.symmetric.mixKeyAndHash(this.psk);
            } else if (tok === 'ee') {
                await this.symmetric.mixKey(await x25519(this.ePriv, this.re));
            } else if (tok === 'es') {  // initiator: DH(e, rs)
                await this.symmetric.mixKey(await x25519(this.ePriv, this.rs));
            } else if (tok === 'se') {  // initiator: DH(s, re)
                await this.symmetric.mixKey(await x25519(this.sPriv, this.re));
            } else if (tok === 'ss') {
                await this.symmetric.mixKey(await x25519(this.sPriv, this.rs));
            }
        }
        parts.push(await this.symmetric.encryptAndHash(payload));
        this.messageIndex++;
        if (this.messageIndex === this.messages.length) await this._finish();
        return concatBytes.apply(null, parts);
    }

    // consume the peer's handshake message (responder turn)
    async readMessage(data) {
        if (this.finished || this.expectsWrite) throw new Error('Noise: not our turn to read');
        let off = 0;
        for (const tok of this.messages[this.messageIndex]) {
            if (tok === 'e') {
                this.re = data.slice(off, off + 32); off += 32;
                await this.symmetric.mixHash(this.re);
                await this.symmetric.mixKey(this.re);  // psk mode
            } else if (tok === 's') {
                const len = this.symmetric.cipher.hasKey() ? 48 : 32;
                this.rs = await this.symmetric.decryptAndHash(data.slice(off, off + len));
                off += len;
            } else if (tok === 'psk') {
                await this.symmetric.mixKeyAndHash(this.psk);
            } else if (tok === 'ee') {
                await this.symmetric.mixKey(await x25519(this.ePriv, this.re));
            } else if (tok === 'es') {  // initiator: DH(e, rs)
                await this.symmetric.mixKey(await x25519(this.ePriv, this.rs));
            } else if (tok === 'se') {  // initiator: DH(s, re)
                await this.symmetric.mixKey(await x25519(this.sPriv, this.re));
            } else if (tok === 'ss') {
                await this.symmetric.mixKey(await x25519(this.sPriv, this.rs));
            }
        }
        const payload = await this.symmetric.decryptAndHash(data.slice(off));
        this.messageIndex++;
        if (this.messageIndex === this.messages.length) await this._finish();
        return payload;
    }

    async _finish() {
        // Split(): initiator sends with c1, receives with c2
        const [c1, c2] = await this.symmetric.split();
        this.sendCipher = c1;
        this.recvCipher = c2;
        this.handshakeHash = this.symmetric.h;   // channel binding (§3.4.5)
        this.finished = true;
    }
}

// ── Noise transport (post-Split session encryption, §3.4.5) ──────────────────
// Every post-handshake message is a Noise transport message; the first
// plaintext byte tags the inner framing (JSON vs WIRE-1 binary), matching
// hivemind_bus_client.noise.NoiseTransport.

class NoiseTransport {
    constructor(handshake) {
        if (!handshake.finished) throw new Error('Noise handshake not finished');
        this.sendCipher = handshake.sendCipher;
        this.recvCipher = handshake.recvCipher;
        this.remoteStaticKey = handshake.rs ? toHex(handshake.rs) : null;
        this.handshakeHash = handshake.handshakeHash;
    }

    // payload: string (JSON HiveMessage) or Uint8Array (WIRE-1 binary frame)
    async encryptFrame(payload) {
        let plaintext;
        if (typeof payload === 'string') {
            plaintext = concatBytes(new Uint8Array([NOISE_FRAME_JSON]),
                                    new TextEncoder().encode(payload));
        } else {
            plaintext = concatBytes(new Uint8Array([NOISE_FRAME_BINARY]), payload);
        }
        return await this.sendCipher.encryptWithAd(new Uint8Array(0), plaintext);
    }

    // returns a string (JSON frame) or Uint8Array (binary frame);
    // throws on any AEAD failure (tampering / replay / reordering — fatal)
    async decryptFrame(data) {
        const plaintext = await this.recvCipher.decryptWithAd(new Uint8Array(0), data);
        const marker = plaintext[0];
        const body = plaintext.slice(1);
        if (marker === NOISE_FRAME_JSON) return new TextDecoder().decode(body);
        if (marker === NOISE_FRAME_BINARY) return body;
        throw new Error('unknown v3 frame marker: ' + marker);
    }
}

// ── Negotiation + PSK helpers ─────────────────────────────────────────────────

// pick (pattern, suite) from the server's advertised lists; KKpsk0 preferred
// when the remote static key is pinned/provisioned; null when no mutual option
function selectNoiseOptions(serverPatterns, serverSuites, pinnedRemoteKey) {
    // walk OUR preference-ordered list (ChaCha first) so the default suite wins
    // whenever both peers support it, regardless of the server's list order
    const suite = NOISE_SUITES_JS.find(s => (serverSuites || []).indexOf(s) !== -1);
    if (!suite) return null;
    if (pinnedRemoteKey && (serverPatterns || []).indexOf(NOISE_PATTERN_KK) !== -1) {
        return { pattern: NOISE_PATTERN_KK, suite };
    }
    if ((serverPatterns || []).indexOf(NOISE_PATTERN_XX) !== -1) {
        return { pattern: NOISE_PATTERN_XX, suite };
    }
    return null;
}

// prologue per HIVEMIND-CRYPTO-1 §3.4.3: exact server cleartext HELLO payload
// bytes + exact cleartext parameter HANDSHAKE payload bytes + the node's
// selected Noise protocol name (canonical JSON on both sides — matches
// hivemind_bus_client.noise.build_prologue)
function buildNoisePrologue(helloPayload, handshakePayload, protocolName) {
    const enc = new TextEncoder();
    return concatBytes(enc.encode(canonicalJson(helloPayload || {})),
                       enc.encode(canonicalJson(handshakePayload || {})),
                       enc.encode(protocolName));
}

// argon2id PSK derivation — the server's DEFAULT (HIVEMIND-CRYPTO-1 §3.4.4),
// byte-identical to poorman_handshake.noise.derive_psk:
//   PSK = argon2id(password, salt=SHA-256(node_id),
//                  t=3, m=64 MiB, p=1, hashLen=32, version 0x13, type=id)
// This lets a password-configured client derive the SAME PSK as core with NO
// server-side configuration. Requires @noble/hashes (bundled in Node; in the
// browser expose it via globalThis.HiveMindNoble — see the readme).
async function derivePskArgon2(password, nodeId) {
    if (!_argon2id) {
        throw new Error('argon2id unavailable: @noble/hashes not loaded ' +
            '(browser bundle must expose globalThis.HiveMindNoble.argon2id)');
    }
    const salt = await sha256(new TextEncoder().encode(nodeId || ''));
    return _argon2id(new TextEncoder().encode(password), salt,
        { t: 3, m: 64 * 1024, p: 1, dkLen: 32 });
}

// PBKDF2 PSK derivation for constrained peers (HIVEMIND-CRYPTO-1 §3.4.4):
//   PSK = PBKDF2-HMAC-SHA256(password, SHA-256(node_id), iterations, 32)
// Only interoperable when the server derives the PSK the same way (i.e. it
// advertises PBKDF2 as the PSK KDF).  Web Crypto has no argon2id, so with an
// argon2id server (the default) the PSK must be provisioned instead.
async function derivePskPBKDF2(password, nodeId, iterations) {
    iterations = iterations || 100000;
    if (iterations < 100000) iterations = 100000;  // spec floor
    const salt = await sha256(new TextEncoder().encode(nodeId));
    const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
        baseKey, 256);
    return new Uint8Array(bits);
}

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
// Noise static-key persistence (HIVEMIND-CRYPTO-1 §3.4.5: the server pins a
// client's static key on first use, so re-generating it on every connect()
// locks the client out after the very first successful handshake).
//
// Browser: localStorage, keyed by host/port/accessKey so unrelated hubs or
// unrelated access keys on the same origin never collide, and never crash
// the connection when storage is unavailable or throws (private mode,
// disabled storage, quota).
//
// Node.js: there is no localStorage. We keep an in-memory, process-lifetime
// cache instead of silently writing a file into the user's home directory —
// a background client library persisting secret key material to disk without
// being asked is a bigger surprise than "the key is fresh every process
// restart". Callers that want a stable node identity across Node process
// restarts must pass options.noiseStaticKey themselves (loaded from wherever
// they choose to keep it).
// ─────────────────────────────────────────────────────────────────────────────

const _nodeNoiseStaticKeyCache = new Map(); // storageKey -> Uint8Array(32), process lifetime only

function _hasLocalStorage() {
    try {
        return typeof localStorage !== 'undefined' && localStorage !== null;
    } catch (e) {
        return false;
    }
}

function _noiseStorageKey(host, port, accessKey) {
    return 'hivemind:noise-static-key:' + host + ':' + port + ':' + accessKey;
}

function _loadPersistedNoiseStaticKey(key) {
    if (_hasLocalStorage()) {
        try {
            const hex = localStorage.getItem(key);
            return hex ? fromHex(hex) : null;
        } catch (e) {
            console.warn('HiveMind: localStorage unavailable, cannot load persisted Noise static key', e);
            return null;
        }
    }
    return _nodeNoiseStaticKeyCache.has(key) ? _nodeNoiseStaticKeyCache.get(key) : null;
}

function _persistNoiseStaticKey(key, priv) {
    if (_hasLocalStorage()) {
        try {
            localStorage.setItem(key, toHex(priv));
        } catch (e) {
            console.warn('HiveMind: localStorage unavailable, Noise static key will not persist across reloads', e);
        }
        return;
    }
    _nodeNoiseStaticKeyCache.set(key, priv);
}

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

    // protocol v3 (Noise) state
    this._maxProtocolVersion = 3;   // highest protocol version this client offers
    this._psk = null;               // Uint8Array(32) — provisioned Noise PSK
    this._serverNoiseKey = null;    // hex — pinned/provisioned server static key
    this._noiseStaticKey = null;    // Uint8Array(32) — this node's static X25519 private key
    this._serverHelloPayload = null;      // raw payload objects, retained for
    this._serverHandshakePayload = null;  // the Noise prologue (§3.4.3)
    this._noiseHandshake = null;    // NoiseHandshake in flight
    this._noiseTransport = null;    // NoiseTransport after Split()
}

// ── Public API ────────────────────────────────────────────────────────────────

// Same 5-arg signature as V0 for backward compat; `password` replaces crypto_key.
// Optional 6th `options` object enables protocol v3 (Noise):
//   psk:                32-byte Uint8Array or 64-char hex — the provisioned Noise
//                       PSK, equal to the server's argon2id(password, SHA-256(node_id)).
//                       Web Crypto has no argon2id, so against an argon2id server
//                       (the default) the PSK MUST be provisioned this way.
//   serverNoiseKey:     hex — pinned server static X25519 public key; enables the
//                       KKpsk0 pattern and aborts on key mismatch (TOFU pinning).
//   noiseStaticKey:     32-byte Uint8Array or hex — this node's static X25519
//                       private key. Optional: when omitted, the client
//                       reuses (or generates and then persists) a key keyed
//                       by host/port/accessKey — in localStorage in the
//                       browser, in an in-memory process-lifetime cache in
//                       Node.js. An explicitly supplied value always wins
//                       over anything stored, and is persisted for later
//                       connects too. This matters because the server pins
//                       a client's static key on first use (HIVEMIND-CRYPTO-1
//                       §3.4.5): re-generating it every connect() locks the
//                       client out after the first successful handshake.
//   maxProtocolVersion: cap the negotiated protocol version (default 3).
JarbasHiveMind.prototype.connect = function (host, port, username, accessKey, password, options) {
    options = options || {};
    this._password = password;
    this._sessionId = _randomUUID();
    this._handshake = new PasswordHandShake(password);
    this._state = States.DISCONNECTED;
    this._binarize = false;
    this._serverSupportsBinarize = false;

    this._maxProtocolVersion = options.maxProtocolVersion !== undefined ? options.maxProtocolVersion : 3;
    this._psk = typeof options.psk === 'string' ? fromHex(options.psk) : (options.psk || null);
    if (this._psk && this._psk.length !== 32) {
        throw new Error('psk must be exactly 32 bytes');
    }
    this._serverNoiseKey = options.serverNoiseKey || null;
    this._noiseStaticKey = typeof options.noiseStaticKey === 'string'
        ? fromHex(options.noiseStaticKey) : (options.noiseStaticKey || null);
    // Persist/reuse the Noise static key so the client doesn't re-key (and
    // get itself locked out) on every connect(). An explicit option always
    // wins and gets persisted too, so future connects without the option
    // still pick it up.
    var noiseStorageKey = _noiseStorageKey(host, port, accessKey);
    if (this._noiseStaticKey) {
        _persistNoiseStaticKey(noiseStorageKey, this._noiseStaticKey);
    } else {
        var storedNoiseStaticKey = _loadPersistedNoiseStaticKey(noiseStorageKey);
        if (storedNoiseStaticKey) {
            this._noiseStaticKey = storedNoiseStaticKey;
        } else {
            this._noiseStaticKey = x25519GeneratePrivate();
            _persistNoiseStaticKey(noiseStorageKey, this._noiseStaticKey);
        }
    }
    // fixed ephemeral key — deterministic interop tests ONLY, never production
    this._noiseEphemeralKey = typeof options._noiseEphemeralKey === 'string'
        ? fromHex(options._noiseEphemeralKey) : (options._noiseEphemeralKey || null);
    this._serverHelloPayload = null;
    this._serverHandshakePayload = null;
    this._noiseHandshake = null;
    this._noiseTransport = null;

    var authToken = btoa(username + ':' + accessKey);
    // A hardcoded 'ws://' cannot reach any hub behind TLS, and a browser on an
    // HTTPS page refuses a ws:// socket outright as mixed content — so the
    // client could not be used from the one place it exists for. `host` may
    // therefore carry its own scheme ('wss://hive.example.org'); otherwise
    // `options.ssl` picks one, defaulting to plain ws for local hubs.
    var scheme;
    if (/^wss?:\/\//.test(host)) {
        scheme = '';
    } else if (options.ssl) {
        scheme = 'wss://';
    } else {
        scheme = 'ws://';
    }
    var url = scheme + host + ':' + port + '?authorization=' + authToken;
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
    if (this._noiseTransport) {
        // protocol v3: every message is a Noise transport message (§3.4.5)
        var v3frame = await this._noiseTransport.encryptFrame(JSON.stringify(hiveMessage));
        this.ws.send(v3frame.buffer);
        return;
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
            platform: 'JarbasHivemindJsV0.2',
            // Per-connection session — stock hivemind-core rejects bus messages
            // that fall back to the 'default' session for non-admin clients.
            session: { session_id: this._sessionId }
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
            platform: 'JarbasHivemindJsV0.2',
            session: { session_id: this._sessionId }
        }
    };
    var hiveMsg = this._wrap('bus', busMsg);
    await this.sendMessage(hiveMsg);
};

// ── Event hooks — override in consumer code ───────────────────────────────────

JarbasHiveMind.prototype.onHiveConnected    = function ()    { console.log('HiveMind connected'); };
JarbasHiveMind.prototype.onHiveDisconnected = function ()    { console.log('HiveMind disconnected'); };
JarbasHiveMind.prototype.onHiveError        = function (err) { console.error('HiveMind error:', err); };
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

JarbasHiveMind.prototype._onWsClose = function (event) {
    var wasReady = this._state === States.READY;
    var closeCode = event && event.code;
    this._state = States.DISCONNECTED;
    this._sessionKey = null;
    this._noiseHandshake = null;
    this._noiseTransport = null;
    if (!wasReady) {
        // The socket closed before the handshake completed: the hub refused
        // or aborted the connection. Without this, callers see "connected"
        // (from a premature log) and then silence, with no error and no
        // onHiveDisconnected reason to explain it.
        var reason = (event && event.reason) ? (': ' + event.reason) : '';
        var message;
        if (closeCode === 1008) {
            // HIVEMIND-WIRE-1: 1008 (Policy Violation) means the server
            // rejected the credentials/handshake — fatal, not a transient drop.
            message = 'HiveMind connection refused: credentials rejected by server (close code 1008)' + reason;
        } else {
            message = 'HiveMind connection refused before handshake completed (close code ' +
                (closeCode !== undefined ? closeCode : 'unknown') + ')' + reason;
        }
        this.onHiveError(new Error(message));
    }
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
    // exact payload retained for the Noise prologue (§3.4.3)
    this._serverHelloPayload = payload;
    this._state = States.HELLO_RECEIVED;
};

JarbasHiveMind.prototype._handleServerHandshake = async function (payload) {
    if (payload.noise && payload.noise.msg && this._noiseHandshake) {
        // protocol v3: server's Noise handshake message
        await this._receiveNoiseHandshake(payload);
    } else if ('envelope' in payload) {
        // Server is responding to our HANDSHAKE with its own envelope
        await this._receiveHandshakeResponse(payload);
    } else {
        // Server is requesting that we start the handshake; store its binarize preference
        this._serverSupportsBinarize = !!payload.binarize;
        this._serverHandshakePayload = payload;  // Noise prologue binding (§3.4.3)
        console.log('HiveMind: HANDSHAKE request received');
        var psk = await this._resolveNoisePsk(payload);
        if (psk) {
            await this._startNoiseHandshake(payload, psk);
        } else {
            await this._sendClientHandshake(payload);
        }
    }
};

// ── Protocol v3 (Noise) handshake ─────────────────────────────────────────────

// Returns the 32-byte PSK when protocol v3 should be used, else null (legacy
// v0-v2 path).  Version negotiation per HIVEMIND-WIRE-1 §2: both peers operate
// at the highest protocol version both support.
JarbasHiveMind.prototype._resolveNoisePsk = async function (payload) {
    if (this._maxProtocolVersion < 3) return null;
    if ((payload.max_protocol_version || 1) < 3) return null;
    var noiseParams = payload.noise;
    if (!noiseParams || typeof noiseParams !== 'object') return null;
    if (!selectNoiseOptions(noiseParams.patterns, noiseParams.suites, this._serverNoiseKey)) {
        // no mutual pattern/suite -> legacy handshake
        console.warn('HiveMind: no mutual Noise pattern/suite, using legacy handshake');
        return null;
    }
    // 1. provisioned PSK — always interoperates (equals the server's
    //    argon2id(password, SHA-256(node_id)))
    if (this._psk) return this._psk;
    var kdf = noiseParams.kdf || {};
    // 2. password via PBKDF2 — only when the server explicitly advertises PBKDF2
    //    as its PSK KDF (§3.4.4); the KDF params are part of the prologue-bound
    //    payload, so this is downgrade-protected
    if (this._password && (kdf.name === 'PBKDF2' || kdf.name === 'PBKDF2-HMAC-SHA256')) {
        return await derivePskPBKDF2(this._password, this._serverNodeId || '', kdf.iterations);
    }
    // 3. password via argon2id — the server DEFAULT; derives the SAME PSK as
    //    core with no server-side configuration (needs @noble/hashes)
    if (this._password && _argon2id) {
        return await derivePskArgon2(this._password, this._serverNodeId || '');
    }
    // 4. no PSK and argon2id unavailable (minimal browser bundle without @noble)
    console.error(
        'HiveMind: server offers protocol v3 (Noise) but no PSK can be derived. ' +
        'argon2id is unavailable — load @noble/hashes (expose ' +
        'globalThis.HiveMindNoble.argon2id in the browser) or pass ' +
        'connect(..., { psk }) with a 32-byte provisioned PSK. ' +
        'Falling back to the legacy handshake.');
    return null;
};

// §3.4.3 step 3: select pattern/suite, bind the prologue, send Noise message 1
JarbasHiveMind.prototype._startNoiseHandshake = async function (payload, psk) {
    var noiseParams = payload.noise;
    var sel = selectNoiseOptions(noiseParams.patterns, noiseParams.suites, this._serverNoiseKey);
    var protocolName = 'Noise_' + sel.pattern + '_' + sel.suite;
    var prologue = buildNoisePrologue(this._serverHelloPayload, payload, protocolName);
    try {
        this._noiseHandshake = await NoiseHandshake.create({
            pattern: sel.pattern,
            suite: sel.suite,
            psk: psk,
            prologue: prologue,
            staticPriv: this._noiseStaticKey || undefined,
            ephemeralPriv: this._noiseEphemeralKey || undefined,
            remoteStaticPub: sel.pattern === NOISE_PATTERN_KK && this._serverNoiseKey
                ? fromHex(this._serverNoiseKey) : undefined
        });
        // Noise payload of message 1: preference-ordered encodings + binarize
        var msg1Payload = new TextEncoder().encode(canonicalJson({
            binarize: false,
            encodings: ['JSON-HEX']
        }));
        var msg1 = await this._noiseHandshake.writeMessage(msg1Payload);
    } catch (e) {
        this._abortNoise('failed to initialize Noise handshake: ' + e.message);
        return;
    }
    console.log('HiveMind: starting protocol v3 handshake: ' + protocolName);
    this._send(this._wrap('shake', {
        noise: { pattern: sel.pattern, suite: sel.suite, msg: toHex(msg1) }
    }));
    this._state = States.HANDSHAKE_SENT;
};

// §3.4.3 steps 4-7: consume the server's Noise message, send message 3 (XX),
// Split(), then send the encrypted HELLO as the first Noise transport message
JarbasHiveMind.prototype._receiveNoiseHandshake = async function (payload) {
    var msg;
    try {
        msg = fromHex(payload.noise.msg);
    } catch (e) {
        this._abortNoise('malformed Noise handshake envelope');
        return;
    }
    var serverSelection = {};
    try {
        var noisePayload = await this._noiseHandshake.readMessage(msg);
        if (!this._noiseHandshake.finished) {
            // XXpsk2 message 3: our (encrypted) static key + final DH mix
            var msg3 = await this._noiseHandshake.writeMessage(new Uint8Array(0));
            this._send(this._wrap('shake', { noise: { msg: toHex(msg3) } }));
        }
        if (noisePayload && noisePayload.length) {
            try { serverSelection = JSON.parse(new TextDecoder().decode(noisePayload)); } catch (_) {}
        }
        var transport = new NoiseTransport(this._noiseHandshake);
    } catch (e) {
        // wrong password/PSK, tampered negotiation (prologue mismatch) or a bad
        // static key -> fatal, fails cryptographically at handshake time (§3.4.3)
        this._abortNoise('Noise handshake authentication failure (wrong PSK/password or tampered negotiation)');
        return;
    }
    // TOFU-then-pin the server's static key (§3.4.5)
    if (this._serverNoiseKey && transport.remoteStaticKey !== this._serverNoiseKey) {
        this._abortNoise('server Noise static key mismatch — possible man-in-the-middle');
        return;
    }
    this._serverNoiseKey = transport.remoteStaticKey;  // expose for pinning by the caller
    this._encoding = serverSelection.encoding || 'JSON-HEX';
    this._noiseTransport = transport;
    this._noiseHandshake = null;
    this._state = States.KEY_DERIVED;
    console.log('HiveMind: protocol v3 Noise session established');
    await this._sendClientHello();
};

JarbasHiveMind.prototype._abortNoise = function (reason) {
    // fatal handshake failure — reject the connection (§3.4.3)
    console.error('HiveMind: aborting protocol v3 connection: ' + reason);
    this._noiseHandshake = null;
    this._noiseTransport = null;
    this._state = States.DISCONNECTED;
    try { this.ws.close(); } catch (_) {}
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
    if (this._noiseTransport) {
        // protocol v3: the encrypted HELLO is the first Noise transport message
        var frame = await this._noiseTransport.encryptFrame(JSON.stringify(hiveMsg));
        this.ws.send(frame.buffer);
        this._state = States.READY;
        console.log('HiveMind: HELLO sent — Connected');
        this.onHiveConnected();
        return;
    }
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
        // OVOS-PIPELINE-1 §9.6 renamed the spoken-response topic to
        // 'ovos.utterance.speak'. Python clients never noticed, because
        // ovos-bus-client rewrites the legacy name for its subscribers; this
        // client has no such shim, so matching only 'speak' meant
        // onMycroftSpeak never fired against a current hub. Both names are
        // accepted: the spec one is what hubs emit now, the legacy one keeps
        // older hubs working.
        if (mycMsg && (mycMsg.type === 'ovos.utterance.speak'
                       || mycMsg.type === 'speak')) {
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
    if (this._noiseTransport) {
        // protocol v3: only valid Noise transport messages are accepted after
        // Split(); an AEAD failure means tampering/replay and is fatal (§3.4.5)
        var inner;
        try {
            inner = await this._noiseTransport.decryptFrame(frame);
        } catch (e) {
            this._abortNoise('Noise transport message rejected (tampered, replayed or out-of-order)');
            return;
        }
        if (typeof inner === 'string') {
            var v3msg;
            try {
                v3msg = JSON.parse(inner);
            } catch (e) {
                console.error('HiveMind: failed to parse v3 frame', e);
                return;
            }
            this._handleUserMessage(v3msg);
        } else {
            // WIRE-1 binary frame inside the Noise transport message
            try {
                var v3decoded = await decodeBitstring(inner);
            } catch (e) {
                console.error('HiveMind: bitstring decode failed', e);
                return;
            }
            var v3payload = v3decoded.payload;
            if (v3decoded.msgType !== 'bin' && typeof v3payload === 'string') {
                try { v3payload = JSON.parse(v3payload); } catch (_) {}
            }
            var v3wrapped = { msg_type: v3decoded.msgType, payload: v3payload, metadata: v3decoded.metadata };
            if (v3decoded.msgType === 'bin') v3wrapped.bin_type = v3decoded.binType;
            this._handleUserMessage(v3wrapped);
        }
        return;
    }
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
        BIN_TYPES, MSG_TYPE_TO_INT, INT_TO_MSG_TYPE,
        // protocol v3 (Noise)
        NoiseHandshake, NoiseTransport, NoiseCipherState, NoiseSymmetricState,
        selectNoiseOptions, buildNoisePrologue, canonicalJson,
        derivePskPBKDF2, derivePskArgon2,
        noiseHkdf, x25519, x25519PublicFromPrivate,
        NOISE_PATTERN_XX, NOISE_PATTERN_KK,
        NOISE_SUITE_CHACHA, NOISE_SUITE_AESGCM, NOISE_SUITES_JS
    };
}
