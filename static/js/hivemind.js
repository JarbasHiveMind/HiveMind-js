
function JarbasHiveMind() { }

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------
function toHexString(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function bufferToHex(buffer) {
    return Array
        .from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function fromHexString(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
}

function concatBytes() {
    let total = 0;
    for (const a of arguments) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arguments) { out.set(a, off); off += a.length; }
    return out;
}

// ---------------------------------------------------------------------------
// AES-GCM (matches hivemind_bus_client.encryption: 16-byte IV/nonce,
// 16-byte tag, JSON-HEX encoding).
//
// crypto_key is the raw session key (16/24/32 bytes) derived from the
// password handshake, NOT a utf-8 string. encryptionKey holds those raw bytes.
// ---------------------------------------------------------------------------
function importSecretKey(rawKey) {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );
}

JarbasHiveMind.prototype._keyBytes = function () {
    // encryptionKey may be raw bytes (from handshake) or a utf-8 string
    // (legacy pre-shared mode). Python truncates/uses the bytes directly.
    if (this.encryptionKey instanceof Uint8Array) {
        return this.encryptionKey;
    }
    return new TextEncoder().encode(this.encryptionKey);
}

JarbasHiveMind.prototype.decrypt_msg = async function (hex_ciphertext, hex_iv) {
    // hex_ciphertext already includes the GCM tag appended (WebCrypto layout)
    let iv = fromHexString(hex_iv);
    let encryption_key = await importSecretKey(this._keyBytes());
    let decrypted = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv
    }, encryption_key, fromHexString(hex_ciphertext))
    return new TextDecoder().decode(decrypted);
}

JarbasHiveMind.prototype.encrypt_msg = async function (text) {
    // 16-byte nonce to match hivemind_bus_client AES_NONCE_SIZE
    let iv = crypto.getRandomValues(new Uint8Array(16))
    let encryption_key = await importSecretKey(this._keyBytes());
    // WebCrypto returns ciphertext||tag; the python side (decrypt_from_json)
    // handles the missing "tag" field by splitting the trailing 16 bytes.
    let cyphertext = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv
    }, encryption_key, new TextEncoder().encode(text))
    return { "nonce": toHexString(iv), "ciphertext": bufferToHex(new Uint8Array(cyphertext)) }
}

// ---------------------------------------------------------------------------
// V1 password handshake (port of poorman_handshake.PasswordHandShake)
//
//   hsub  = (iv || SHA256(iv + password)).hex()[:48]   (iv = 8 random bytes)
//   salt  = our_iv XOR iv_from(their_hsub)             (both 8 bytes)
//   key   = PBKDF2-HMAC-SHA256(password, salt, 100000) -> 32 bytes
//
// Both peers derive the same salt (XOR is symmetric) and therefore the same
// session key, which is then used for AES-GCM. The password itself never
// crosses the wire.
// ---------------------------------------------------------------------------
async function sha256(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
}

async function createHsub(password, iv, hsublen) {
    hsublen = hsublen || 48;
    const pwd = new TextEncoder().encode(password);
    const hashed = await sha256(concatBytes(iv, pwd));
    const hsub = toHexString(concatBytes(iv, hashed));
    return hsub.slice(0, hsublen);
}

function ivFromHsub(hsub, digits) {
    digits = digits || 16; // first 64 bits => 16 hex chars
    if (hsub.length < digits) return null;
    return fromHexString(hsub.slice(0, digits));
}

function PasswordHandShake(password) {
    this.password = password;
    this.iv = null;
    this.salt = null;
}

PasswordHandShake.prototype.generate_handshake = async function () {
    this.iv = crypto.getRandomValues(new Uint8Array(8));
    return await createHsub(this.password, this.iv);
}

PasswordHandShake.prototype.receive_handshake = function (shake) {
    const theirIv = ivFromHsub(shake);
    this.salt = new Uint8Array(this.iv.length);
    for (let i = 0; i < this.iv.length; i++) {
        this.salt[i] = this.iv[i] ^ theirIv[i];
    }
}

PasswordHandShake.prototype.secret = async function () {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(this.password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: this.salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        256 // 32 bytes, matches python dk length
    );
    return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// hivemind events
// ---------------------------------------------------------------------------
JarbasHiveMind.prototype.onHiveMessage = async function (event) {
    let message = JSON.parse(event.data);

    // decrypt if needed
    if (this.crypto_key && message.ciphertext) {
        let combined = message.tag
            ? message["ciphertext"] + message["tag"]
            : message["ciphertext"];
        let plaintext = await this.decrypt_msg(combined, message["nonce"]);
        message = JSON.parse(plaintext);
    }

    let msgType = message.msg_type;

    // --- V1 handshake state machine -------------------------------------
    if (msgType === "hello") {
        // first HELLO carries the master node_id + pubkey
        let payload = message.payload || {};
        if (!this.node_id && payload.node_id) {
            this.node_id = payload.node_id;
            this.mpubkey = payload.pubkey;
        }
        return;
    }

    if (msgType === "shake") {
        await this.handleHandshake(message.payload || {});
        return;
    }

    // --- normal bus traffic --------------------------------------------
    if (msgType === "bus") {
        let mycroft_message = message.payload;
        this.onMycroftMessage(mycroft_message)
        if (mycroft_message.type === "speak") {
            this.onMycroftSpeak(mycroft_message)
        }
    }
}

JarbasHiveMind.prototype.handleHandshake = async function (payload) {
    if ("envelope" in payload) {
        // master replied with its envelope -> derive shared session key
        this.encoding = payload.encoding || "JSON-HEX";
        this.cipher = payload.cipher || "AES-GCM";
        this.pswd_handshake.receive_handshake(payload.envelope);
        let key = await this.pswd_handshake.secret();
        this.crypto_key = key;
        this.encryptionKey = key; // raw bytes used by encrypt/decrypt
        // communication is now secure; announce ourselves with an
        // (encrypted) HELLO carrying our session, then report connected.
        await this.sendHello();
        this._onHandshakeComplete();
        return;
    }

    // master is requesting we start the handshake
    if (payload.password && this.password) {
        this.pswd_handshake = new PasswordHandShake(this.password);
        let envelope = await this.pswd_handshake.generate_handshake();
        // force JSON-HEX + AES-GCM (matches what encrypt/decrypt implement);
        // server selects our first preference.
        let msg = {
            msg_type: "shake",
            payload: {
                envelope: envelope,
                binarize: false,
                encodings: ["JSON-HEX"],
                ciphers: ["AES-GCM"]
            }
        };
        // handshake messages are always sent unencrypted
        await this.ws.send(JSON.stringify(msg));
    } else {
        console.error("master did not offer password handshake; " +
            "this client only implements the V1 password handshake");
    }
}

JarbasHiveMind.prototype.sendHello = async function () {
    // session id, mirrors the python client's post-handshake HELLO
    if (!this.session_id) {
        this.session_id = (crypto.randomUUID && crypto.randomUUID()) ||
            toHexString(crypto.getRandomValues(new Uint8Array(16)));
    }
    let hello = {
        msg_type: "hello",
        payload: {
            session: { session_id: this.session_id },
            site_id: this.site_id || "unknown"
        }
    };
    // HELLO is never encrypted (matches server: HELLO/HANDSHAKE skip crypto)
    await this.ws.send(JSON.stringify(hello));
}

JarbasHiveMind.prototype._onHandshakeComplete = function () {
    if (this._handshakeDone) return;
    this._handshakeDone = true;
    try {
        this.onHiveConnected();
    } catch (e) {
        console.error("onHiveConnected handler error", e);
    }
}

JarbasHiveMind.prototype.onHiveConnected = function () {
    console.log("connected");
}

JarbasHiveMind.prototype.onHiveDisconnected = function () {
    console.log("disconnected");
}

// ---------------------------------------------------------------------------
// hivemind api
// ---------------------------------------------------------------------------
JarbasHiveMind.prototype.connect = function (host, port, username, accessKey, encryptionKey) {
    // encryptionKey is treated as a PASSWORD: the V1 handshake derives the
    // real AES session key from it. (A pre-shared raw key path also exists,
    // see connectPreshared.)
    let address = 'ws://' + host + ":" + port
    let authToken = btoa(username + ":" + accessKey);

    this.username = username;
    this.password = encryptionKey;   // used to drive the password handshake
    this.crypto_key = null;          // session key, set after handshake
    this.encryptionKey = null;       // raw key bytes once derived
    this.node_id = null;
    this._handshakeDone = false;

    this.ws = new WebSocket(address + "?authorization=" + authToken);
    // bind all socket events back to THIS client instance
    this.ws.onopen = () => { /* wait for server HELLO/HANDSHAKE */ };
    this.ws.onmessage = (event) => this.onHiveMessage(event);
    this.ws.onclose = () => this.onHiveDisconnected();
    return this.ws
}

// Optional: pre-shared raw key mode (no handshake). rawKey must be a
// 16/24/32-byte Uint8Array (or a hex string of that length).
JarbasHiveMind.prototype.connectPreshared = function (host, port, username, accessKey, rawKey) {
    let address = 'ws://' + host + ":" + port
    let authToken = btoa(username + ":" + accessKey);

    this.username = username;
    this.password = null;
    if (typeof rawKey === "string") {
        rawKey = fromHexString(rawKey);
    }
    this.crypto_key = rawKey;
    this.encryptionKey = rawKey;
    this.node_id = null;
    this._handshakeDone = false;

    this.ws = new WebSocket(address + "?authorization=" + authToken);
    this.ws.onopen = () => { /* HELLO/HANDSHAKE handled in onHiveMessage */ };
    this.ws.onmessage = (event) => this.onHiveMessage(event);
    this.ws.onclose = () => this.onHiveDisconnected();
    return this.ws
}

JarbasHiveMind.prototype.sendMessage = async function (message) {
    let hive_msg = message;
    if (this.crypto_key) {
        message = await this.encrypt_msg(JSON.stringify(hive_msg))
    }
    await this.ws.send(JSON.stringify(message));
}

// ---------------------------------------------------------------------------
// mycroft api
// ---------------------------------------------------------------------------
JarbasHiveMind.prototype.sendUtterance = async function (utterance) {
    let payload = {
        'type': "recognizer_loop:utterance",
        "data": { "utterances": [utterance] },
        "context": {
            "source": "javascript",
            "destination": "HiveMind",
            "platform": "JarbasHivemindJsV0.1",
            "session": { "session_id": this.session_id }
        }
    };
    await this.sendMessage({
        'msg_type': "bus",
        "payload": payload
    });

}

JarbasHiveMind.prototype.sendAudioB64 = async function (base64) {
    let payload = {
        'type': "recognizer_loop:b64_audio",
        "data": { "audio": base64 },
        "context": {
            "source": "javascript",
            "destination": "HiveMind",
            "platform": "JarbasHivemindJsV0.1",
            "session": { "session_id": this.session_id }
        }
    };
    await this.sendMessage({
        'msg_type': "bus",
        "payload": payload
    });

}

// ---------------------------------------------------------------------------
// mycroft events
// ---------------------------------------------------------------------------
JarbasHiveMind.prototype.onMycroftSpeak = function (mycroft_message) {
    console.log("mycroft.speak - " + mycroft_message.data.utterance)
}

JarbasHiveMind.prototype.onMycroftMessage = function (mycroft_message) {
    console.log(mycroft_message)
}


// Make the client usable from CommonJS / Node (e.g. e2e drivers) without
// affecting browser usage where JarbasHiveMind is a global. The browser
// expects WebSocket + crypto.subtle to exist; a Node consumer must polyfill
// globalThis.WebSocket (e.g. with the `ws` package) before connecting.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { JarbasHiveMind };
}
