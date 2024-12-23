function JarbasHiveMind() {
    this.password = null;
    this.sessionId = null;
    this.binarize = false;
    this.siteId = "cyberspace";
    this.handshakeEvent = false;
    this.encryptionKey = null;
}

// Helper function to generate a random IV
function generateIV(keyLength = 8) {
    const validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let iv = '';
    for (let i = 0; i < keyLength; i++) {
        iv += validChars.charAt(Math.floor(Math.random() * validChars.length));
    }
    return new TextEncoder().encode(iv); // Return as Uint8Array
}

// Create HSub (handshake envelope) function
async function createHSub(password, iv = null, hsublen = 48) {
    if (!iv) {
        iv = generateIV();  // Generate IV if not provided
    }
    const encoder = new TextEncoder();
    const concatenated = new Uint8Array([...iv, ...encoder.encode(password)]);
    const hashed = await crypto.subtle.digest('SHA-256', concatenated); // Hashing using SHA-256
    const hsub = new Uint8Array([...iv, ...new Uint8Array(hashed)]);
    return Array.from(hsub).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, hsublen);
}

// Extract IV from HSub
function ivFromHSub(hsub, digits = 16) {
    if (hsub.length < digits) return false;
    try {
        const hexIv = hsub.slice(0, digits);
        return new Uint8Array(hexIv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    } catch (err) {
        console.error('Error extracting IV:', err); // Better error logging
        return false;
    }
}

// Match HSub with password
async function matchHSub(hsub, password) {
    const hsublen = hsub.length;
    if (hsublen < 48 || hsublen > 80) return false;

    const iv = ivFromHSub(hsub);
    if (!iv) return false;

    const generatedHSub = await createHSub(password, iv, hsublen); // Async due to hashing
    return generatedHSub === hsub;
}

// Generate Handshake hsub
async function generateHandshake(password) {
    const iv = generateIV();
    const hsub = await createHSub(password, iv);  // Async operation, as it involves hashing
    return { hsub, iv };
}

// Receive Handshake and process it
function receiveHandshake(envelope) {
    const iv = ivFromHSub(envelope);
    if (!iv) return null;
    return new Uint8Array(iv.map(byte => byte ^ iv[0])); // Simplified XOR for example
}

// Get secret using PBKDF2
async function getSecret(password, salt) {
    if (!password || !salt) return null;  // Check if password and salt are provided

    try {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const derivedKey = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );

        return new Uint8Array(derivedKey);
    } catch (err) {
        console.error('Error in PBKDF2 key derivation:', err);
        return null;
    }
}

// AES encryption/decryption helpers
function importSecretKey(rawKey) {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );
}

function toHexString(byteArray) {
    return Array.from(byteArray, byte => byte.toString(16).padStart(2, '0')).join('');
}

function fromHexString(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Decrypt message function
JarbasHiveMind.prototype.decrypt_msg = async function(hex_ciphertext, hex_iv) {
    try {
        const iv = fromHexString(hex_iv);
        const encryptionKey = await importSecretKey(new TextEncoder().encode(this.encryptionKey));
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, encryptionKey, fromHexString(hex_ciphertext));
        return new TextDecoder().decode(decrypted);
    } catch (err) {
        console.error('Error decrypting message:', err);
        return null; // Return null in case of an error
    }
};

// Encrypt message function
JarbasHiveMind.prototype.encrypt_msg = async function(text) {
    try {
        const iv = crypto.getRandomValues(new Uint8Array(16));  // AES-GCM IV
        const encryptionKey = await importSecretKey(new TextEncoder().encode(this.encryptionKey));
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encryptionKey, new TextEncoder().encode(text));
        return { nonce: toHexString(iv), ciphertext: toHexString(new Uint8Array(ciphertext)) };
    } catch (err) {
        console.error('Error encrypting message:', err);
        return null; // Return null in case of an error
    }
};

// Start Handshake method
JarbasHiveMind.prototype.start_handshake = async function() {
    if (this.binarize) {
        console.log("HiveMind supports binarization protocol");
    } else {
        console.log("HiveMind does not support binarization protocol");
    }

    const session = { "session_id": this.sessionId };
    const envelope = await generateHandshake(this.password); // Ensure async call is awaited
    const msg = {
        msg_type: "handshake",
        payload: {
            envelope,
            binarize: this.binarize,
            session,
            site_id: this.siteId
        }
    };
    this.sendMessage(msg);
};

// Receive Handshake message
JarbasHiveMind.prototype.receive_handshake = async function(envelope) {
    console.log("Received password envelope");
    let salt = await receiveHandshake(envelope); // Ensure async call is awaited
    if (!salt) {
        console.error('Invalid handshake envelope.');
        return;
    }
    this.encryptionKey = await getSecret(this.password, salt); // Await async getSecret call
    this.handshakeEvent = true;
};

// Handle Hello message
JarbasHiveMind.prototype.onHelloMessage = function(message) {
    if (message.payload.session_id) {
        this.sessionId = message.payload.session_id;
        console.log("session_id updated to: " + this.sessionId);
    }
};

// Handle Handshake message
JarbasHiveMind.prototype.onHandshakeMessage = async function(message) {
    if (message.payload.envelope) {
        console.log("Received password envelope");
        let salt = await receiveHandshake(message.payload.envelope); // Ensure async call is awaited
        this.encryptionKey = await getSecret(this.password, salt); // Await async getSecret call
        this.handshakeEvent = true;
    } else {
        console.log("Handshake failed, retrying. Only password handshake is currently supported.");

        // TODO: support binarize in future PR
        this.binarize = message.payload.binarize || false;
        await this.start_handshake();
    }
};

// HiveMind events
JarbasHiveMind.prototype.onHiveMessage = async function(message) {
    try {
        message = JSON.parse(message.data);
        if (this.encryptionKey && message.ciphertext) {
            const decrypted = await this.decrypt_msg(message.ciphertext, message.nonce);
            message = JSON.parse(decrypted);
        }

        switch (message.msg_type) {
            case "bus":
                this.onMycroftMessage(message.payload);
                if (message.payload.type === "speak") {
                    this.onMycroftSpeak(message.payload);
                }
                break;
            case "hello":
                this.onHelloMessage(message.payload);
                break;
            case "handshake":
                this.onHandshakeMessage(message.payload);
                break;
            default:
                console.warn("Unknown message type:", message.msg_type); // Handle unknown message types
                break;
        }
    } catch (err) {
        console.error('Error processing HiveMind message:', err);
    }
};

JarbasHiveMind.prototype.onHiveConnected = function() {
    console.log("connected");
    this.start_handshake()
};

JarbasHiveMind.prototype.onHiveDisconnected = function() {
    console.log("disconnected");
};

// HiveMind API
JarbasHiveMind.prototype.connect = function(host, port, username, accessKey, password) {
    const address = `ws://${host}:${port}`;
    const authToken = btoa(`${username}:${accessKey}`);
    this.password = password;
    this.ws = new WebSocket(`${address}?authorization=${authToken}`);
    this.ws.onopen = this.onHiveConnected;
    this.ws.onmessage = this.onHiveMessage.bind(this);
    this.ws.onclose = this.onHiveDisconnected;
};

// Send message method
JarbasHiveMind.prototype.sendMessage = async function(message) {
    if (this.encryptionKey) {
        message = await this.encrypt_msg(JSON.stringify(message));
        if (!message) return; // If encryption failed, do not send the message
    }
    // TODO - inject sessionId in context
    this.ws.send(JSON.stringify(message));
};

// Send utterance method
JarbasHiveMind.prototype.sendUtterance = async function(utterance) {
    const payload = {
        type: "recognizer_loop:utterance",
        data: { utterances: [utterance] },
        context: {
            source: "javascript",
            destination: "HiveMind",
            platform: "JarbasHivemindJsV0.2",
            session: {"session_id": this.sessionId}
        }
    };
    await this.sendMessage({ msg_type: "bus", payload });
};

// Handle speak message
JarbasHiveMind.prototype.onMycroftSpeak = function(mycroft_message) {
    console.log("mycroft.speak - " + mycroft_message.data.utterance);
};

// Handle general Mycroft message
JarbasHiveMind.prototype.onMycroftMessage = function(mycroft_message) {
    console.log(mycroft_message);
};
