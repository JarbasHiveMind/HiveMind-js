
function JarbasHiveMind() { }

// AES encryption
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

JarbasHiveMind.prototype.decrypt_msg = async function(hex_ciphertext, hex_iv) {
    // IV must be the same length (in bits) as the key
    let iv = fromHexString(hex_iv);

    let encryption_key = await importSecretKey(new TextEncoder().encode(this.encryptionKey));

    let decrypted = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv
    }, encryption_key, fromHexString(hex_ciphertext))
    return String.fromCharCode.apply(null, new Uint8Array(decrypted));

}

JarbasHiveMind.prototype.encrypt_msg = async function(text) {
    // IV must be the same length (in bits) as the key
    let iv = await crypto.getRandomValues(new Uint8Array(16))

    let encryption_key = await importSecretKey(new TextEncoder().encode(this.encryptionKey));

    let cyphertext = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv
    }, encryption_key, new TextEncoder().encode(text))
    return {"nonce": toHexString(iv), "ciphertext": bufferToHex(cyphertext)}

}

// hivemind events
JarbasHiveMind.prototype.onHiveMessage = async function (message) {
    message = JSON.parse(message.data);
    if (this.encryptionKey && message.ciphertext) {
        if (message.tag) {
            message = await this.decrypt_msg(message["ciphertext"] + message["tag"], message["nonce"])
        } else {
            message = await this.decrypt_msg(message["ciphertext"], message["nonce"])
        }
        message = JSON.parse(message)
    }

    if (message.msg_type === "bus") {
        let mycroft_message = message.payload;
        this.onMycroftMessage(mycroft_message)
        if (mycroft_message.type === "speak") {
            this.onMycroftSpeak(mycroft_message)
        }
    }
}

JarbasHiveMind.prototype.onHiveConnected = function() {
    console.log("connected");
}

JarbasHiveMind.prototype.onHiveDisconnected = function() {
    console.log("disconnected");
}

// hivemind api
JarbasHiveMind.prototype.connect = function(host, port, username, accessKey, encryptionKey) {
    let address = 'ws://' + host + ":" + port
    let authToken = btoa(username + ":" + accessKey);
    this.ws = new WebSocket(address + "?authorization=" + authToken);
    this.ws.onopen = this.onHiveConnected
    this.ws.onmessage = this.onHiveMessage
    this.ws.onclose = this.onHiveDisconnected
    this.ws.onMycroftSpeak = this.onMycroftSpeak
    this.ws.onMycroftMessage = this.onMycroftMessage
    this.ws.encryptionKey = encryptionKey
    this.ws.decrypt_msg = this.decrypt_msg
    this.ws.encrypt_msg = this.encrypt_msg
    return this.ws
}

JarbasHiveMind.prototype.sendMessage = async function (message) {
    let hive_msg = message;
    if (this.encryptionKey) {
        message = await this.encrypt_msg(JSON.stringify(hive_msg))
    }
    this.ws.send(JSON.stringify(message));
}

// mycroft api
JarbasHiveMind.prototype.sendUtterance = async function (utterance) {
    let payload = {
        'type': "recognizer_loop:utterance",
        "data": {"utterances": [utterance]},
        "context": {
            "source": "javascript",
            "destination": "HiveMind",
            "platform": "JarbasHivemindJsV0.1"
        }
    };
    await this.sendMessage({
        'msg_type': "bus",
        "payload": payload
    });

}

// mycroft events
JarbasHiveMind.prototype.onMycroftSpeak = function (mycroft_message) {
    console.log("mycroft.speak - " + mycroft_message.data.utterance)
}

JarbasHiveMind.prototype.onMycroftMessage = function (mycroft_message) {
    console.log(mycroft_message)
}

