// Compile-only fixture: the readme examples, typed against static/js/hivemind.d.ts.
// test/types.test.js runs tsc over this file. It is never executed.

import hivemindDefault, {
    JarbasHiveMind, States, BIN_TYPES, encodeBitstring, decryptAesGcmBin, decodeBitstring,
    type ConnectOptions, type MycroftMessage,
} from 'hivemind-js';

declare const WebSocketImpl: typeof WebSocket;
declare const wavBytes: Uint8Array;

globalThis.WebSocket = WebSocketImpl;

const hivemind = new JarbasHiveMind();

hivemind.onHiveConnected = async () => {
    console.log('connected');
    await hivemind.sendUtterance('tell me a joke');
};

hivemind.onMycroftSpeak = (msg: MycroftMessage) => console.log('speak:', msg.data?.utterance);
hivemind.onHiveError = (e: Error) => console.error(e.message);

// connect(host, port, username, accessKey, password)
hivemind.connect('127.0.0.1', 5678, 'HivemindNode', 'ivf1NQSkQNogWYyr', 'mypassword');

// protocol v3 options
const options: ConnectOptions = { serverNoiseKey: 'ab'.repeat(32), maxProtocolVersion: 3, ssl: true };
hivemind.connect('wss://hive.example.org', 443, 'HivemindNode', 'key', null, options);

// Sending a raw audio frame
async function sendAudio(): Promise<void> {
    const metadata = { sample_rate: 16000, sample_width: 2 };
    const frame = encodeBitstring('bin', wavBytes, metadata, BIN_TYPES.RAW_AUDIO);
    await hivemind._sendEncryptedBinary(frame);
}

// Handling incoming binary frames (e.g. TTS audio)
const orig = hivemind._handleBinaryWsMessage.bind(hivemind);
hivemind._handleBinaryWsMessage = async function (this: JarbasHiveMind, buffer: ArrayBuffer) {
    const decrypted = await decryptAesGcmBin(this._sessionKey!, new Uint8Array(buffer));
    const decoded = await decodeBitstring(decrypted);
    if (decoded.binType === BIN_TYPES.TTS_AUDIO) {
        return;
    }
    await orig(buffer);
};

// the default export carries the same objects
const ready: 5 = hivemindDefault.States.READY;
const alsoReady: number = States.READY;

// @ts-expect-error: port is a number, not a string
hivemind.connect('127.0.0.1', '5678', 'HivemindNode', 'key', 'pw');

void sendAudio; void ready; void alsoReady;
