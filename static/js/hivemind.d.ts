// Type declarations for hivemind-js, the HiveMind protocol client.
//
// These describe static/js/hivemind.js, which is plain JavaScript. They are
// written by hand, so a change to a public signature there must be made here
// too; test/types.test.js compiles the readme examples against this file.

/** Connection state machine. */
export declare const States: {
    readonly DISCONNECTED: 0;
    readonly CONNECTING: 1;
    readonly HELLO_RECEIVED: 2;
    readonly HANDSHAKE_SENT: 3;
    readonly KEY_DERIVED: 4;
    readonly READY: 5;
};
export type State = (typeof States)[keyof typeof States];

/** Binary payload types for a `bin` HiveMessage. */
export declare const BIN_TYPES: {
    readonly UNDEFINED: 0;
    readonly RAW_AUDIO: 1;
    readonly NUMPY_IMAGE: 2;
    readonly FILE: 3;
    readonly STT_AUDIO_TRANSCRIBE: 4;
    readonly STT_AUDIO_HANDLE: 5;
    readonly TTS_AUDIO: 6;
};
export type BinType = (typeof BIN_TYPES)[keyof typeof BIN_TYPES];

/** HiveMessage type name to its 5-bit wire code. */
export declare const MSG_TYPE_TO_INT: Readonly<Record<string, number>>;
/** 5-bit wire code to HiveMessage type name. */
export declare const INT_TO_MSG_TYPE: Readonly<Record<number, string>>;

/** A Layer-1 (OVOS) bus message as carried in a `bus` HiveMessage payload. */
export interface MycroftMessage {
    type: string;
    data?: Record<string, any>;
    context?: Record<string, any>;
}

/** A HiveMessage as the client sends and receives it. */
export interface HiveMessage {
    msg_type: string;
    payload?: any;
    metadata?: Record<string, any>;
    bin_type?: number;
    [key: string]: any;
}

/** Optional 6th argument of connect(). Any option enables protocol v3 (Noise) use. */
export interface ConnectOptions {
    /** 32-byte PSK, or 64 hex characters: the server's argon2id(password, SHA-256(node_id)). */
    psk?: Uint8Array | string;
    /** Hex X25519 public key of the server; enables KKpsk0 and aborts on a mismatch. */
    serverNoiseKey?: string;
    /** This node's static X25519 private key, 32 bytes or hex. Persisted when omitted. */
    noiseStaticKey?: Uint8Array | string;
    /** Cap on the negotiated protocol version. Default 3. */
    maxProtocolVersion?: number;
    /** Use wss:// when the host has no scheme of its own. */
    ssl?: boolean;
    /** Fixed ephemeral key for deterministic interop tests only. Never in production. */
    _noiseEphemeralKey?: Uint8Array | string;
}

/** The HiveMind client. Assign the on* hooks, then call connect(). */
export declare class JarbasHiveMind {
    constructor();

    /** Negotiated server static key (hex) after a Noise handshake, for pinning. */
    readonly _serverNoiseKey: string | null;

    /**
     * Open the connection and run the handshake.
     * @returns the underlying WebSocket.
     */
    connect(host: string, port: number, username: string, accessKey: string,
            password?: string | null, options?: ConnectOptions): WebSocket;

    /** Send a HiveMessage. Rejects before the handshake completes. */
    sendMessage(hiveMessage: HiveMessage): Promise<void>;
    /** Send an utterance to the hub's intent pipeline. */
    sendUtterance(utterance: string): Promise<void>;

    /** The handshake completed; messages can be sent. */
    onHiveConnected: () => void | Promise<void>;
    /** The socket closed. */
    onHiveDisconnected: () => void;
    /** A connection, handshake or frame error. */
    onHiveError: (error: Error) => void;
    /** Any Layer-1 bus message from the hub. */
    onMycroftMessage: (message: MycroftMessage) => void;
    /** A spoken response ('ovos.utterance.speak' or the legacy 'speak'). */
    onMycroftSpeak: (message: MycroftMessage) => void;
    onHiveBroadcast: (message: HiveMessage) => void;
    onHivePropagate: (message: HiveMessage) => void;
    onHiveIntercom: (message: HiveMessage) => void;
    onHivePing: (message: HiveMessage) => void;

    /** @internal Session key of a legacy (pre-Noise) session. */
    _sessionKey: Uint8Array | null;
    /** @internal Send an already encoded bitstring frame, encrypted for the session. */
    _sendEncryptedBinary(frame: Uint8Array): Promise<void>;
    /** @internal Receive path for a binary WebSocket frame. */
    _handleBinaryWsMessage(buffer: ArrayBuffer): Promise<void>;
}

/** Legacy password handshake (port of poorman_handshake). */
export declare class PasswordHandShake {
    constructor(password: string);
    password: string;
    iv: Uint8Array | null;
    salt: Uint8Array | null;
    generateIV(): Uint8Array;
    createHsub(iv: Uint8Array, hsublen?: number): Promise<string>;
    ivFromHsub(hsub: string): Uint8Array;
    matchHsub(hsub: string): Promise<boolean>;
    generateHandshake(): Promise<{ envelope: string; iv: Uint8Array }>;
    receiveHandshake(theirEnvelope: string): void;
    deriveSecret(): Promise<Uint8Array>;
}

/** Hex fields of a legacy AES-GCM JSON frame. */
export interface AesGcmJsonFrame {
    ciphertext: string;
    tag: string;
    nonce: string;
}

export declare function encryptAesGcm(keyBytes: Uint8Array, plaintext: string): Promise<AesGcmJsonFrame>;
export declare function decryptAesGcm(keyBytes: Uint8Array, payload: AesGcmJsonFrame): Promise<string>;
export declare function encryptAesGcmBin(keyBytes: Uint8Array, plaintextBytes: Uint8Array): Promise<Uint8Array>;
export declare function decryptAesGcmBin(keyBytes: Uint8Array, frame: Uint8Array): Promise<Uint8Array>;

export interface DecodedBitstring {
    msgType: string;
    /** Bytes for a `bin` message, text otherwise. */
    payload: Uint8Array | string;
    metadata: Record<string, any>;
    binType: number;
}

export declare function encodeBitstring(msgType: string, payload: string | Uint8Array,
                                        metadata?: Record<string, any>, binType?: number,
                                        versioned?: boolean): Uint8Array;
export declare function decodeBitstring(bytes: Uint8Array): Promise<DecodedBitstring>;

// ── protocol v3 (Noise) ─────────────────────────────────────────────────────

export declare const NOISE_PATTERN_XX: 'XXpsk2';
export declare const NOISE_PATTERN_KK: 'KKpsk0';
export declare const NOISE_SUITE_CHACHA: '25519_ChaChaPoly_SHA256';
export declare const NOISE_SUITE_AESGCM: '25519_AESGCM_SHA256';
/** Suites this build can run, preferred first. */
export declare const NOISE_SUITES_JS: readonly string[];

export type NoisePattern = typeof NOISE_PATTERN_XX | typeof NOISE_PATTERN_KK;
export type NoiseSuite = typeof NOISE_SUITE_CHACHA | typeof NOISE_SUITE_AESGCM;

export declare class NoiseCipherState {
    constructor(suite?: string);
    k: Uint8Array | null;
    n: bigint;
    initializeKey(k: Uint8Array | null): void;
    hasKey(): boolean;
    encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
    decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
}

export declare class NoiseSymmetricState {
    static create(protocolName: Uint8Array, suite?: string): Promise<NoiseSymmetricState>;
    mixHash(data: Uint8Array): Promise<void>;
    mixKey(ikm: Uint8Array): Promise<void>;
    mixKeyAndHash(ikm: Uint8Array): Promise<void>;
    encryptAndHash(plaintext: Uint8Array): Promise<Uint8Array>;
    decryptAndHash(ciphertext: Uint8Array): Promise<Uint8Array>;
    split(): Promise<[NoiseCipherState, NoiseCipherState]>;
}

export interface NoiseHandshakeOptions {
    pattern: string;
    suite: string;
    initiator: boolean;
    /** 32-byte pre-shared key. */
    psk: Uint8Array;
    staticPriv?: Uint8Array;
    ephemeralPriv?: Uint8Array;
    remoteStaticPub?: Uint8Array;
    prologue?: Uint8Array;
}

export declare class NoiseHandshake {
    static create(opts: NoiseHandshakeOptions): Promise<NoiseHandshake>;
    pattern: string;
    suite: string;
    writeMessage(payload?: Uint8Array): Promise<Uint8Array>;
    readMessage(data: Uint8Array): Promise<Uint8Array>;
}

export declare class NoiseTransport {
    constructor(handshake: NoiseHandshake);
    /** Hex static key of the peer, or null. */
    readonly remoteStaticKey: string | null;
    readonly handshakeHash: Uint8Array;
    encryptFrame(payload: string | Uint8Array): Promise<Uint8Array>;
    /** A string for a JSON frame, bytes for a binary frame. */
    decryptFrame(data: Uint8Array): Promise<string | Uint8Array>;
}

export declare function selectNoiseOptions(serverPatterns: readonly string[], serverSuites: readonly string[],
                                           pinnedRemoteKey?: string | null): { pattern: NoisePattern; suite: string } | null;
export declare function buildNoisePrologue(helloPayload: Record<string, any> | null,
                                           handshakePayload: Record<string, any> | null,
                                           protocolName: string): Uint8Array;
export declare function canonicalJson(value: unknown): string;
export declare function derivePskPBKDF2(password: string, nodeId: string, iterations?: number): Promise<Uint8Array>;
export declare function derivePskArgon2(password: string, nodeId: string): Promise<Uint8Array>;
export declare function noiseHkdf(chainingKey: Uint8Array, inputKeyMaterial: Uint8Array,
                                  numOutputs: 2 | 3): Promise<Uint8Array[]>;
export declare function x25519(rawPriv: Uint8Array, rawPub: Uint8Array): Promise<Uint8Array>;
export declare function x25519PublicFromPrivate(rawPriv: Uint8Array): Promise<Uint8Array>;

declare const hivemind: {
    JarbasHiveMind: typeof JarbasHiveMind;
    PasswordHandShake: typeof PasswordHandShake;
    States: typeof States;
    encryptAesGcm: typeof encryptAesGcm;
    decryptAesGcm: typeof decryptAesGcm;
    encryptAesGcmBin: typeof encryptAesGcmBin;
    decryptAesGcmBin: typeof decryptAesGcmBin;
    encodeBitstring: typeof encodeBitstring;
    decodeBitstring: typeof decodeBitstring;
    BIN_TYPES: typeof BIN_TYPES;
    MSG_TYPE_TO_INT: typeof MSG_TYPE_TO_INT;
    INT_TO_MSG_TYPE: typeof INT_TO_MSG_TYPE;
    NoiseHandshake: typeof NoiseHandshake;
    NoiseTransport: typeof NoiseTransport;
    NoiseCipherState: typeof NoiseCipherState;
    NoiseSymmetricState: typeof NoiseSymmetricState;
    selectNoiseOptions: typeof selectNoiseOptions;
    buildNoisePrologue: typeof buildNoisePrologue;
    canonicalJson: typeof canonicalJson;
    derivePskPBKDF2: typeof derivePskPBKDF2;
    derivePskArgon2: typeof derivePskArgon2;
    noiseHkdf: typeof noiseHkdf;
    x25519: typeof x25519;
    x25519PublicFromPrivate: typeof x25519PublicFromPrivate;
    NOISE_PATTERN_XX: typeof NOISE_PATTERN_XX;
    NOISE_PATTERN_KK: typeof NOISE_PATTERN_KK;
    NOISE_SUITE_CHACHA: typeof NOISE_SUITE_CHACHA;
    NOISE_SUITE_AESGCM: typeof NOISE_SUITE_AESGCM;
    NOISE_SUITES_JS: typeof NOISE_SUITES_JS;
};
export default hivemind;
