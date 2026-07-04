#!/usr/bin/env python3
"""Generate protocol v3 (Noise) interop test vectors for the JS test suite.

Drives the Python reference stack (the ``noiseprotocol`` library, the same
engine ``poorman_handshake.noise.NoiseHandShake`` wraps) as the **responder**
(HiveMind server role) through full handshakes with fixed keys, and dumps the
handshake messages, transport messages, and expected plaintexts as JSON
fixtures.  The JS implementation, acting as the **initiator** (node role) with
the same fixed keys, must reproduce every byte — proving byte-level interop
with a Python/noiseprotocol server.

Both registered cipher suites are covered (HIVEMIND-CRYPTO-1 §3.4.1):

- ``25519_ChaChaPoly_SHA256`` — the mandatory/DEFAULT suite. HiveMind-js runs
  ChaCha20-Poly1305 via ``@noble/ciphers``.
- ``25519_AESGCM_SHA256`` — the Web-Crypto-native fallback suite.

The PSK-derivation fixtures cover both the DEFAULT argon2id (matching
``poorman_handshake.noise.derive_psk`` exactly) and the PBKDF2 fallback.

Run with a venv that has ``poorman_handshake`` + ``noiseprotocol`` installed:
  ~/.venvs/hivemind-v3/bin/python test/generate_noise_vectors.py
"""
import hashlib
import json
import os

from noise.connection import Keypair, NoiseConnection
from poorman_handshake.noise import derive_psk

# ── Fixed inputs (deterministic) ──────────────────────────────────────────────

PSK = bytes.fromhex(
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
WRONG_PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000001")

INITIATOR_STATIC = bytes.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111")
INITIATOR_EPHEMERAL = bytes.fromhex(
    "2222222222222222222222222222222222222222222222222222222222222222")
RESPONDER_STATIC = bytes.fromhex(
    "3333333333333333333333333333333333333333333333333333333333333333")
RESPONDER_EPHEMERAL = bytes.fromhex(
    "4444444444444444444444444444444444444444444444444444444444444444")

# both registered cipher suites (HIVEMIND-CRYPTO-1 §3.4.1)
SUITE_CHACHA = "25519_ChaChaPoly_SHA256"
SUITE_AESGCM = "25519_AESGCM_SHA256"


def pubkey_of(private_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.from_private_bytes(private_bytes).public_key() \
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def canonical_json(payload) -> bytes:
    """Must match hivemind_bus_client.noise.canonical_json (and the JS port)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ── Negotiation payloads (mirror hivemind-core's cleartext step 1/2 payloads) ─

HELLO_PAYLOAD = {
    "pubkey": "-----BEGIN PUBLIC KEY-----\nserver-rsa-pubkey\n-----END PUBLIC KEY-----",
    "peer": "tcp4:127.0.0.1:12345",
    "node_id": "tcp4:0.0.0.0:5678"
}


def handshake_payload(suites) -> dict:
    return {
        "handshake": True,
        "min_protocol_version": 2,
        "max_protocol_version": 3,
        "binarize": False,
        "preshared_key": False,
        "password": True,
        "crypto_required": True,
        "encodings": ["JSON-HEX"],
        "ciphers": ["AES-GCM"],
        "noise": {"patterns": ["XXpsk2"], "suites": list(suites)},
    }


# Noise payloads carried inside the handshake messages
MSG1_PAYLOAD = canonical_json({"binarize": False, "encodings": ["JSON-HEX"]})
MSG2_PAYLOAD = canonical_json({"encoding": "JSON-HEX"})

# transport-message plaintexts (v3 frame marker \x00 = JSON, per
# hivemind_bus_client.noise)
SERVER_BUS_JSON = ('{"msg_type": "bus", "payload": {"type": "speak", '
                   '"data": {"utterance": "hello from python"}, "context": {}}}')
CLIENT_BUS_JSON = ('{"msg_type":"bus","payload":{"type":"recognizer_loop:utterance",'
                   '"data":{"utterances":["hi"]},"context":{}}}')


def make_connection(name: bytes, initiator: bool, psk: bytes, prologue: bytes,
                    static: bytes, ephemeral: bytes,
                    remote_static: bytes = None) -> NoiseConnection:
    c = NoiseConnection.from_name(name)
    c.set_keypair_from_private_bytes(Keypair.STATIC, static)
    c.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral)
    if remote_static is not None:
        c.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
    c.set_psks(psk)
    c.set_prologue(prologue)
    if initiator:
        c.set_as_initiator()
    else:
        c.set_as_responder()
    c.start_handshake()
    return c


def build_prologue(protocol_name: str, hs_payload: dict) -> bytes:
    """Per HIVEMIND-CRYPTO-1 §3.4.3 / hivemind_bus_client.noise.build_prologue."""
    return (canonical_json(HELLO_PAYLOAD) + canonical_json(hs_payload)
            + protocol_name.encode("utf-8"))


def xx_vector(suite: str) -> dict:
    name = f"Noise_XXpsk2_{suite}"
    hs_payload = handshake_payload([suite])
    prologue = build_prologue(name, hs_payload)
    init = make_connection(name.encode(), True, PSK, prologue,
                           INITIATOR_STATIC, INITIATOR_EPHEMERAL)
    resp = make_connection(name.encode(), False, PSK, prologue,
                           RESPONDER_STATIC, RESPONDER_EPHEMERAL)

    msg1 = init.write_message(MSG1_PAYLOAD)
    assert resp.read_message(msg1) == MSG1_PAYLOAD
    msg2 = resp.write_message(MSG2_PAYLOAD)
    assert init.read_message(msg2) == MSG2_PAYLOAD
    msg3 = init.write_message(b"")
    assert resp.read_message(msg3) == b""
    assert init.get_handshake_hash() == resp.get_handshake_hash()

    # transport messages (counters start at 0 in each direction)
    server_frame = resp.encrypt(b"\x00" + SERVER_BUS_JSON.encode("utf-8"))
    # what the initiator must produce for CLIENT_BUS_JSON at send-counter 0
    expected_client_frame = init.encrypt(b"\x00" + CLIENT_BUS_JSON.encode("utf-8"))
    assert resp.decrypt(expected_client_frame) == b"\x00" + CLIENT_BUS_JSON.encode("utf-8")

    # wrong-PSK responder: reads msg1 fine (psk mixes at message 2) but its
    # msg2 must fail authentication on the initiator side
    bad_resp = make_connection(name.encode(), False, WRONG_PSK, prologue,
                               RESPONDER_STATIC, RESPONDER_EPHEMERAL)
    bad_resp.read_message(msg1)
    msg2_wrong_psk = bad_resp.write_message(MSG2_PAYLOAD)

    return {
        "suite": suite,
        "protocol_name": name,
        "hello_payload": HELLO_PAYLOAD,
        "handshake_payload": hs_payload,
        "prologue_hex": prologue.hex(),
        "psk_hex": PSK.hex(),
        "initiator_static_hex": INITIATOR_STATIC.hex(),
        "initiator_ephemeral_hex": INITIATOR_EPHEMERAL.hex(),
        "responder_static_pub_hex": pubkey_of(RESPONDER_STATIC).hex(),
        "msg1_payload": MSG1_PAYLOAD.decode("utf-8"),
        "msg1_hex": msg1.hex(),
        "msg2_hex": msg2.hex(),
        "msg2_payload": MSG2_PAYLOAD.decode("utf-8"),
        "msg3_hex": msg3.hex(),
        "handshake_hash_hex": init.get_handshake_hash().hex(),
        "server_transport_frame_hex": server_frame.hex(),
        "server_transport_plaintext": SERVER_BUS_JSON,
        "client_transport_plaintext": CLIENT_BUS_JSON,
        "expected_client_transport_frame_hex": expected_client_frame.hex(),
        "msg2_wrong_psk_hex": msg2_wrong_psk.hex(),
    }


def kk_vector(suite: str) -> dict:
    name = f"Noise_KKpsk0_{suite}"
    hs_payload = handshake_payload([suite])
    prologue = build_prologue(name, hs_payload)
    init = make_connection(name.encode(), True, PSK, prologue,
                           INITIATOR_STATIC, INITIATOR_EPHEMERAL,
                           remote_static=pubkey_of(RESPONDER_STATIC))
    resp = make_connection(name.encode(), False, PSK, prologue,
                           RESPONDER_STATIC, RESPONDER_EPHEMERAL,
                           remote_static=pubkey_of(INITIATOR_STATIC))

    msg1 = init.write_message(MSG1_PAYLOAD)
    assert resp.read_message(msg1) == MSG1_PAYLOAD
    msg2 = resp.write_message(MSG2_PAYLOAD)
    assert init.read_message(msg2) == MSG2_PAYLOAD

    server_frame = resp.encrypt(b"\x00" + SERVER_BUS_JSON.encode("utf-8"))
    expected_client_frame = init.encrypt(b"\x00" + CLIENT_BUS_JSON.encode("utf-8"))
    assert resp.decrypt(expected_client_frame) == b"\x00" + CLIENT_BUS_JSON.encode("utf-8")

    return {
        "suite": suite,
        "protocol_name": name,
        "prologue_hex": prologue.hex(),
        "psk_hex": PSK.hex(),
        "initiator_static_hex": INITIATOR_STATIC.hex(),
        "initiator_ephemeral_hex": INITIATOR_EPHEMERAL.hex(),
        "responder_static_pub_hex": pubkey_of(RESPONDER_STATIC).hex(),
        "msg1_payload": MSG1_PAYLOAD.decode("utf-8"),
        "msg1_hex": msg1.hex(),
        "msg2_hex": msg2.hex(),
        "msg2_payload": MSG2_PAYLOAD.decode("utf-8"),
        "handshake_hash_hex": init.get_handshake_hash().hex(),
        "server_transport_frame_hex": server_frame.hex(),
        "server_transport_plaintext": SERVER_BUS_JSON,
        "client_transport_plaintext": CLIENT_BUS_JSON,
        "expected_client_transport_frame_hex": expected_client_frame.hex(),
    }


def argon2id_vector() -> dict:
    """DEFAULT PSK derivation — byte-identical to poorman_handshake.noise.derive_psk:
    argon2id(password, salt=SHA-256(node_id), t=3, m=64 MiB, p=1, len=32)."""
    password = "test-password-123"
    node_id = HELLO_PAYLOAD["node_id"]
    psk = derive_psk(password, node_id=node_id)
    return {
        "password": password,
        "node_id": node_id,
        "salt_hex": hashlib.sha256(node_id.encode("utf-8")).hexdigest(),
        "time_cost": 3,
        "memory_cost_kib": 64 * 1024,
        "parallelism": 1,
        "hash_len": 32,
        "expected_psk_hex": psk.hex(),
    }


def pbkdf2_vector() -> dict:
    """PSK derivation for PBKDF2-advertising servers (HIVEMIND-CRYPTO-1 §3.4.4):
    PSK = PBKDF2-HMAC-SHA256(password, SHA-256(node_id), iterations, 32)."""
    password = "test-password-123"
    node_id = HELLO_PAYLOAD["node_id"]
    iterations = 100000
    salt = hashlib.sha256(node_id.encode("utf-8")).digest()
    psk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)
    return {
        "password": password,
        "node_id": node_id,
        "iterations": iterations,
        "expected_psk_hex": psk.hex(),
    }


def main():
    vectors = {
        # DEFAULT ChaCha20-Poly1305 suite
        "xxpsk2_chacha": xx_vector(SUITE_CHACHA),
        "kkpsk0_chacha": kk_vector(SUITE_CHACHA),
        # Web-Crypto-native AES-GCM suite
        "xxpsk2_aesgcm": xx_vector(SUITE_AESGCM),
        "kkpsk0_aesgcm": kk_vector(SUITE_AESGCM),
        # PSK derivations
        "argon2id_psk": argon2id_vector(),
        "pbkdf2_psk": pbkdf2_vector(),
        # legacy aliases (AES-GCM) kept for any external consumers
        "xxpsk2": xx_vector(SUITE_AESGCM),
        "kkpsk0": kk_vector(SUITE_AESGCM),
    }
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "noise_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Noise vectors written to {out_path}")


if __name__ == "__main__":
    main()
