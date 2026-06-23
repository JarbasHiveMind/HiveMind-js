#!/usr/bin/env python3
"""Generate cross-compatibility test vectors for the JS test suite.

Run with the workspace venv:
  /home/miro/PycharmProjects/HiveMind Workspace/.venv/bin/python \
      HiveMind-js/test/generate_vectors.py
"""
import hashlib
import json
import os
import sys

# Add workspace root to path so the venv packages are found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from hivemind_bus_client.serialization import get_bitstring
from hivemind_bus_client.message import HiveMessageType, HiveMindBinaryPayloadType

from poorman_handshake.symmetric.utils import create_hsub, iv_from_hsub
from Cryptodome.Cipher import AES

# ── Fixed inputs (deterministic) ──────────────────────────────────────────────

PASSWORD = "test-password-123"
IV_HEX   = "deadbeefcafebabe"          # 8 bytes — client IV for hSub
SALT_HEX = "0102030405060708"          # 8 bytes — pre-fixed salt for PBKDF2 vector
NONCE_HEX = "00112233445566778899aabbccddeeff"  # 16 bytes — AES-GCM nonce

iv_bytes    = bytes.fromhex(IV_HEX)
salt_bytes  = bytes.fromhex(SALT_HEX)
nonce_bytes = bytes.fromhex(NONCE_HEX)

# ── hSub vector ───────────────────────────────────────────────────────────────

hsub = create_hsub(PASSWORD, iv_bytes)
assert hsub[:16] == IV_HEX, "IV must be first 16 hex chars of hSub"
assert len(hsub) == 48, "Default hSublen is 48"

# ── PBKDF2 vector ─────────────────────────────────────────────────────────────

key_bytes = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode('utf-8'), salt_bytes, 100000)
assert len(key_bytes) == 32, "PBKDF2-SHA256 default dklen is 32"

# ── AES-GCM vector ────────────────────────────────────────────────────────────

PLAINTEXT = '{"msg_type":"bus","payload":"test"}'
cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
ciphertext_bytes, tag_bytes = cipher.encrypt_and_digest(PLAINTEXT.encode('utf-8'))

# Verify round-trip
cipher2 = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
recovered = cipher2.decrypt_and_verify(ciphertext_bytes, tag_bytes).decode('utf-8')
assert recovered == PLAINTEXT, "Round-trip must succeed"

# ── Write vectors.json ────────────────────────────────────────────────────────

# ── Bitstring vector ──────────────────────────────────────────────────────────

BITSTRING_PAYLOAD = '{"type":"test"}'
bitstr = get_bitstring(HiveMessageType.BUS, payload=BITSTRING_PAYLOAD,
                       hivemeta={}, compressed=False, versioned=False)

vectors = {
    "hsub": {
        "password":       PASSWORD,
        "iv_hex":         IV_HEX,
        "expected_hsub":  hsub
    },
    "pbkdf2": {
        "password":          PASSWORD,
        "salt_hex":          SALT_HEX,
        "expected_key_hex":  key_bytes.hex()
    },
    "aes_gcm": {
        "key_hex":        key_bytes.hex(),
        "plaintext":      PLAINTEXT,
        "nonce_hex":      NONCE_HEX,
        "ciphertext_hex": ciphertext_bytes.hex(),
        "tag_hex":        tag_bytes.hex()
    },
    "bitstring": {
        "msg_type":    "bus",
        "payload":     BITSTRING_PAYLOAD,
        "metadata":    {},
        "compressed":  False,
        "versioned":   False,
        "expected_hex": bitstr.bytes.hex()
    }
}

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2)

print(f"Vectors written to {out_path}")
print(json.dumps(vectors, indent=2))
