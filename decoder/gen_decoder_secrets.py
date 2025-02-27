#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import hashlib
import json
import os
import sys

SECRETS_FILE = "src/secrets.c"
KEY_LEN = 16


def write_header():
    with open(SECRETS_FILE, "w") as f:
        f.write('#include "cryptosystem.h"\n\n')


def gen_subscription_key(decoder_id, secrets):
    shared_key_root = bytes.fromhex(secrets["shared_key_root"])

    h = hashlib.sha256()
    h.update(shared_key_root)
    h.update(decoder_id)
    subscription_key = h.digest()[:KEY_LEN]

    with open(SECRETS_FILE, "a") as f:
        f.write("const aeskey_t SUBSCRIPTION_KEY = { .bytes = {")
        f.write(",".join([f"0x{b:02x}" for b in subscription_key]))
        f.write("} };\n")


def write_ch0(secrets):
    ch0 = bytes.fromhex(secrets["root_keys"]["0"])

    with open(SECRETS_FILE, "a") as f:
        f.write(
            "const kdf_node_t SUB0_NODE = { .level = 0, .index = 0, .key = { .bytes = {"
        )
        f.write(",".join([f"0x{b:02x}" for b in ch0]))
        f.write("} } };\n")


def write_pubkey(secrets):
    privkey_bytes = bytes.fromhex(secrets["signing_key"])
    privkey = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    pubkey = privkey.public_key()
    pubkey_bytes = pubkey.public_bytes_raw()

    with open(SECRETS_FILE, "a") as f:
        f.write("const uint8_t SK_BYTES[32] = {")
        f.write(",".join([f"0x{b:02x}" for b in pubkey_bytes]))
        f.write("};\n")


if __name__ == "__main__":
    decoder_id = sys.argv[1][2:] if sys.argv[1].startswith("0x") else sys.argv[1]
    decoder_id = "0" * (8 - len(decoder_id)) + decoder_id
    decoder_id = bytes.fromhex(decoder_id)
    if len(sys.argv) > 2:
        secrets_file = sys.argv[2]
    else:
        secrets_file = (
            "/global.secrets"
            if os.path.exists("/global.secrets")
            else "../global.secrets"
        )
    secrets = json.load(open(secrets_file, "rb"))
    write_header()
    gen_subscription_key(decoder_id, secrets)
    write_ch0(secrets)
    write_pubkey(secrets)
