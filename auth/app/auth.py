import hashlib
import time
import random
import ecdsa

from auth.app.verify_signature import validate_signature_data_string
from auth.config import (
    AUTH_CHALLENGE_SIZE,
    AUTH_CHALLENGE_TIMEOUT_IN_SEC,
)


# Bech32 Encoding
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_SEPARATOR = '1'
DENOM = "plmnt"

challenges = {}


def cleanup_pending_challenges():
    for key in list(challenges.keys()):
        if challenges[key][1] + AUTH_CHALLENGE_TIMEOUT_IN_SEC < time.time():
            del challenges[key]


def does_pub_key_belong_to_valid_actor(pub_key: bytes) -> bool:
    try:
        ecdsa.VerifyingKey.from_string(pub_key, curve=ecdsa.SECP256k1)
        return True
    except ecdsa.keys.MalformedPointError:
        return False


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_encode(hrp, data):
    combined = bech32_hrp_expand(hrp) + data
    checksum = bech32_create_checksum(hrp, data)
    return hrp + BECH32_SEPARATOR + ''.join([CHARSET[d] for d in data + checksum])


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


# Convert public key to address
def pubkey_to_bech32_address(pubkey: str, hrp: str) -> str:
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey)).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    data = convertbits(ripemd160_hash, 8, 5)
    return bech32_encode(hrp, data)


def is_pub_key_corresponding_to_address(pub_key: str, address: str) -> bool:
    return pubkey_to_bech32_address(pub_key, DENOM) == address
