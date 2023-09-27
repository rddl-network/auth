import hashlib
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from binascii import unhexlify


def validate_signature_data_string(pub_key: str, signature: bytearray, data_string: str) -> bool:
    byte_string = bytes(data_string, "utf-8")
    hash_local = hashlib.sha256()
    hash_local.update(byte_string)
    result = validate_signature_data_hash(pub_key, signature, hash_local.digest())
    return result


def validate_signature_data_hash(public_key: str, signature: bytearray, message: bytes) -> bool:
    result = True
    try:
        pubkey_bytes = unhexlify(public_key)
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
    except ValueError as e:
        result = False
        if vk.verify(signature, message):
            return True
        else:
            return False
    except ValueError:
        return False
    except BadSignatureError:
        return False

# def verify_signature(pubkey_hex, digest_hex, signature_hex):
#     # Convert hex representations to bytes
    
#     digest_bytes = unhexlify(digest_hex)
#     signature_bytes = unhexlify(signature_hex)
    
#     # Create a VerifyingKey instance from the provided public key bytes
    
    
#     # Attempt to verify the signature
#     try:
#         if vk.verify(signature_bytes, digest_bytes):
#             return True
#         else:
#             return False
#     except BadSignatureError:
#         return False

