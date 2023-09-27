import pytest
import hashlib
import pytest
import hashlib
from fastapi.testclient import TestClient
from auth.main import app
import os
from ecdsa import SigningKey, SECP256k1
from binascii import hexlify

def sign_message(message, privkey_hex=None):
    """
    Sign a message using ECDSA with the SECP256k1 curve.
    
    Args:
    - message (str): The message to sign.
    - privkey_hex (str, optional): Optional private key in hex. If not provided, a new one will be generated.

    Returns:
    - tuple: private key (hex), signature (hex)
    """
    
    # Generate a new private key if not provided
    if not privkey_hex:
        sk = SigningKey.generate(curve=SECP256k1)
    else:
        sk = SigningKey.from_string(bytes.fromhex(privkey_hex), curve=SECP256k1)
    
    signature = sk.sign(message.encode('utf-8'))
    
    return sk.to_string().hex(), hexlify(signature).decode('utf-8')

# Sample usage
message = "Hello, World!"

privkey, signature = sign_message(message)
print(f"Private Key: {privkey}")
print(f"Signature: {signature}")





def sign_challenge(challenge):
    SK_B58_ILP = b"9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs"
    sk = Ed25519SigningKey(SK_B58_ILP)

    byte_string = bytes(challenge, "utf-8")
    hash_local = hashlib.sha256()
    hash_local.update(byte_string)

    signature = sk.sign(hash_local.digest())
    return signature


@pytest.fixture
def bearer_token():
    client = TestClient(app)
    VK_B58_ILP = b"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU"
    response = client.get(f"auth?public_key={VK_B58_ILP.decode()}")
    signature = sign_challenge(response.json()["challenge"])

    jwt_response = client.post(f"auth?public_key={VK_B58_ILP.decode()}&signature={signature.decode()}")
    return jwt_response.json()["access_token"]
