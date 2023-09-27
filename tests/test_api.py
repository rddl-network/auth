import hashlib
from fastapi.testclient import TestClient
#from planetmint_cryptoconditions.crypto import Ed25519SigningKey, Ed25519VerifyingKey
from auth.main import app
from auth.app.auth import challenges, validate_signature_data_string
from auth.app.JWTBearer import JWTBearer
from auth.config import JWT_DOMAIN

client = TestClient(app)

VK_HEX_ILP = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"  # noqa E501
VK_B64_ILP = b"7Bcrk61eVjv0kyxw4SRQNMNUZ+8u/U1k6/gZaDRn4r8="
VK_B58_ILP = b"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU"
VK_BYT_ILP = b"\xec\x17+\x93\xad^V;\xf4\x93,p\xe1$P4\xc3Tg\xef.\xfdMd\xeb\xf8\x19h4g\xe2\xbf"  # noqa E501


SK_HEX_ILP = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"  # noqa E501
SK_B64_ILP = b"gz/mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI="
SK_B58_ILP = b"9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs"
SK_BYT_ILP = b"\x83?\xe6$\t#{\x9db\xecwXu \x91\x1e\x9au\x9c\xec\x1d\x19u[}\xa9\x01\xb9m\xca=B"  # noqa E501


#def sign_challenge(challenge):
#    sk = Ed25519SigningKey(SK_B58_ILP)
#
#    byte_string = bytes(challenge, "utf-8")
#    hash_local = hashlib.sha256()
#    hash_local.update(byte_string)
#
#    signature = sk.sign(hash_local.digest())
#    return signature

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
    
    byte_string = bytes(message, "utf-8")
    hash_local = hashlib.sha256()
    hash_local.update(byte_string)
    
    #signature = sk.sign(message.encode('utf-8'))
    signature = sk.sign( hash_local.digest() )
    
    return sk.to_string().hex(), hexlify(signature).decode('utf-8')

# # Sample usage
# message = "Hello, World!"

# privkey, signature = sign_message(message)
# print(f"Private Key: {privkey}")
# print(f"Signature: {signature}")







def test_challenge_response_cycle():
    response = client.get(f"auth?public_key={VK_B58_ILP.decode()}")
    assert response.status_code == 200
    assert len(response.json()["challenge"]) == 256

    assert challenges[VK_B58_ILP.decode()][0].hex() == response.json()["challenge"]
    sign_message( response.json()["challenge"] )
    signature = sign_challenge(response.json()["challenge"])

    public_key_hex = ""
    jwt_response = client.post(f"auth?public_key={public_key_hex}&signature={signature.decode()}")
    assert jwt_response.status_code == 200

    decoded_token = JWTBearer.decodeJWT(jwt_response.json()["access_token"])
    assert decoded_token["actor"] == f"{VK_B58_ILP.decode()}@{JWT_DOMAIN}"

# def test_verifiation():
    # payload = "5f965e52b20ec3ea2be4caf27e5c69b0aa62e94c69f005d157236c027c0f37b09178753aa85472ad62cd856bce33afc7b622e208710e4339608494f988a57801b244fdfe1ab5289d8e53434a355013a83066517b750a4b2b3bb82492f2aed94703c7d36258770b955adfa8549b35ba93452835adc451ff35d146335bb1e760f"
    # hash = "A00E49955384802BD942C7FDDB98564EA9FBD53C151D38B196BE27B947A9C3C7"
    # sig = "5jNsyxcgupJkyytkyJUPpQvLb4jpaRbJXxSSNG7AzALV2V7xQ3Ld4kHDNq7qeyUKuGUqNSbJD3YtejvM7dQYtBQh"
    # pub_key= "ZTzU4e8KaoiH5n9zTfLWnRmow8dsPheyeqgWvjGCBx5i"
    # result = validate_signature_data_string( pub_key, sig, payload )
    # assert result == True
    # 
# def test_sign_and_verify():
    # payload = "5f965e52b20ec3ea2be4caf27e5c69b0aa62e94c69f005d157236c027c0f37b09178753aa85472ad62cd856bce33afc7b622e208710e4339608494f988a57801b244fdfe1ab5289d8e53434a355013a83066517b750a4b2b3bb82492f2aed94703c7d36258770b955adfa8549b35ba93452835adc451ff35d146335bb1e760f"
    # hash = "A00E49955384802BD942C7FDDB98564EA9FBD53C151D38B196BE27B947A9C3C7"
    sig = "5jNsyxcgupJkyytkyJUPpQvLb4jpaRbJXxSSNG7AzALV2V7xQ3Ld4kHDNq7qeyUKuGUqNSbJD3YtejvM7dQYtBQh"
    sig = "5jNsyxcgupJkyytkyJUPpQvLb4jpaRbJXxSSNG7AzALV2V7xQ3Ld4kHDNq7qeyUKuGUqNSbJD3YtejvM7dQYtBQh"
    # sig = "5jNsyxcgupJkyytkyJUPpQvLb4jpaRbJXxSSNG7AzALUvDrpcG7KDaNSfsfxLE1KSwMAs8ru34CLcYEsd1mUHkKq"
    sig = "2Q3Vnrsx4ZXPQpukh8yH3kKhJ92wNknoQH8SjYHkFr57BAzpjmfdq14Jk7runqyAPKfNxGZHwPFD46KfmiwetCAq"
    # pub_key= "GEg6ZrNinkyWWhNaEVADbCyHgdzYeVatAnjC4oqRfzqS"
    pub_key = "6V8ycJdv7kPiXpAhCgk6YPrmc35yMnCCvxP4YnGzvhp9"
    # priv_key = "3hMh9bWEDQHH6yMFTTtSvpcon126MA2qm2m47R4bwV9r"
    # 
    # public_hex = 'E2600F746C5DE0FA70A8BEB5F6D721D3A8442ACFAF55019B8236ABF1752EBB6D'
    # public_hex = public_hex.lower()
    # vk_from_b58 = Ed25519VerifyingKey(pub_key, 'base58')
    # vk_from_hex = Ed25519VerifyingKey(public_hex, 'hex')
    # assert vk_from_b58.encode().decode() == vk_from_hex.encode().decode()
    ret = vk_from_hex.verify(hash.lower(), signature=sig)
    ret2 = vk_from_b58.verify(hash.lower(), signature=sig)
    # priv_hex = '280E00C2CADC4CEFE17DCB21A9C8266175E42AF0DFD61E95112E80F2FD0BA761'
    # priv_hex = priv_hex.lower()
    # 
    # sk = Ed25519SigningKey(priv_hex, 'hex')
    # assert sk._signing_key.hex() == '280e00c2cadc4cefe17dcb21a9c8266175e42af0dfd61e95112e80f2fd0ba761e2600f746c5de0fa70a8beb5f6d721d3a8442acfaf55019b8236abf1752ebb6d'
    # vk_from_sk = sk.get_verifying_key()
    # assert vk_from_sk.encode().decode() == vk_from_hex.encode().decode()
    # assert vk_from_sk.encode().decode() == pub_key
    # 
# 
    # byte_string = bytes(payload, "utf-8")
    # hash_local = hashlib.sha256()
    # hash_local.update(byte_string)
    # assert hash_local.digest().hex() == hash.lower()
    assert "ZTzU4e8KaoiH5n9zTfLWnRmow8dsPheyeqgWvjGCBx5i" == "ZTzU4e8KaoiH5n9zTfLWnRmow8dsPheyeqgWvjGCBx5i"
    # signature = sk.sign(hash_local.digest())
    # assert signature.decode()    == sig
# 
# 
# 