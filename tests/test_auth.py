import random
from auth.app import auth


def test_verify_signed_challenge(mocker):
    mocker.patch('auth.app.auth.validate_signature_data_string', return_value=True)
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    challenge = auth.create_challenge(pub_key)
    signature = challenge.hex()
    assert auth.verify_signed_challenge(pub_key, signature)


def test_cleanup_pending_challenges():
    auth.challenges.clear()
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    challenge = auth.create_challenge(pub_key)
    assert pub_key in auth.challenges
    auth.challenges[pub_key] = (challenge, 0)
    auth.cleanup_pending_challenges()
    assert pub_key not in auth.challenges


def test_does_pub_key_belong_to_valid_actor():
    valid_pub_key = bytes.fromhex("02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f")
    invalid_pub_key = bytes.fromhex("01" * 33)
    assert auth.does_pub_key_belong_to_valid_actor(valid_pub_key)
    assert not auth.does_pub_key_belong_to_valid_actor(invalid_pub_key)


def test_is_pub_key_corresponding_to_address():
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    correct_address = auth.pubkey_to_bech32_address(pub_key, auth.DENOM)
    wrong_address = "plmnt1wrongaddress1234567890"
    assert auth.is_pub_key_corresponding_to_address(pub_key, correct_address)
    assert not auth.is_pub_key_corresponding_to_address(pub_key, wrong_address)


def test_bech32_conversion():
    hrp = "plmnt"
    data = [0, 1, 2, 3, 4, 5]
    encoded = auth.bech32_encode(hrp, data)
    assert isinstance(encoded, str)


def test_bech32_polymod():
    values = [ord(x) for x in "plmnt"]
    result = auth.bech32_polymod(values)
    assert isinstance(result, int)


def test_bech32_hrp_expand():
    hrp = "plmnt"
    result = auth.bech32_hrp_expand(hrp)
    assert isinstance(result, list)


def test_create_challenge():
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    challenge = auth.create_challenge(pub_key)
    assert isinstance(challenge, bytes)
    assert len(challenge) == auth.AUTH_CHALLENGE_SIZE


def test_valid_pub_key_actor():
    # Using a well-known valid public key for SECP256k1
    valid_pub_key = bytes.fromhex("02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f")
    assert auth.does_pub_key_belong_to_valid_actor(valid_pub_key)


def test_invalid_length_pub_key_actor():
    invalid_length_pub_key = bytes.fromhex("02b32fa8d6")
    assert not auth.does_pub_key_belong_to_valid_actor(invalid_length_pub_key)


def test_random_byte_data_pub_key_actor():
    random_byte_data = bytes([random.randint(0, 255) for _ in range(33)])
    assert not auth.does_pub_key_belong_to_valid_actor(random_byte_data)


# Positive and Negative Tests for is_pub_key_corresponding_to_address

def test_mismatched_pub_key_and_address():
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    mismatched_address = "plmnt1randomaddress1234567890"
    assert not auth.is_pub_key_corresponding_to_address(pub_key, mismatched_address)


def test_valid_pub_key_random_address():
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    random_address = "plmnt" + ''.join([random.choice(auth.CHARSET) for _ in range(39)])
    assert not auth.is_pub_key_corresponding_to_address(pub_key, random_address)


# Positive and Negative Tests for bech32_encode

def test_bech32_encode_random_data():
    hrp = "plmnt"
    random_data = [random.randint(0, 31) for _ in range(6)]
    encoded = auth.bech32_encode(hrp, random_data)
    assert isinstance(encoded, str)


def test_bech32_encode_invalid_hrp():
    invalid_hrp = "invalidhrp"
    data = [0, 1, 2, 3, 4, 5]
    encoded = auth.bech32_encode(invalid_hrp, data)
    assert isinstance(encoded, str)


# Positive and Negative Tests for create_challenge

def test_create_challenge_repeated_calls():
    pub_key = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"
    challenge1 = auth.create_challenge(pub_key)
    challenge2 = auth.create_challenge(pub_key)
    assert challenge1 != challenge2  # Challenges should be different


def test_create_challenge_invalid_pub_key():
    invalid_pub_key = "invalidpubkey"
    challenge = auth.create_challenge(invalid_pub_key)
    # If the function doesn't raise an exception, we can test the output instead
    assert challenge is None or isinstance(challenge, bytes)
