from auth.app.auth import does_pub_key_belong_to_valid_actor, pubkey_to_bech32_address

# adress = plmnt1g7keu2rx8sn0j4zlca0lulzeknrglmlzh405f0
# pubkey = 02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f
# extended_pubkey = pmpb7v1HL92mjFwoRMETnLBnzrC8BJeWJfefxk6Ng7NZMH5nxxatz5rPefpQ8ZZgk4ta8v6KYWw7P19h92jAUxGJLLpFM2MRSH1vqXntmZ28vBC
prefix = "plmnt"


def test_valid_pubkey():
    pubkey = "02b32fa8d61eeda138a7afd0c377d9e6ac4df8c517668d3ddb18769ad473d69c6f"

    valid_pubkey_bytes = bytes.fromhex(pubkey)
    assert does_pub_key_belong_to_valid_actor(valid_pubkey_bytes)

    computed_address = pubkey_to_bech32_address(pubkey, prefix)
    print(computed_address)
    expected_adress = 'plmnt1g7keu2rx8sn0j4zlca0lulzeknrglmlzh405f0'
    assert computed_address == expected_adress

def test_invalid_pubkey():
    invalid_pubkey_hex = '02b32fa8d61eeda138a7afd0c372d9e6ac4df8c517668d3ddb132218769ad473d69c6f'
    expected_adress = 'plmnt1g7keu2rx8sn0j4zlca0lulzeknrglmlzh405f0'
    invalid_pubkey_bytes = bytes.fromhex(invalid_pubkey_hex)
    assert does_pub_key_belong_to_valid_actor(invalid_pubkey_bytes) == False
    computed_address = pubkey_to_bech32_address(invalid_pubkey_hex, prefix)
    assert computed_address != expected_adress