from src.core.modes.cfb import BlowfishCFB

def test_cfb():
    """
    Basic test with an 8-byte IV and some plaintext that is
    longer than 8 bytes.
    Should PASS (assert recovered == plaintext).
    """
    key = b"hello"
    iv  = b"00000000"  # Must be exactly 8 bytes
    plaintext = b"hello my name is yarden"

    cfb_cipher = BlowfishCFB(key, iv)

    # Encrypt
    ciphertext = cfb_cipher.encrypt(plaintext)
    # Print ciphertext as hex
    print("[test_cfb] Ciphertext (hex):", ciphertext.hex())

    # Decrypt
    recovered = cfb_cipher.decrypt(ciphertext)
    print("[test_cfb] Recovered:", recovered)

    # Check the result
    assert recovered == plaintext, "[test_cfb] CFB Decryption failed!"
    print("[test_cfb] Test passed!\n")

def test_cfb_partial_block():
    """
    Tests CFB with a plaintext whose length is NOT a multiple of 8 bytes,
    ensuring partial blocks are handled properly.
    Should PASS if your CFB implementation supports partial blocks correctly.
    """
    key = b"secret"
    iv = b"12345678"
    # 15 bytes -> not multiple of 8
    plaintext = b"short message!"

    cfb_cipher = BlowfishCFB(key, iv)

    ciphertext = cfb_cipher.encrypt(plaintext)
    print("[test_cfb_partial_block] Ciphertext (hex):", ciphertext.hex())

    recovered = cfb_cipher.decrypt(ciphertext)
    print("[test_cfb_partial_block] Recovered:", recovered)

    assert recovered == plaintext, "[test_cfb_partial_block] Partial block decryption failed!"
    print("[test_cfb_partial_block] Test passed!\n")

def test_cfb_wrong_key():
    """
    Encrypt with one key, then attempt to decrypt with a DIFFERENT key.
    We EXPECT this to FAIL (the recovered text won't match the original).
    """
    key_encrypt = b"correct"
    key_decrypt = b"wronggg"

    iv = b"ABCDEFGH"
    plaintext = b"This should fail"

    cfb_cipher_enc = BlowfishCFB(key_encrypt, iv)
    ciphertext = cfb_cipher_enc.encrypt(plaintext)
    print("[test_cfb_wrong_key] Ciphertext (hex):", ciphertext.hex())

    # Decrypt with a different key
    cfb_cipher_dec = BlowfishCFB(key_decrypt, iv)
    recovered = cfb_cipher_dec.decrypt(ciphertext)

    try:
        # Attempt to decode as UTF-8 string
        print("[test_cfb_wrong_key] Recovered:", recovered.decode("utf-8"))
    except UnicodeDecodeError:
        # Handle invalid UTF-8 bytes
        print("[test_cfb_wrong_key] Recovered: (non-decodable bytes)", recovered)

    # This assertion SHOULD fail (recovered != plaintext)
    assert recovered != plaintext, (
        "[test_cfb_wrong_key] This test is expected to FAIL, "
        "but it passed unexpectedly!"
    )
    print("[test_cfb_wrong_key] Test passed (unexpected)!\n")

# We'll run ALL tests in sequence.
# 1) Should PASS
test_cfb()

# 2) Should PASS if partial blocks are handled
test_cfb_partial_block()

# 3) EXPECTED to FAIL
print("Running test_cfb_wrong_key (expected to FAIL)...")
test_cfb_wrong_key()

print("Finished running all tests.")
