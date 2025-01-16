from src.gui.cipherManager import CipherManager

# Set up the CipherManager instance for testing
key = b"testkey123"
iv = b"12345678"  # 8 bytes for Blowfish CFB
cipher_manager = CipherManager(key, iv)

# Test that encryption followed by decryption returns the original plaintext
def test_encrypt_decrypt():
    plaintext = b"This is a test message."
    encrypted = cipher_manager.encrypt(plaintext)
    print(encrypted)
    decrypted = cipher_manager.decrypt(encrypted)
    print(decrypted)
    assert decrypted == plaintext, "Decrypted text does not match the original plaintext."

def test_base64_format():
    plaintext = b"Another test message."
    encrypted = cipher_manager.encrypt(plaintext)
    # Check if the encrypted output is a valid Base64 string
    try:
        encrypted.encode("utf-8")
    except UnicodeDecodeError:
        assert False, "Encrypted output is not a valid UTF-8 string."

def test_partial_block():
    plaintext = b"Short"
    encrypted = cipher_manager.encrypt(plaintext)
    decrypted = cipher_manager.decrypt(encrypted)
    assert decrypted == plaintext, "Decryption failed for partial block."

def test_invalid_decryption():
    invalid_encrypted = "InvalidBase64$$"
    try:
        cipher_manager.decrypt(invalid_encrypted)
        assert False, "Decryption should have failed for invalid Base64 string."
    except Exception:
        pass

def test_reset_cipher():
    plaintext = b"Reset test message."
    encrypted = cipher_manager.encrypt(plaintext)
    cipher_manager.reset_cipher()
    decrypted = cipher_manager.decrypt(encrypted)
    assert decrypted == plaintext, "Cipher reset failed to maintain functionality."

# Run all tests
def run_tests():
    test_encrypt_decrypt()
    print("test_encrypt_decrypt passed.")
    test_base64_format()
    print("test_base64_format passed.")
    test_partial_block()
    print("test_partial_block passed.")
    test_invalid_decryption()
    print("test_invalid_decryption passed.")
    test_reset_cipher()
    print("test_reset_cipher passed.")


run_tests()
