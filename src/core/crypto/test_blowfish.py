from src.core.crypto.blowfish import Blowfish

def test_blowfish():
    key = b"examplekey123456"  # Must be between 4 and 56 bytes
    plaintext = b"TestData"    # Must be 8 bytes (64 bits)

    # Initialize Blowfish with the given key
    blowfish = Blowfish(key)

    # Encrypt the plaintext
    encrypted = blowfish.encrypt(plaintext)

    # Decrypt the ciphertext
    decrypted = blowfish.decrypt(encrypted)

    # Assert that decrypted plaintext matches the original plaintext
    
    assert decrypted == plaintext, "Decryption failed: {0} != {1}".format(decrypted, plaintext)
    print("Encrypted plaintext is: {0}".format(encrypted))

    print("Blowfish test passed! Plaintext: {0}".format(plaintext))

