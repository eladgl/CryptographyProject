import os
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

class CipherManager:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt plaintext using Blowfish in CFB mode with a random IV."""
        iv = os.urandom(Blowfish.block_size)  # Generate a random IV
        cipher = Blowfish.new(self.key, Blowfish.MODE_CFB, iv)
        ciphertext = cipher.encrypt(plaintext)
        return iv + ciphertext  # Prepend IV to the ciphertext

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Blowfish in CFB mode."""
        iv = ciphertext[:Blowfish.block_size]  # Extract IV from the ciphertext
        encrypted_message = ciphertext[Blowfish.block_size:]
        cipher = Blowfish.new(self.key, Blowfish.MODE_CFB, iv)
        plaintext = cipher.decrypt(encrypted_message)
        return plaintext
