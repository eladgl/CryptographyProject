import base64
from ..core.modes.cfb import BlowfishCFB

class CipherManager:
    def __init__(self, key, iv=b"00000000"):
        """
        Initialize the cipher manager with a key and IV.

        :param key: The encryption key (bytes).
        :param iv: The initialization vector (bytes, default is 8 zero bytes).
        """
        self.key = key
        self.iv = iv
        self.cipher = BlowfishCFB(self.key, self.iv)

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext using Blowfish in CFB mode.

        :param plaintext: The plaintext to encrypt (bytes).
        :return: The encrypted message (Base64-encoded string).
        """
        encrypted = self.cipher.encrypt(plaintext)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encrypted_base64):
        """
        Decrypt the encrypted message using Blowfish in CFB mode.

        :param encrypted_base64: The Base64-encoded encrypted message (string).
        :return: The decrypted plaintext (bytes).
        """
        encrypted_bytes = base64.b64decode(encrypted_base64)
        return self.cipher.decrypt(encrypted_bytes)

    def reset_cipher(self):
        """Reinitialize the cipher (useful if the key or IV changes)."""
        self.cipher = BlowfishCFB(self.key, self.iv)
