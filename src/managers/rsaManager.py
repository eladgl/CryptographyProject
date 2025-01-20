from .cryptoManager import CryptoManager
from ..core.crypto.rsa import generate_key_pair, encrypt, decrypt

class RSAManager(CryptoManager):
    def __init__(self, rsa_key_size=(61, 53)):
        super().__init__()
        self.public_key, self.private_key = generate_key_pair(*rsa_key_size)

    def encrypt(self, key, plaintext):
        """Encrypt plaintext using the RSA public key."""
        return encrypt(key, plaintext)

    def decrypt(self, key, ciphertext):
        """Decrypt ciphertext using the RSA private key."""
        return decrypt(key, ciphertext)
    
    def get_public_key(self):
        return self.public_key
    
    def get_private_key(self):
        return self.private_key
