"""
rsa
===
Implements RSA encryption and decryption for secure key exchange.

Classes
-------
RSAKeyPair
    Represents an RSA public-private key pair.
Functions
---------
encrypt_key(public_key: bytes, key: bytes) -> bytes
    Encrypts a symmetric key using the RSA public key.
decrypt_key(private_key: bytes, encrypted_key: bytes) -> bytes
    Decrypts an encrypted symmetric key using the RSA private key.
"""
