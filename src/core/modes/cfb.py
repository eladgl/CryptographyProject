from src.core.crypto.blowfish import Blowfish

BLOCK_SIZE = 8  # Blowfish block size is 8 bytes (64 bits)

def _xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """
    XOR two byte strings, up to the length of the shorter one.
    """
    return bytes(a ^ b for a, b in zip(b1, b2))

class BlowfishCFB:
    """
    A class-based approach to Blowfish encryption/decryption in CFB mode.

    Usage:
        cfb_cipher = BlowfishCFB(key, iv)
        ciphertext = cfb_cipher.encrypt(plaintext)
        recovered_plaintext = cfb_cipher.decrypt(ciphertext)
    """

    def __init__(self, key, iv):
        """
        Initialize the CFB cipher with a Blowfish key and IV.

        :param key: Blowfish key (4-56 bytes)
        :param iv:  8-byte Initialization Vector
        """
        # Create an instance of your Blowfish class
        self._cipher = Blowfish(key)

        # Must be exactly 8 bytes for Blowfish
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be {BLOCK_SIZE} bytes for Blowfish CFB.")

        self._iv = iv  # We'll use or copy this as needed

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using Blowfish in CFB mode.

        :param plaintext: Data to encrypt (bytes)
        :return:          Ciphertext (bytes)
        """
        offset = 0
        ciphertext = b""
        # Current feedback register starts with the IV
        feedback = self._iv  

        while offset < len(plaintext):
            # Grab next chunk of up to 8 bytes
            block = plaintext[offset : offset + BLOCK_SIZE]

            # STEP 1: Encrypt the feedback to get keystream
            L = int.from_bytes(feedback[0:4], "big")
            R = int.from_bytes(feedback[4:8], "big")
            eL, eR = self._cipher.encrypt_block(L, R)
            keystream = eL.to_bytes(4, "big") + eR.to_bytes(4, "big")

            # STEP 2: XOR keystream with plaintext block -> ciphertext block
            cfb_block = _xor_bytes(keystream[: len(block)], block)

            # STEP 3: Append the resulting ciphertext block
            ciphertext += cfb_block

            # STEP 4: Update feedback
            # If block is full 8 bytes, entire block replaces feedback
            # If it's smaller, we replace that part, keep the remainder of the old feedback
            if len(block) == BLOCK_SIZE:
                feedback = cfb_block
            else:
                feedback = cfb_block + feedback[len(block) :]

            offset += BLOCK_SIZE

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using Blowfish in CFB mode.

        :param ciphertext: Data to decrypt (bytes)
        :return:           Plaintext (bytes)
        """
        offset = 0
        plaintext = b""
        feedback = self._iv

        while offset < len(ciphertext):
            block = ciphertext[offset : offset + BLOCK_SIZE]

            # STEP 1: Encrypt feedback -> keystream (same as in encrypt)
            L = int.from_bytes(feedback[0:4], "big")
            R = int.from_bytes(feedback[4:8], "big")
            eL, eR = self._cipher.encrypt_block(L, R)
            keystream = eL.to_bytes(4, "big") + eR.to_bytes(4, "big")

            # STEP 2: XOR keystream with ciphertext block -> plaintext block
            pBlock = _xor_bytes(keystream[: len(block)], block)
            plaintext += pBlock

            # STEP 3: Update feedback with the actual ciphertext block
            if len(block) == BLOCK_SIZE:
                feedback = block
            else:
                feedback = block + feedback[len(block) :]

            offset += BLOCK_SIZE

        return plaintext
