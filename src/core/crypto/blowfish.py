"""
blowfish
========
Implements high-level Blowfish encryption and decryption logic.

Dependencies
------------
- Uses submodules in `blowfish` for specific components like key scheduling, 
  S-Boxes, and the Feistel network.

Classes
-------
BlowfishCipher
    A class that handles Blowfish encryption and decryption.
"""
import numpy as np

from .function_f import func_f
from .key_schedule import key_scheduler
from .utilities import give_four_s

from .constants import P_ARRAY, S_BOXES

class Blowfish:
    def __init__(self, key):
        self.P = P_ARRAY.copy()
        self.S = {i: S_BOXES[i].copy() for i in range(4)}
        
        # Perform key scheduling
        self.P, self.S = key_scheduler(key, self.S, self.P, self.encrypt_block)    

    def encrypt_block(self, L, R):
        """
        Encrypt a single 64-bit block.

        Parameters
        ----------
        L : int
            The left 32 bits of the block.
        R : int
            The right 32 bits of the block.

        Returns
        -------
        tuple
            The encrypted left and right 32-bit integers.
        """
        for round in range(16):
            L = L ^ self.P[round]
            R = func_f(L, *give_four_s(self.S)) ^ R
            L, R = R, L  # Swap
        L, R = R, L  # Undo last swap
        R = R ^ self.P[16]
        L = L ^ self.P[17]
        return int(L), int(R)

    def decrypt_block(self, L, R):
        """Decrypt a single 64-bit block."""
        # Undo final round swap from encryption
        L, R = R, L
        R = R ^ self.P[17]
        L = L ^ self.P[16]

        # Reverse rounds (15 to 0)
        for round in range(15, -1, -1):
            L, R = R, L  # Swap
            R = func_f(L, *give_four_s(self.S)) ^ R
            L = L ^ self.P[round]

        return L, R

    def encrypt(self, data):
        """Encrypts the provided data. Data must be a multiple of 8 bytes."""
        assert len(data) % 8 == 0, "Data length must be a multiple of 8 bytes."

        encrypted = b""
        for i in range(0, len(data), 8):
            L = int.from_bytes(data[i:i+4], 'big')
            R = int.from_bytes(data[i+4:i+8], 'big')
            L, R = self.encrypt_block(L, R)
            encrypted += L.to_bytes(4, 'big') + R.to_bytes(4, 'big')
        return encrypted

    def decrypt(self, data):
        """Decrypts the provided data. Data must be a multiple of 8 bytes."""
        assert len(data) % 8 == 0, "Data length must be a multiple of 8 bytes."

        decrypted = b""
        for i in range(0, len(data), 8):
            L = int.from_bytes(data[i:i+4], 'big')
            R = int.from_bytes(data[i+4:i+8], 'big')
            L, R = self.decrypt_block(L, R)
            decrypted += int(L).to_bytes(4, 'big') + int(R).to_bytes(4, 'big')  # Explicit cast to int
        return decrypted
