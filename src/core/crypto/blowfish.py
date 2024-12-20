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
from constants import S_BOXES, P_ARRAY

class Blowfish:
    def __init__(self, key: bytes):
        self.s_boxes = {i: S_BOXES[i].copy() for i in range(4)}
        self.p_array = P_ARRAY.copy()
        self.key = key
