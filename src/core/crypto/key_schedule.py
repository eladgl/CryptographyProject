"""
key_schedule
============
Handles key expansion for the Blowfish cipher.

Functions
---------
initialize_key(key: bytes) -> tuple
    Expands the given key using P-Box transformations and Feistel iterations.
"""

def init_P_array(key, P):
    """
    Initializes the P-array by XORing it with the key.

    Parameters
    ----------
    key : bytes
        The key to be used for initialization.
    P : np.ndarray
        The P-array to initialize.
    """
    key_len = len(key)
    key_pos = 0

    for i in range(len(P)):
        k = 0
        for _ in range(4):
            k = (k << 8) | key[key_pos]
            key_pos = (key_pos + 1) % key_len
        P[i] ^= k

def key_scheduler(key, S, P, encrypt_block):
    """
    Completes the key scheduling process by expanding the key into the P-array and S-boxes.

    Parameters
    ----------
    key : bytes
        The key for the Blowfish cipher.
    S : dict
        The S-boxes (4 arrays of 256 elements each).
    P : np.ndarray
        The P-array to be initialized.
    encrypt_block : function
        The function to encrypt blocks, used for key expansion.

    Returns
    -------
    tuple
        Updated P-array and S-boxes.
    """
    # Initialize P-array
    init_P_array(key, P)

    # Initialize with zeros
    L, R = 0, 0

    # Blowfish key expansion for P-array
    for i in range(0, len(P), 2):
        L, R = encrypt_block(L, R)
        P[i] = L
        P[i + 1] = R

    # Fill S-boxes by encrypting L and R
    for i in range(4):
        for j in range(0, 256, 2):
            L, R = encrypt_block(L, R)
            S[i][j] = L
            S[i][j + 1] = R

    return P, S
