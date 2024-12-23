def func_f(x, S0, S1, S2, S3):
    """Function f used in Blowfish algorithm."""
    high_byte = (x >> 24) & 0xFF
    second_byte = (x >> 16) & 0xFF
    third_byte = (x >> 8) & 0xFF
    low_byte = x & 0xFF

    h = (int(S0[high_byte]) + int(S1[second_byte])) & 0xFFFFFFFF  # Explicit casting to int to avoid overflow
    h = h ^ int(S2[third_byte])
    return (h + int(S3[low_byte])) & 0xFFFFFFFF  # Explicit casting to int to avoid overflow
