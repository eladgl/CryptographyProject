from src.core.signature.ec_elgamal import ECElGamal
import pytest


# Test the polynomial generation for elliptic curve
def test_polynomial():
    ec = ECElGamal(a=2, b=3, n=7)
    LHS = [[]]
    RHS = [[]]
    LHS.append([])
    RHS.append([])

    ec.polynomial(LHS, RHS)

    assert len(LHS[0]) == ec.n
    assert len(LHS[1]) == ec.n
    assert len(RHS[0]) == ec.n
    assert len(RHS[1]) == ec.n


# Test the point generation on the elliptic curve
def test_points_generate():
    ec = ECElGamal(a=2, b=3, n=7)
    LHS = [[0, 1, 2, 3, 4, 5, 6], [3, 6, 6, 3, 3, 6, 0]]
    RHS = [[0, 1, 2, 3, 4, 5, 6], [0, 1, 4, 2, 2, 4, 1]]

    arr_x, arr_y = ec.points_generate(LHS, RHS)

    assert len(arr_x) > 0
    assert len(arr_y) > 0


# Test the selection of a base point
def test_generate_base_point():
    ec = ECElGamal(a=2, b=3, n=7)
    arr_x = [1, 2, 3]
    arr_y = [4, 5, 6]

    bx, by = ec.generate_base_point(arr_x, arr_y)

    assert bx == 1
    assert by == 4


# Test public key generation with clear error message
def test_generate_public_key():
    ec = ECElGamal(a=2, b=3, n=7)
    bx, by = 2, 3
    d = 4

    Qx, Qy = ec.generate_public_key(bx, by, d)

    assert Qx == (d * bx) % ec.n
    assert Qy == (d * by) % ec.n

    # Test invalid private key
    with pytest.raises(ValueError, match="Private key \(d=10\) must be less than the order of the curve \(n=7\)"):
        ec.generate_public_key(bx, by, 10)


# Test encryption of a message with clear error message
def test_encrypt_message():
    ec = ECElGamal(a=2, b=3, n=7)
    bx, by = 2, 3
    Qx, Qy = 4, 5
    k = 3
    M = 6

    (C1x, C1y), (C2x, C2y) = ec.encrypt_message(bx, by, Qx, Qy, k, M)

    assert C1x == (k * bx) % ec.n
    assert C1y == (k * by) % ec.n
    assert C2x == (k * Qx + M) % ec.n
    assert C2y == (k * Qy + M) % ec.n

    # Test invalid random number k
    with pytest.raises(ValueError, match="Random number \(k=10\) must be less than the order of the curve \(n=7\)"):
        ec.encrypt_message(bx, by, Qx, Qy, 10, M)


# Test decryption of a message
def test_decrypt_message():
    ec = ECElGamal(a=2, b=3, n=7)
    C1x, C1y = 2, 3
    C2x, C2y = 6, 7
    d = 3

    Mx, My = ec.decrypt_message(C1x, C1y, C2x, C2y, d)

    assert Mx == (C2x - d * C1x) % ec.n
    assert My == (C2y - d * C1y) % ec.n


# Test invalid base point selection
def test_invalid_base_point():
    ec = ECElGamal(a=2, b=3, n=7)
    arr_x = []
    arr_y = []

    with pytest.raises(ValueError, match="No valid points on the curve"):
        ec.generate_base_point(arr_x, arr_y)


if __name__ == "__main__":
    pytest.main()
