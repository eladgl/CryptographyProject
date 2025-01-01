"""
ec_elgamal
==========
Implements the Elliptic Curve ElGamal (EC ElGamal) digital signature scheme.

Classes
-------
ECElGamal
    A class that handles EC ElGamal signature generation and verification.
"""


class ECElGamal:
    def __init__(self, a, b, n):
        self.a = a
        self.b = b
        self.n = n

    def polynomial(self, LHS, RHS):
        for i in range(0, self.n):
            LHS[0].append(i)
            RHS[0].append(i)
            LHS[1].append((i * i * i + self.a * i + self.b) % self.n)
            RHS[1].append((i * i) % self.n)

    def points_generate(self, LHS, RHS):
        arr_x, arr_y = [], []
        for i in range(0, self.n):
            for j in range(0, self.n):
                if LHS[1][i] == RHS[1][j]:
                    arr_x.append(LHS[0][i])
                    arr_y.append(RHS[0][j])
        return arr_x, arr_y

    @staticmethod
    def generate_base_point(arr_x, arr_y):
        if not arr_x or not arr_y:
            raise ValueError("No valid points on the curve")
        return arr_x[0], arr_y[0]

    def generate_public_key(self, bx, by, d):
        if d >= self.n:
            raise ValueError(f"Private key (d={d}) must be less than the order of the curve (n={self.n}).")
        return (d * bx) % self.n, (d * by) % self.n

    def encrypt_message(self, bx, by, Qx, Qy, k, M):
        if k >= self.n:
            raise ValueError(f"Random number (k={k}) must be less than the order of the curve (n={self.n}).")
        C1x = (k * bx) % self.n
        C1y = (k * by) % self.n
        C2x = (k * Qx + M) % self.n
        C2y = (k * Qy + M) % self.n
        return (C1x, C1y), (C2x, C2y)

    def decrypt_message(self, C1x, C1y, C2x, C2y, d):
        Mx = (C2x - d * C1x) % self.n
        My = (C2y - d * C1y) % self.n
        return Mx, My
