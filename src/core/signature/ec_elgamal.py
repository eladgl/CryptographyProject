"""
ec_elgamal
==========
Implements the Elliptic Curve ElGamal (EC ElGamal) digital signature scheme.

Classes
-------
ECElGamal
    A class that handles EC ElGamal signature generation and verification.
"""
import hashlib

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
        strong_points = [p for p in zip(arr_x, arr_y) if p[0] > 2 and p[1] > 2]
        if not strong_points:
            raise ValueError("No strong points available.")
        return strong_points[0]  # Or pick randomly

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

        # Ensure Mx and My are within the valid message space
        if Mx < 0 or My < 0:
            raise ValueError(f"Decrypted message values out of bounds: Mx={Mx}, My={My}")

        return Mx, My


    def generate_ec_private_key(ec, seed=None):
            """
            Generate a private key for EC ElGamal (must be in the range [1, n-1]).

            :param ec: An instance of the ECElGamal class containing the curve's parameters.
            :param seed: Optional seed value for deterministic key generation (useful for testing).
            :return: A private key as an integer.
            """
            if not isinstance(ec, ECElGamal):
                raise ValueError("The 'ec' parameter must be an instance of ECElGamal.")
            
            n = ec.n  # Extract the order of the curve
            if seed is None:
                seed = "default_seed"  # Default seed if none is provided

            # Hash the seed to create a deterministic random value
            seed_hash = hashlib.sha256(str(seed).encode()).hexdigest()
            private_key = (int(seed_hash, 16) % (n - 1)) + 1

            if private_key <= 0 or private_key >= n:
                raise ValueError("Generated private key is out of range. Adjust your logic.")

            return private_key