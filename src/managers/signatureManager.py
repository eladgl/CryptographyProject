from .cryptoManager import CryptoManager
from ..core.signature.ec_elgamal import ECElGamal

class SignatureManager(CryptoManager):
    def __init__(self, curve_params=(2, 6, 3253)):
        super().__init__()
        self.ecelgamal = ECElGamal(*curve_params)
        self.private_key = self.ecelgamal.generate_ec_private_key(curve_params[2])
        self.base_point = self.ecelgamal.generate_base_point(*self._generate_curve_points())
        self.public_key = self.ecelgamal.generate_public_key(
            self.base_point[0], self.base_point[1], self.private_key
        )

    def _generate_curve_points(self):
        LHS, RHS = [[], []], [[], []]
        self.ecelgamal.polynomial(LHS, RHS)
        return self.ecelgamal.points_generate(LHS, RHS)

    def sign_message(self, recipient_public_key_ec_x, recipient_public_key_ec_y, k, message):
        """Sign a message using the private key."""
        # Example of signing using EC ElGamal
        return self.ecelgamal.encrypt_message(
                    self.base_point[0], self.base_point[1],
                    recipient_public_key_ec_x, recipient_public_key_ec_y,
                    k, message
                )
    
    def decrypt(self, encrypted_part):
        C1x, C1y = encrypted_part[0]
        C2x, C2y = encrypted_part[1]
        return self.ecelgamal.decrypt_message(C1x, C1y, C2x, C2y, self.private_key)

    def verify_signature(self, signature, message):
        """Verify a signature using the public key."""
        return self.ecelgamal.verify(signature, message, self.public_key)
    
    def get_public_key(self):
        return self.public_key
    
    def get_private_key(self):
        return self.private_key
