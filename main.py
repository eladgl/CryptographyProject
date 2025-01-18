from src.core.crypto.test_blowfish import test_blowfish
from src.core.modes.test_cfb import test_cfb, test_cfb_partial_block, test_cfb_wrong_key
from src.core.modes.cfb import BlowfishCFB
from src.core.crypto.rsa import generate_key_pair
from src.core.common.utilities import generate_large_prime
from src.core.signature.ec_elgamal import ECElGamal
from src.gui.app import EncryptionApp
import tkinter as tk
import random
# Run the tests
def main():
    root = tk.Tk()  # Create the main application window
    app = EncryptionApp(root)  # Initialize the EncryptionApp
    root.mainloop()  # Start the Tkinter event loop
    
    # Run all tests in TestCommunicationWorkflow
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestCommunicationWorkflow)
    #unittest.TextTestRunner(verbosity=2).run(suite)

    # #step 1: Generate RSA keys
    # #step 1.1: Generate large prime numbers
    # print("Generating large RSA keys...")
    # p = generate_large_prime(4)
    # q = generate_large_prime(4)
    # #step 1.2: Generate RSA public and private keys
    # sender_rsa_public, sender_rsa_private = generate_key_pair(p, q)
    # receiver_rsa_public, receiver_rsa_private = generate_key_pair(p, q)

    # print("Sender RSA Public Key:", sender_rsa_public)
    # print("Receiver RSA Public Key:", receiver_rsa_public)

    # # Step 2: Generate Blowfish symmetric key
    # print("Generating Blowfish key...")
    # blowfish_key = b"mysecretkey12345"  # Example key (16 bytes for Blowfish)
    # iv  = b"00000000"
    # blowfish = BlowfishCFB(blowfish_key, iv)
    # print("Blowfish Key:", blowfish_key)

    # # Step 3: ElGamal Key Generation and Curve Initialization
    # print("Initializing EC ElGamal...")
    # curve_a, curve_b, curve_n = 2, 3, generate_large_prime(6)  # Example elliptic curve parameters (y^2 = x^3 + 2x + 3 over Z_97)
    # ec_elgamal = ECElGamal(curve_a, curve_b, curve_n)

    # # Generate points on the curve
    # LHS, RHS = [[], []], [[], []]
    # ec_elgamal.polynomial(LHS, RHS)
    # arr_x, arr_y = ec_elgamal.points_generate(LHS, RHS)
    # print("Points on the curve:", list(zip(arr_x, arr_y)))

    # # Generate base point
    # bx, by = ec_elgamal.generate_base_point(arr_x, arr_y)
    # print("Base Point:", (bx, by))

    # # Generate public/private key pair
    # private_key = random.randint(1, curve_n - 1)
    # public_key = ec_elgamal.generate_public_key(bx, by, private_key)
    # print("EC ElGamal Private Key:", private_key)
    # print("EC ElGamal Public Key:", public_key)

    # # Step 4: Sign and Encrypt the Blowfish Key
    # print("Encrypting Blowfish key with EC ElGamal...")
    # k = random.randint(1, curve_n - 1)  # Random number for encryption
    # encrypted_blowfish_key, signature = ec_elgamal.encrypt_message(
    #     bx, by, public_key[0], public_key[1], k, int.from_bytes(blowfish_key, 'big')
    # )
    # print("Encrypted Blowfish Key (EC ElGamal):", encrypted_blowfish_key)
    # print("Signature (EC ElGamal):", signature)

    # # Step 5: Decrypt the Blowfish Key
    # print("Decrypting Blowfish key with EC ElGamal...")
    # decrypted_blowfish_key = ec_elgamal.decrypt_message(
    #     encrypted_blowfish_key[0], encrypted_blowfish_key[1],
    #     signature[0], signature[1],
    #     private_key
    # )
    # decrypted_blowfish_key_bytes = decrypted_blowfish_key[0].to_bytes(16, 'big')
    # print("Decrypted Blowfish Key:", decrypted_blowfish_key_bytes)

    #  # Step 6: Verify correctness
    # assert decrypted_blowfish_key_bytes == blowfish_key, "Decryption failed!"

    #  # Step 7: Encrypt and Decrypt a Message Using Blowfish
    # plaintext = b"Confidential message"
    # print("Encrypting message using Blowfish...")
    # ciphertext = blowfish.encrypt(plaintext)
    # print("Ciphertext:", ciphertext)

    # print("Decrypting message using Blowfish...")
    # decrypted_message = blowfish.decrypt(ciphertext)
    # print("Decrypted Message:", decrypted_message)

    # # Final verification
    # assert decrypted_message == plaintext, "Message decryption failed!"
    # print("Workflow completed successfully!")


if __name__ == "__main__":
    main()
