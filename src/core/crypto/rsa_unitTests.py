import unittest
from rsa import gcd, is_prime, multiplicative_inverse, generate_key_pair, encrypt, decrypt


class TestRSA(unittest.TestCase):

    def test_gcd(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(101, 10), 1)
        self.assertEqual(gcd(0, 10), 10)
        self.assertEqual(gcd(7, 0), 7)
        self.assertEqual(gcd(0, 0), 0)

    def test_is_prime(self):
        self.assertTrue(is_prime(17))
        self.assertTrue(is_prime(19))
        self.assertFalse(is_prime(15))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(0))
        self.assertTrue(is_prime(2))
        self.assertFalse(is_prime(4))

    def test_multiplicative_inverse(self):
        phi = 40
        e = 7
        self.assertEqual((multiplicative_inverse(3, 26) * 3) % 26, 1)

    def test_key_generation(self):
        public, private = generate_key_pair(17, 23)
        self.assertEqual(len(public), 2)
        self.assertEqual(len(private), 2)
        self.assertNotEqual(public, private)
        self.assertTrue(gcd(public[0], (17-1)*(23-1)) == 1)

    def test_encrypt_decrypt(self):
        public, private = generate_key_pair(17, 23)
        plaintext = "Hello"
        encrypted = encrypt(public, plaintext)
        decrypted = decrypt(private, encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_special_characters(self):
        public, private = generate_key_pair(257, 263)  # Larger primes
        plaintext = "こんにちは世界"
        encrypted = encrypt(public, plaintext)
        decrypted = decrypt(private, encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_edge_case_small_primes(self):
        with self.assertRaises(ValueError):
            generate_key_pair(3, 5)  # Small primes should raise a ValueError


if __name__ == '__main__':
    unittest.main()
