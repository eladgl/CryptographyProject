"""
utilities
=========
Provides shared helper functions for the project.
"""

from sympy import randprime

def generate_large_prime(bits=512):
    # Generate a random prime number with the specified bit length
    lower_bound = 2**(bits - 1)
    upper_bound = 2**bits - 1
    return randprime(lower_bound, upper_bound)
