from src.core.crypto.test_blowfish import test_blowfish
from src.core.modes.test_cfb import test_cfb, test_cfb_partial_block, test_cfb_wrong_key

# Run the tests
def main():
    test_blowfish()

    test_cfb()
    test_cfb_partial_block()
    test_cfb_wrong_key()


if __name__ == "__main__":
    main()
