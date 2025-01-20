class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def save_key(self, name, key, shared_state):
        """Save a key to the shared state."""
        shared_state[name] = key

    def load_key(self, name, shared_state):
        """Load a key from the shared state."""
        key = shared_state.get(name)
        if not key:
            raise ValueError(f"Key '{name}' not found in shared state.")
        return key