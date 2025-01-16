import tkinter as tk
from .userFrame import UserFrame  # Import the updated UserFrame

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App: Alice and Bob")
        
        # Shared state for communication between user frames
        self.shared_state = {"alice": None, "bob": None}
        
        self.create_gui()

    def create_gui(self):
        # Create Alice Frame
        alice_frame = UserFrame(
            self.root,
            controller=self,
            bg_color="lightblue",
            title="Alice",
            name="alice",  # Unique identifier for Alice
            recipients=["bob"]
        )
        alice_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create Bob Frame
        bob_frame = UserFrame(
            self.root,
            controller=self,
            bg_color="lightgreen",
            title="Bob",
            name="bob",  # Unique identifier for Bob
            recipients=["alice"]
        )
        bob_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Configure grid weights for responsiveness
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)