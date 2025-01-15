import tkinter as tk
from .alice_frame import AliceFrame
from .bob_frame import BobFrame

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App: Alice and Bob")
        self.shared_state = {"alice_message": "", "bob_message": ""}
        self.create_gui()

    def create_gui(self):
        # Create Alice Frame
        alice_frame = AliceFrame(self.root, self, recipients=['bob'])
        alice_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create Bob Frame
        bob_frame = BobFrame(self.root, self, recipients=['alice'])
        bob_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

