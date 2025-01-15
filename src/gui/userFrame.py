import base64

import tkinter as tk
from tkinter import messagebox
from ..core.modes.cfb import BlowfishCFB
from .cipherManage import CipherManager

class UserFrame(tk.Frame):
    def __init__(self, master, controller, bg_color, title, recipients):
        """
        Initialize a user frame with shared functionality.

        :param master: Parent widget.
        :param controller: The main application controller (EncryptionApp).
        :param bg_color: Background color for the frame.
        :param title: Title of the frame (e.g., Alice or Bob).
        """
        super().__init__(master, padx=10, pady=10, bg=bg_color)
        self.master = master
        self.controller = controller
        self.title = title
        self.recipients = recipients
        self.selected_recipient = tk.StringVar(value=self.recipients[0])
        self.last_message = ""
        self.create_widgets()
        self.listen_for_messages()

        self.cipher_manager = None

    def initialize_cipher(self):
        """Initialize the CipherManager with the provided key."""
        key = self.key_entry.get().encode()
        if not key:
            raise ValueError("Key cannot be empty.")
        self.cipher_manager = CipherManager(key)

    def create_widgets(self):
        # Title
        title_label = tk.Label(self, text=self.title, font=("Arial", 16), bg=self["bg"])
        title_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Recipient dropdown
        tk.Label(self, text="Recipient:", bg=self["bg"]).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        recipient_menu = tk.OptionMenu(self, self.selected_recipient, *self.recipients)
        recipient_menu.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Key Entry
        tk.Label(self, text="Key:", bg=self["bg"]).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.key_entry = tk.Entry(self, width=40)
        self.key_entry.grid(row=2, column=1, padx=5, pady=5)

        # Message Entry
        tk.Label(self, text="Message:", bg=self["bg"]).grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.message_entry = tk.Entry(self, width=40)
        self.message_entry.grid(row=3, column=1, padx=5, pady=5)

        # Buttons
        encrypt_button = tk.Button(self, text="Encrypt & Send", command=self.encrypt_message)
        encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

        decrypt_button = tk.Button(self, text="Decrypt", command=self.decrypt_message)
        decrypt_button.grid(row=5, column=0, columnspan=2, pady=5)

        # Configure column weights for responsiveness
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)


    def encrypt_message(self):
        """Encrypt the message and send it to the other user."""
        try:
            if not self.cipher_manager:
                self.initialize_cipher()

            message = self.message_entry.get().encode()
            if not message:
                raise ValueError("Message cannot be empty.")

            # Encrypt the message
            encrypted_message = self.cipher_manager.encrypt(message)

            # Send the message to the selected recipient
            self.send_message(encrypted_message, self.selected_recipient)
            messagebox.showinfo("Success", f"Message encrypted and sent to {self.selected_recipient}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        """Decrypt the message received from the other user."""
        encrypted_message = self.get_message()
        if not encrypted_message:
            messagebox.showerror("Error", "No message to decrypt.")
            return

        try:
            if not self.cipher_manager:
                self.initialize_cipher()

            # Decrypt the message
            decrypted_message = self.cipher_manager.decrypt(encrypted_message)

            # Display the decrypted message
            messagebox.showinfo("Decrypted Message", f"Message: {decrypted_message.decode()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self, message):
        """Send the encrypted message (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement this method.")

    def get_message(self):
        """Get the message from the shared state (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement this method.")
    
    def listen_for_messages(self):
        """Continuously listen for new messages."""
        new_message = self.get_message()  # Fetch the latest message from the shared state

        if new_message and new_message != self.last_message:
            self.last_message = new_message
            self.message_entry.delete(0, tk.END)  # Clear current text
            self.message_entry.insert(0, new_message)  # Display new message
            messagebox.showinfo("New Message", f"New message received: {new_message}")

        # Schedule this function to run again after 500 milliseconds
        self.after(500, self.listen_for_messages)
