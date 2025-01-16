import base64

import tkinter as tk
from tkinter import messagebox
from ..core.modes.cfb import BlowfishCFB
from .cipherManager import CipherManager

class UserFrame(tk.Frame):
    def __init__(self, master, controller, bg_color, title, name, recipients):
        """
        Initialize a user frame with shared functionality.

        :param master: Parent widget.
        :param controller: The main application controller (EncryptionApp).
        :param bg_color: Background color for the frame.
        :param title: Title of the frame (e.g., Alice or Bob).
        :param name: Unique name for this frame in the shared state (e.g., "alice").
        :param recipients: List of recipient names this user can send messages to.
        """
        super().__init__(master, padx=10, pady=10, bg=bg_color)
        self.master = master
        self.controller = controller
        self.title = title
        self.name = name
        self.recipients = recipients
        self.selected_recipient = tk.StringVar(value=self.recipients[0])
        self.last_message = ""
        self.create_widgets()
        self.listen_for_messages()

        # Cipher manager will be initialized upon the first encryption or decryption
        self.cipher_manager = None

        # Initialize this user's message state
        self.controller.shared_state[self.name] = None

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
            self.send_message(encrypted_message, self.selected_recipient.get())
            messagebox.showinfo("Success", f"Message encrypted and sent to {self.selected_recipient.get()}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        """Decrypt the message received from the other user."""
        encrypted_message = self.get_message()
        if not encrypted_message:
            messagebox.showerror("Error", "No message to decrypt.")
            return

        try:
            # Decode the Base64-encoded message
            encrypted_message_bytes = base64.b64decode(encrypted_message)
            print(encrypted_message_bytes)
            
            # Check if the cipher manager is initialized or if the key has changed
            current_key = self.key_entry.get().encode()
            print('Current key ', current_key)
            if not self.cipher_manager or self.cipher_manager.key != current_key:
                print("Key changed or cipher not initialized. Regenerating cipher...")
                self.cipher_manager = CipherManager(current_key)
            
            # Decrypt the message
            decrypted_message = self.cipher_manager.decrypt(encrypted_message_bytes)

            # Display the decrypted message
            messagebox.showinfo("Decrypted Message", f"Message: {decrypted_message.decode()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def send_message(self, message, recipient):
        """
        Send the encrypted message to the selected recipient.
        :param message: The encrypted message (bytes).
        :param recipient: The name of the recipient (str).
        """
        if recipient not in self.controller.shared_state:
            raise ValueError(f"Recipient '{recipient}' does not exist.")
        encoded_message = base64.b64encode(message).decode("utf-8")
        self.controller.shared_state[recipient] = encoded_message

    def get_message(self):
        """
        Get the message intended for this user.
        :return: The message (bytes) or None if no message is available.
        """
        return self.controller.shared_state.get(self.name)

    def set_message(self, message):
        """
        Set the message for this user in the shared state.
        :param message: The message to set (bytes).
        """
        self.controller.shared_state[self.name] = message
    
    def listen_for_messages(self):
        """Continuously listen for new messages."""
        new_message = self.get_message()  # Fetch the latest message from the shared state

        if new_message and new_message != self.last_message:
            try:
                # Decode the message (assuming it's Base64-encoded)
                print('new message ', new_message)
                decoded_message = base64.b64decode(new_message).decode("utf-8")
                print('decoded_message ', decoded_message)
            except Exception:
                # If decoding fails, display the raw message
                print('decode didnt work')
                decoded_message = new_message

            self.last_message = new_message
            self.message_entry.delete(0, tk.END)  # Clear current text
            self.message_entry.insert(0, decoded_message)  # Display decoded message
            messagebox.showinfo("New Message", f"New message received: {decoded_message}")

        # Schedule this function to run again after 500 milliseconds
        self.after(500, self.listen_for_messages)
