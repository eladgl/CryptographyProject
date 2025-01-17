import base64
import random
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from src.core.modes.cfb import BlowfishCFB
from src.gui.cipherManager import CipherManager
from src.core.signature.ec_elgamal import ECElGamal

# RSA Encryption and Decryption with OAEP
def encrypt(public_key, plaintext):
    """
    Encrypt the plaintext using RSA with OAEP.
    :param public_key: The recipient's RSA public key.
    :param plaintext: The plaintext to encrypt (bytes).
    :return: The encrypted ciphertext (bytes).
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)

def decrypt(private_key, ciphertext):
    """
    Decrypt the ciphertext using RSA with OAEP.
    :param private_key: The recipient's RSA private key.
    :param ciphertext: The ciphertext to decrypt (bytes).
    :return: The decrypted plaintext (bytes).
    """
    decipher = PKCS1_OAEP.new(private_key)
    return decipher.decrypt(ciphertext)

class UserFrame(tk.Frame):
    def __init__(self, master, controller, bg_color, title, name, recipients):
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

        # RSA keys
        key = RSA.generate(2048)
        self.rsa_private_key = key
        self.rsa_public_key = key.publickey()
        self.controller.shared_state[self.name + "_public_key"] = self.rsa_public_key

        # EC ElGamal setup
        self.ec_elgamal = ECElGamal(a=2, b=3, n=97)
        self.private_key = 5
        self.public_key = self.ec_elgamal.generate_public_key(2, 3, self.private_key)
        self.controller.shared_state[self.name + "_ec_public_key"] = self.public_key

        # Cipher manager
        self.cipher_manager = None

        # Initialize this user's message state
        self.controller.shared_state[self.name] = None

    def initialize_cipher(self, key):
        """Initialize the CipherManager with the provided key."""
        self.cipher_manager = CipherManager(key)

    def create_widgets(self):
        title_label = tk.Label(self, text=self.title, font=("Arial", 16), bg=self["bg"])
        title_label.grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(self, text="Recipient:", bg=self["bg"]).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        recipient_menu = tk.OptionMenu(self, self.selected_recipient, *self.recipients)
        recipient_menu.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Key:", bg=self["bg"]).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.key_entry = tk.Entry(self, width=40)
        self.key_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(self, text="Message:", bg=self["bg"]).grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.message_entry = tk.Entry(self, width=40)
        self.message_entry.grid(row=3, column=1, padx=5, pady=5)

        send_button = tk.Button(self, text="Encrypt & Send", command=self.encrypt_message)
        send_button.grid(row=4, column=0, columnspan=2, pady=10)

        decrypt_button = tk.Button(self, text="Decrypt", command=self.decrypt_message)
        decrypt_button.grid(row=5, column=0, columnspan=2, pady=5)

        verify_button = tk.Button(self, text="Verify Digital Signature", command=self.verify_signature)
        verify_button.grid(row=6, column=0, columnspan=2, pady=5)

    def encrypt_message(self):
        """Encrypt the message and the key, then sign it."""
        try:
            print("Encrypt button clicked")
            symmetric_key = self.key_entry.get().encode()
            if not symmetric_key:
                raise ValueError("Key cannot be empty.")
            if not self.cipher_manager:
                self.initialize_cipher(symmetric_key)
                print("Cipher initialized")

            recipient = self.selected_recipient.get()
            recipient_rsa_key = self.controller.shared_state.get(recipient + "_public_key")
            if not recipient_rsa_key:
                raise ValueError(f"Recipient {recipient} does not have a public key available.")

            # Encrypt the symmetric key with RSA (OAEP)
            encrypted_key = encrypt(recipient_rsa_key, symmetric_key)
            print("Encrypted Symmetric Key:", encrypted_key)

            # Convert symmetric key to integer for signing
            symmetric_key_int = int.from_bytes(symmetric_key, "big")
            print("Symmetric Key (Integer):", symmetric_key_int)

            # Sign the symmetric key using EC ElGamal
            k = random.randint(1, self.ec_elgamal.n - 1)
            signature = self.ec_elgamal.encrypt_message(
                2, 3, self.public_key[0], self.public_key[1], k, symmetric_key_int
            )
            print("Generated Signature:", signature)

            # Encrypt the message
            plaintext = self.message_entry.get().encode()
            if not plaintext:
                raise ValueError("Message cannot be empty.")
            ciphertext = self.cipher_manager.encrypt(plaintext)
            print("Ciphertext:", ciphertext)

            # Send the encrypted key, ciphertext, and signature
            self.send_message((encrypted_key, ciphertext, signature), recipient)
            print("Message sent to recipient")
            messagebox.showinfo("Success", f"Message encrypted, signed, and sent to {recipient}.")
        except Exception as e:
            print("Error during encryption:", e)
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_message(self):
        """Decrypt the symmetric key and message."""
        try:
            received_data = self.get_message()
            if not received_data:
                raise ValueError("No message received.")

            encrypted_key, ciphertext, signature = received_data

            # Decrypt the symmetric key with RSA (OAEP)
            decrypted_key = decrypt(self.rsa_private_key, encrypted_key)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, decrypted_key.decode())

            # Initialize the cipher with the decrypted key
            self.initialize_cipher(decrypted_key)

            # Decrypt the message
            plaintext = self.cipher_manager.decrypt(ciphertext)
            self.message_entry.delete(0, tk.END)
            self.message_entry.insert(0, plaintext.decode())
            messagebox.showinfo("Decrypted Message", f"Message: {plaintext.decode()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def verify_signature(self):
        """Verify the digital signature of the symmetric key."""
        try:
            # Retrieve the encrypted key and signature
            encrypted_key, _, signature = self.controller.shared_state.get(self.name)

            if not encrypted_key or not signature:
                raise ValueError("No encrypted key or signature available for verification.")

            # Step 1: Decrypt the symmetric key with RSA
            decrypted_key = decrypt(self.rsa_private_key, encrypted_key)

            # Convert the symmetric key to its integer representation
            decrypted_key_int = int.from_bytes(decrypted_key, "big")

            # Step 2: Hash the symmetric key
            hashed_key = self.ec_elgamal.hash_message(decrypted_key)

            # Step 3: Verify the signature using EC ElGamal
            sender = self.selected_recipient.get()
            sender_ec_public_key = self.controller.shared_state.get(sender + "_ec_public_key")
            if not sender_ec_public_key:
                raise ValueError(f"Sender {sender} does not have a public EC key available.")

            verified_value = self.ec_elgamal.decrypt_message(
                signature[0][0], signature[0][1], signature[1][0], signature[1][1], self.private_key
            )

            print("Hashed Symmetric Key Integer:", hashed_key)
            print("Verified Value (from Signature):", verified_value)

            # Compare the hashed symmetric key with the verified value
            if hashed_key != verified_value:
                raise ValueError("Signature verification failed: The signature does not match the symmetric key.")

            messagebox.showinfo("Signature Verified", "The digital signature is valid and matches the symmetric key.")
        except Exception as e:
            print("Error during signature verification:", e)
            messagebox.showerror("Error", f"Signature verification failed: {str(e)}")




    def send_message(self, message, recipient):
        """
        Send the encrypted message to the selected recipient.
        :param message: The encrypted key, ciphertext, and signature (tuple).
        :param recipient: The name of the recipient (str).
        """
        if recipient not in self.controller.shared_state:
            raise ValueError(f"Recipient '{recipient}' does not exist.")
        self.controller.shared_state[recipient] = message

    def get_message(self):
        """
        Get the message intended for this user.
        :return: The message (tuple) or None if no message is available.
        """
        return self.controller.shared_state.get(self.name)

    def listen_for_messages(self):
        """Continuously listen for new messages."""
        new_message = self.get_message()
        if new_message and new_message != self.last_message:
            self.last_message = new_message

            # Display the encrypted key and message on the GUI
            encrypted_key, ciphertext, _ = new_message
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, base64.b64encode(encrypted_key).decode())
            self.message_entry.delete(0, tk.END)
            self.message_entry.insert(0, base64.b64encode(ciphertext).decode())

            messagebox.showinfo("New Message", "You have received a new message.")
        self.after(500, self.listen_for_messages)
