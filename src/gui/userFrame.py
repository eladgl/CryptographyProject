import base64
import json

import tkinter as tk
from tkinter import messagebox
from .cipherManager import CipherManager
from ..managers.rsaManager import RSAManager
from ..managers.signatureManager import SignatureManager

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
        self.symmetric_key = None

        # Cipher manager will be initialized upon the first encryption or decryption
        self.cipher_manager = None

        self.rsa_manager = RSAManager()
        self.signature_manager = SignatureManager()

        # Initialize this user's message state
        self.controller.shared_state[self.name] = None

        # Share the RSA public key
        self.send_public_key()

    def initialize_cipher(self):
        """Initialize the CipherManager with the provided key."""
        key = self.key_entry.get().encode()
        if not key:
            raise ValueError("Key cannot be empty!")
        elif key == self.symmetric_key:
            raise ValueError("Do not generate cipher because key did not change")
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
        
    def get_recipient_public_rsa_key(self):
        return self.ask_for_public_rsa_key(self.selected_recipient.get())
    def get_recipient_public_ec_key(self):
        """Retrieve the recipient's EC ElGamal public key."""
        public_key = self.controller.shared_state.get(f"{self.selected_recipient.get()}_public_ec_key")
        if public_key is None:
            raise ValueError(f"EC ElGamal public key for recipient '{self.selected_recipient.get()}' not found.")
        return public_key
        
    def encrypt_message(self):
        """Encrypt the message and send it to the other user."""
        try:
            symmetric_key = self.key_entry.get()
            # Step 1: Initialize the cipher manager if not already done
            if not self.cipher_manager or symmetric_key != self.symmetric_key:
                self.symmetric_key = symmetric_key
                self.initialize_cipher()

            # Step 2: Get the symmetric key
            
            if not symmetric_key:
                raise ValueError("Symmetric key cannot be empty.")

            symmetric_key_as_list = list(map(ord, symmetric_key))  # Convert to list of ASCII values

            # Step 3: Encrypt the symmetric key with EC ElGamal
            recipient_public_key_ec = self.get_recipient_public_ec_key()

            ec_encrypted_key = []
            for key_part in symmetric_key_as_list:
                ec_encrypted_key.append(self.signature_manager.sign_message(
                    recipient_public_key_ec[0], recipient_public_key_ec[1],
                    5, key_part
                ))

            # Step 4: Encrypt the EC ElGamal-encrypted key with RSA
            recipient_public_rsa_key = self.get_recipient_public_rsa_key()

            # Flatten the EC ElGamal encrypted key for RSA encryption
            flattened_ec_encrypted_key = [
                value
                for (C1x, C1y), (C2x, C2y) in ec_encrypted_key
                for value in (C1x, C1y, C2x, C2y)
            ]

            # Encrypt the flattened EC ElGamal key with RSA
            rsa_encrypted_key = self.rsa_manager.encrypt(recipient_public_rsa_key, json.dumps(flattened_ec_encrypted_key))

            # Step 5: Encrypt the plaintext message with Blowfish
            plaintext = self.message_entry.get().strip()
            if not plaintext:
                raise ValueError("Message cannot be empty.")
            ciphertext = self.cipher_manager.encrypt(plaintext.encode())

            # Encode ciphertext to Base64
            encoded_ciphertext = base64.b64encode(ciphertext).decode("utf-8")

            # Step 6: Send encrypted keys and ciphertext
            self.send_message(
                {
                    "rsa_encrypted_key": rsa_encrypted_key,  # Already encrypted and serialized
                    "ciphertext": encoded_ciphertext,       # Base64-encoded ciphertext
                },
                self.selected_recipient.get(),
            )
            messagebox.showinfo("Success", f"Message encrypted and sent to {self.selected_recipient.get()}.")
        except Exception as e:
            print("Error in encrypt_message:", str(e))
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_message(self):
        """Decrypt the message received from the other user."""
        try:
            # Step 1: Retrieve the message bundle
            message_bundle = self.get_message()
            if not message_bundle:
                raise ValueError("No message received.")

            # Step 2: Extract ciphertext
            ciphertext = base64.b64decode(message_bundle.get("ciphertext"))

            # Step 3: Get the decryption key from GUI input
            decryption_key = self.key_entry.get().strip()
            if not decryption_key:
                raise ValueError("Decryption key cannot be empty.")

            # Step 4: Encode the decryption key to binary
            binary_key = decryption_key.encode()

            # Step 5: Initialize the cipher manager with the binary key
            if not self.cipher_manager or self.cipher_manager.key != binary_key:
                self.cipher_manager = CipherManager(binary_key)

            # Step 6: Decrypt the ciphertext with Blowfish
            scrambled_plaintext = None
            try:
                plaintext = self.cipher_manager.decrypt(ciphertext).decode('utf-8')
                scrambled_plaintext = plaintext
            except (UnicodeDecodeError, ValueError):
                # If decryption fails, show scrambled data instead
                plaintext = self.cipher_manager.decrypt(ciphertext)
                scrambled_plaintext = plaintext
            # Step 7: Show the (potentially scrambled) message
            messagebox.showinfo("Decrypted Message", f"Message: {scrambled_plaintext}")

        except Exception as e:
            plaintext = self.cipher_manager.decrypt(ciphertext)

    def send_public_key(self):
        """Send this user's RSA public key to the shared state."""
        self.controller.shared_state[f"{self.name}_public_rsa_key"] = self.rsa_manager.get_public_key()
        self.controller.shared_state[f"{self.name}_public_ec_key"] = self.signature_manager.get_public_key()
    
    def ask_for_public_rsa_key(self, recipient):
        """Retrieve the recipient's RSA public key."""
        public_key = self.controller.shared_state.get(f"{recipient}_public_rsa_key")
        if public_key is None:
            raise ValueError(f"Public key for recipient '{recipient}' not found.")
        return public_key
    
    def validate_message(self, message):
        if not isinstance(message.get("rsa_encrypted_key"), list):
            raise ValueError("rsa_encrypted_key must be a list of integers.")
        if not all(isinstance(i, int) for i in message["rsa_encrypted_key"]):
            raise ValueError("rsa_encrypted_key must contain only integers.")
        if not isinstance(message.get("ciphertext"), str):
            raise ValueError("ciphertext must be a Base64-encoded string.")

    def send_message(self, message, recipient):
        """
        Send the encrypted message to the selected recipient.
        :param message: The encrypted message (dictionary with keys 'rsa_encrypted_key' and 'ciphertext').
        :param recipient: The name of the recipient (str).
        """
        try:
            # Validate recipient
            if recipient not in self.controller.shared_state:
                raise ValueError(f"Recipient '{recipient}' does not exist.")

            # Validate message structure (before serialization)
            self.validate_message(message)

            # Serialize the RSA-encrypted key to JSON for storage
            serialized_rsa_key = json.dumps(message["rsa_encrypted_key"])

            # Prepare the final message dictionary with serialized RSA key
            final_message = {
                "rsa_encrypted_key": serialized_rsa_key,
                "ciphertext": message["ciphertext"],  # Ciphertext is already Base64-encoded
            }

            # Serialize the entire message to JSON and encode it in UTF-8
            message_bytes = json.dumps(final_message).encode("utf-8")

            # Encode the serialized message in Base64
            encoded_message = base64.b64encode(message_bytes).decode("utf-8")

            # Store the Base64-encoded message in the shared state
            self.controller.shared_state[recipient] = encoded_message

        except Exception as e:
            print("Error in send_message:", str(e))
            raise


    def get_message(self):
        """
        Get the message intended for this user, including decryption of the key.
        :return: A dictionary with the decrypted key and ciphertext, or None if no message is available.
        """
        encoded_message = self.controller.shared_state.get(self.name)
        if not encoded_message:
            return None

        try:
            # Decode the Base64-encoded string and deserialize the JSON
            message_bytes = base64.b64decode(encoded_message)
            message = json.loads(message_bytes.decode("utf-8"))

            # Step 1: Deserialize and decrypt the RSA-encrypted key
            rsa_encrypted_key = json.loads(message["rsa_encrypted_key"])

            # Decrypt the RSA key to get the flattened EC ElGamal-encrypted key
            flattened_ec_encrypted_key = json.loads(self.decrypt_symmetric_key(rsa_encrypted_key))
            # Reconstruct the EC ElGamal-encrypted key
            ec_encrypted_key = [
                ((flattened_ec_encrypted_key[i], flattened_ec_encrypted_key[i + 1]),
                (flattened_ec_encrypted_key[i + 2], flattened_ec_encrypted_key[i + 3]))
                for i in range(0, len(flattened_ec_encrypted_key), 4)
            ]

            # Step 2: Decrypt the EC ElGamal key to get the symmetric key
            symmetric_key_as_list = []
            for encrypted_part in ec_encrypted_key:
                symmetric_key_as_list.append(self.signature_manager.decrypt(encrypted_part)[0])

            # Handle non-printable characters
            if not all(32 <= value < 127 for value in symmetric_key_as_list):  # Printable ASCII range
                # Convert to a readable format, like hexadecimal
                symmetric_key = " ".join(f"{value:02x}" for value in symmetric_key_as_list)
            else:
                # Convert the decrypted symmetric key to plaintext
                symmetric_key = "".join(map(chr, symmetric_key_as_list))

            # Replace the RSA-encrypted key in the message with the readable symmetric key
            message["rsa_encrypted_key"] = symmetric_key

            return message

        except Exception as e:
            print("Error in get_message:", str(e))
            return None
    
    def listen_for_messages(self):
        """Continuously listen for new messages."""
        try:
            # Fetch the latest message from the shared state
            encoded_message = self.controller.shared_state.get(self.name)

            if encoded_message and encoded_message != self.last_message:
                try:
                    # Decode the Base64-encoded string and deserialize the JSON
                    message_bytes = base64.b64decode(encoded_message)
                    new_message = json.loads(message_bytes.decode("utf-8"))  # Deserialize JSON to a dictionary

                    # Check if the message contains encrypted content
                    if "rsa_encrypted_key" in new_message and "ciphertext" in new_message:
                        self.last_message = encoded_message  # Store the Base64-encoded string
                        messagebox.showinfo("New Message", "You have received an encrypted message.")

                        # Update the message entry with the ciphertext
                        self.message_entry.delete(0, tk.END)  # Clear current text
                        self.message_entry.insert(0, new_message["ciphertext"])  # Show Base64-encoded ciphertext

                        # Optionally, update the key entry with the encrypted key
                        rsa_encrypted_key_str = json.dumps(new_message["rsa_encrypted_key"])
                        self.key_entry.delete(0, tk.END)  # Clear current key entry
                        self.key_entry.insert(0, self.get_message()["rsa_encrypted_key"])  # Insert the RSA-encrypted key as a string

                    else:
                        print("Unexpected message format:", new_message)

                except Exception as inner_e:
                    print("Error while processing the message:", str(inner_e))

        except Exception as e:
            print("Error in listen_for_messages:", str(e))

        # Schedule this function to run again after 500 milliseconds
        self.after(500, self.listen_for_messages)

    def encrypt_symmetric_key(self, symmetric_key):
        """
        Encrypt the symmetric key using this user's RSA public key.
        :param symmetric_key: The symmetric key (str) to be encrypted.
        :return: Encrypted symmetric key (list of integers).
        """
        if not symmetric_key:
            raise ValueError("Symmetric key cannot be empty.")
        return self.rsa_manager.encrypt(self.rsa_manager.get_public_key(), symmetric_key)

    def decrypt_symmetric_key(self, encrypted_symmetric_key):
        """
        Decrypt the symmetric key using this user's RSA private key.
        :param encrypted_symmetric_key: The RSA-encrypted symmetric key (list of integers).
        :return: Decrypted symmetric key (str).
        """
        if not encrypted_symmetric_key:
            raise ValueError("Encrypted symmetric key cannot be empty.")
        return self.rsa_manager.decrypt(self.rsa_manager.get_private_key(), encrypted_symmetric_key)