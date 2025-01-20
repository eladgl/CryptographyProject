import base64
import json

import tkinter as tk
from tkinter import messagebox
from ..core.modes.cfb import BlowfishCFB
from .cipherManager import CipherManager
from ..core.signature.ec_elgamal import ECElGamal
from ..core.crypto.rsa import generate_key_pair, encrypt, decrypt

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
        print('\n\nuserFrame constructor -----------')
        # RSA keys for key exchange
        self.rsa_public_key, self.rsa_private_key = generate_key_pair(61, 53)  # Replace with secure primes
        print('\tRSA setup')
        print(f"\t\tRSA Public Key: {self.rsa_public_key}")
        print(f"\t\tRSA Private Key: {self.rsa_private_key}")

        # EC ElGamal setup
        print('\t EC ElGamal setup')
        self.ecelgamal = ECElGamal(a=2, b=6, n=3253)
        self.private_key = self.ecelgamal.generate_ec_private_key(3253)  # Example private key (d); replace with secure random value
        #LHS - left hand side, represent y^2 mod n where y is in [0, n-1]
        #RHS - right hand side, represent x^3+ax+b mod n where x is in [0, n-1]
        LHS, RHS = [[], []], [[], []]
        self.ecelgamal.polynomial(LHS, RHS)
        arr_x, arr_y = self.ecelgamal.points_generate(LHS, RHS)
        #print('\t\tpoints on the curve are: ', [x for x in zip(arr_x, arr_y)])
        self.base_point = self.ecelgamal.generate_base_point(arr_x, arr_y)
        print('\t\tbase point: ', self.base_point)
        self.public_key = self.ecelgamal.generate_public_key(
            self.base_point[0], self.base_point[1], self.private_key
        )
        print(f"\t\tEC Private Key: {self.private_key}")
        print(f"\t\tEC Public Key: {self.public_key}")

        # Initialize this user's message state
        self.controller.shared_state[self.name] = None

        # Share the RSA public key
        self.send_public_key()

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


    def get_cipher_key(self):
        # Get the symmetric key
        print('\tget_cipher_key userFram-------------------')
        symmetric_key = self.key_entry.get()
        print('\t\tsymmetric_key: ', symmetric_key)
        if not symmetric_key:
            raise ValueError("Symmetric key cannot be empty.")
        return symmetric_key
        
    def get_recipient(self):
        return self.selected_recipient.get()
    def get_recipient_public_rsa_key(self):
        return self.ask_for_public_rsa_key(self.get_recipient())
    def get_recipient_public_ec_key(self):
        """Retrieve the recipient's EC ElGamal public key."""
        
        public_key = self.controller.shared_state.get(f"{self.get_recipient()}_public_ec_key")
        if public_key is None:
            print(self.controller.shared_state)
            raise ValueError(f"EC ElGamal public key for recipient '{self.get_recipient()}' not found.")
        return public_key
        
    def encrypt_message(self):
        """Encrypt the message and send it to the other user."""
        print('\n\nencrypt_message userFrame -------------')
        try:
            # Step 1: Initialize the cipher manager if not already done
            if not self.cipher_manager:
                self.initialize_cipher()

            # Step 2: Get the symmetric key
            symmetric_key = self.get_cipher_key()
            if not symmetric_key:
                raise ValueError("Symmetric key cannot be empty.")

            symmetric_key_as_list = list(map(ord, symmetric_key))  # Convert to list of ASCII values
            print('\tSymmetric Key as List of Integers:', symmetric_key_as_list)
            print("\tSymmetric Key as List of Integers length is:", len(symmetric_key_as_list))

            # Step 3: Encrypt the symmetric key with EC ElGamal
            recipient_public_key_ec = self.get_recipient_public_ec_key()
            print('\tRecipient EC Public Key:', recipient_public_key_ec)
            print("\tRecipient EC Public Key length is:", len(recipient_public_key_ec))

            ec_encrypted_key = []
            for key_part in symmetric_key_as_list:
                encrypted_part = self.ecelgamal.encrypt_message(
                    self.base_point[0], self.base_point[1],
                    recipient_public_key_ec[0], recipient_public_key_ec[1],
                    5, key_part
                )
                ec_encrypted_key.append(encrypted_part)
            print("\tEC ElGamal Encrypted Key:", ec_encrypted_key)
            print("\tEC ElGamal Encrypted Key length is:", len(ec_encrypted_key))

            # Step 4: Encrypt the EC ElGamal-encrypted key with RSA
            recipient_public_rsa_key = self.get_recipient_public_rsa_key()
            print("\tRecipient RSA Public Key:", recipient_public_rsa_key)

            # Flatten the EC ElGamal encrypted key for RSA encryption
            flattened_ec_encrypted_key = [
                value
                for (C1x, C1y), (C2x, C2y) in ec_encrypted_key
                for value in (C1x, C1y, C2x, C2y)
            ]

            # Encrypt the flattened EC ElGamal key with RSA
            rsa_encrypted_key = encrypt(recipient_public_rsa_key, json.dumps(flattened_ec_encrypted_key))
            print("\tRSA Encrypted Key (Flattened and Encrypted):", rsa_encrypted_key)

            # Step 5: Encrypt the plaintext message with Blowfish
            plaintext = self.message_entry.get().strip()
            if not plaintext:
                raise ValueError("Message cannot be empty.")
            ciphertext = self.cipher_manager.encrypt(plaintext.encode())
            print("\tCiphertext (Encrypted):", ciphertext)

            # Encode ciphertext to Base64
            encoded_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
            print("\tEncoded Ciphertext (Base64):", encoded_ciphertext)

            # Step 6: Send encrypted keys and ciphertext
            self.send_message(
                {
                    "rsa_encrypted_key": rsa_encrypted_key,  # Already encrypted and serialized
                    "ciphertext": encoded_ciphertext,       # Base64-encoded ciphertext
                },
                self.get_recipient(),
            )
            messagebox.showinfo("Success", f"Message encrypted and sent to {self.selected_recipient.get()}.")
        except Exception as e:
            print("Error in encrypt_message:", str(e))
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_message(self):
        """Decrypt the message received from the other user."""
        print('\n\ndecrypt_message userFrame-------------')
        try:
            # Step 1: Retrieve the message bundle
            message_bundle = self.get_message()
            print('\tMessage Bundle:', message_bundle)
            if not message_bundle:
                raise ValueError("No message received.")

            # Step 2: Extract ciphertext
            ciphertext = base64.b64decode(message_bundle.get("ciphertext"))
            print("\tCiphertext (Encrypted):", ciphertext)

            # Step 3: Get the decryption key from GUI input
            decryption_key = self.key_entry.get().strip()
            if not decryption_key:
                raise ValueError("Decryption key cannot be empty.")
            print("\tDecryption Key (From GUI):", decryption_key)

            # Step 4: Encode the decryption key to binary
            binary_key = decryption_key.encode()
            print("\tBinary Key:", binary_key)

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
                scrambled_plaintext = ''.join(chr(byte) for byte in ciphertext[:20])  # Show partial scrambled output

            # Step 7: Show the (potentially scrambled) message
            print("\tDecrypted Plaintext Message (Scrambled or Original):", scrambled_plaintext)
            messagebox.showinfo("Decrypted Message", f"Message: {scrambled_plaintext}")

        except Exception as e:
            print("Decryption Error:", str(e))
            messagebox.showerror("Error", f"Decryption failed.")

    def send_public_key(self):
        """Send this user's RSA public key to the shared state."""
        self.controller.shared_state[f"{self.name}_public_rsa_key"] = self.rsa_public_key
        self.controller.shared_state[f"{self.name}_public_ec_key"] = self.public_key
        print(f"{self.name}'s public key shared.")
    
    def ask_for_public_rsa_key(self, recipient):
        """Retrieve the recipient's RSA public key."""
        public_key = self.controller.shared_state.get(f"{recipient}_public_rsa_key")
        if public_key is None:
            print('ask for public RSA key ', self.controller.shared_state)
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
            print("\n\nsend_message userFrame ----------")
            print("\tmessage: ", message)

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
            print("\tmessage_bytes: ", message_bytes)

            # Encode the serialized message in Base64
            encoded_message = base64.b64encode(message_bytes).decode("utf-8")
            print("\tencoded_message: ", encoded_message)

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
            print("\t\tEncoded Message Decoded:", message)

            # Step 1: Deserialize and decrypt the RSA-encrypted key
            rsa_encrypted_key = json.loads(message["rsa_encrypted_key"])
            print("\t\tRSA Encrypted Key (List):", rsa_encrypted_key)

            # Decrypt the RSA key to get the flattened EC ElGamal-encrypted key
            flattened_ec_encrypted_key = json.loads(self.decrypt_symmetric_key(rsa_encrypted_key))
            print("\t\tDecrypted Flattened EC ElGamal Encrypted Key:", flattened_ec_encrypted_key)

            # Reconstruct the EC ElGamal-encrypted key
            ec_encrypted_key = [
                ((flattened_ec_encrypted_key[i], flattened_ec_encrypted_key[i + 1]),
                (flattened_ec_encrypted_key[i + 2], flattened_ec_encrypted_key[i + 3]))
                for i in range(0, len(flattened_ec_encrypted_key), 4)
            ]
            print("\t\tReconstructed EC ElGamal Encrypted Key:", ec_encrypted_key)

            # Step 2: Decrypt the EC ElGamal key to get the symmetric key
            symmetric_key_as_list = []
            for encrypted_part in ec_encrypted_key:
                C1x, C1y = encrypted_part[0]
                C2x, C2y = encrypted_part[1]
                decrypted_part = self.ecelgamal.decrypt_message(C1x, C1y, C2x, C2y, self.private_key)
                symmetric_key_as_list.append(decrypted_part[0])  # Use Mx only
                print("\t\t\tDecrypted Part:", decrypted_part)

            print("\t\tDecrypted Symmetric Key (List):", symmetric_key_as_list)

            # Handle non-printable characters
            if not all(32 <= value < 127 for value in symmetric_key_as_list):  # Printable ASCII range
                print("\t\tWarning: Decrypted values contain non-printable characters.")
                # Convert to a readable format, like hexadecimal
                symmetric_key = " ".join(f"{value:02x}" for value in symmetric_key_as_list)
                print("\t\tDecrypted Symmetric Key (Hex):", symmetric_key)
            else:
                # Convert the decrypted symmetric key to plaintext
                symmetric_key = "".join(map(chr, symmetric_key_as_list))
                print("\t\tDecrypted Symmetric Key (Plaintext):", symmetric_key)

            # Replace the RSA-encrypted key in the message with the readable symmetric key
            message["rsa_encrypted_key"] = symmetric_key

            return message

        except Exception as e:
            print("Error in get_message:", str(e))
            return None





    def set_message(self, message):
        """
        Set the message for this user in the shared state.
        :param message: The message to set (bytes).
        """
        self.controller.shared_state[self.name] = message
    
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

                    print("Decoded Message:", new_message)

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
        return encrypt(self.rsa_public_key, symmetric_key)

    def decrypt_symmetric_key(self, encrypted_symmetric_key):
        """
        Decrypt the symmetric key using this user's RSA private key.
        :param encrypted_symmetric_key: The RSA-encrypted symmetric key (list of integers).
        :return: Decrypted symmetric key (str).
        """
        if not encrypted_symmetric_key:
            raise ValueError("Encrypted symmetric key cannot be empty.")
        return decrypt(self.rsa_private_key, encrypted_symmetric_key)