import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    def __init__(self):
        self.key_file = "encryption.key"
        self.data_file = "passwords.enc"
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)
        self.passwords = self._load_passwords()

    def _load_or_generate_key(self):
        """Load existing key or generate a new one."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
            return key

    def _load_passwords(self):
        """Load encrypted passwords from file."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    return json.loads(decrypted_data)
            except Exception:
                return {}
        return {}

    def _save_passwords(self):
        """Save passwords to encrypted file."""
        encrypted_data = self.fernet.encrypt(json.dumps(self.passwords).encode())
        with open(self.data_file, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, service, username, password):
        """Add a new password entry."""
        self.passwords[service] = {
            "username": username,
            "password": password
        }
        self._save_passwords()

    def get_password(self, service):
        """Retrieve a password entry."""
        return self.passwords.get(service)

    def delete_password(self, service):
        """Delete a password entry."""
        if service in self.passwords:
            del self.passwords[service]
            self._save_passwords()
            return True
        return False

    def get_all_services(self):
        """Get list of all stored services."""
        return list(self.passwords.keys())

    def update_password(self, service, username, new_password):
        """Update an existing password entry."""
        if service in self.passwords:
            self.passwords[service] = {
                "username": username,
                "password": new_password
            }
            self._save_passwords()
            return True
        return False 