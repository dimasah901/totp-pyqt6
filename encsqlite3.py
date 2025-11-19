from fernet import Fernet
import base64
import hashlib
import sqlite3
import io
import os


class EncryptedSQLite3():
    def __init__(self, path, password, override=False):
        # Create an in-memory database
        self.db = sqlite3.connect(":memory:")

        # Store the path for later
        self.path = path

        if override:
            self.salt = os.urandom(16)
            key = base64.urlsafe_b64encode(self.generate_key(password))
            self.fernet = Fernet(key)
            self.write()
            return
        try:
            # Read existing data
            self.read(password)
        except FileNotFoundError:
            # No file (yet), write b''
            self.salt = os.urandom(16)
            key = base64.urlsafe_b64encode(self.generate_key(password))
            self.fernet = Fernet(key)
            self.write()

    def generate_key(self, password):
        return hashlib.pbkdf2_hmac("sha256", password, self.salt, 1_200_000, 32)

    def write(self):
        with io.open(self.path, "wb") as file:
            file.write(self.salt)
            try:
                # Serialize and write
                file.write(
                    base64.urlsafe_b64decode(self.fernet.encrypt(self.db.serialize())))
            except sqlite3.OperationalError:
                # Database is empty: write b''
                file.write(
                    base64.urlsafe_b64decode(self.fernet.encrypt(b'')))

    def read(self, password):
        with io.open(self.path, "rb") as file:
            self.salt = file.read(16)
            key = base64.urlsafe_b64encode(self.generate_key(password))
            self.fernet = Fernet(key)
            try:
                # Read and deserialize
                self.db.deserialize(
                    self.fernet.decrypt(base64.urlsafe_b64encode(file.read())))
            except MemoryError:
                # Stored file is empty
                pass
