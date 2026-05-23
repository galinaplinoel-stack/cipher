"""AES-256 Encryption Engine for CIPHER Agent."""

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Encryptor:
    """Handles AES-256 encryption and decryption of data."""

    def __init__(self, key: bytes = None):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str, associated_data: bytes = None) -> dict:
        """Encrypt plaintext with AES-256-GCM."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(
            nonce, plaintext.encode("utf-8"), associated_data
        )
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": "AES-256-GCM",
        }

    def decrypt(self, encrypted: dict, associated_data: bytes = None) -> str:
        """Decrypt AES-256-GCM encrypted data."""
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        nonce = base64.b64decode(encrypted["nonce"])
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode("utf-8")

    @staticmethod
    def hash_data(data: str) -> str:
        """Generate SHA-256 hash of data."""
        return hashlib.sha256(data.encode()).hexdigest()

    def export_key(self) -> str:
        """Export encryption key as base64."""
        return base64.b64encode(self.key).decode()

    @classmethod
    def from_key(cls, key_b64: str) -> "Encryptor":
        """Create encryptor from base64-encoded key."""
        return cls(base64.b64decode(key_b64))
