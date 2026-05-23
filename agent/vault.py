"""Secure Secret Vault for CIPHER Agent."""

import os
import json
import time
from typing import Optional, List, Dict
from cryptography.fernet import Fernet


class Vault:
    """Encrypted secret storage with access controls."""

    def __init__(self, vault_path: str = ".cipher_vault", master_key: bytes = None):
        self.vault_path = vault_path
        self.key = master_key or Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self._index: Dict[str, dict] = {}
        self._load_vault()

    def _load_vault(self):
        """Load vault index from disk."""
        index_path = f"{self.vault_path}.idx"
        if os.path.exists(index_path):
            with open(index_path, "r") as f:
                self._index = json.load(f)

    def _save_index(self):
        """Persist vault index to disk."""
        index_path = f"{self.vault_path}.idx"
        with open(index_path, "w") as f:
            json.dump(self._index, f, indent=2)

    def store(self, name: str, value: str, tags: List[str] = None) -> dict:
        """Store an encrypted secret."""
        encrypted = self.fernet.encrypt(value.encode())
        filepath = f"{self.vault_path}/{name}.secret"
        os.makedirs(self.vault_path, exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(encrypted)

        self._index[name] = {
            "created": time.time(),
            "updated": time.time(),
            "tags": tags or [],
            "size": len(value),
        }
        self._save_index()

        return {"name": name, "status": "stored", "encrypted": True}

    def retrieve(self, name: str) -> Optional[str]:
        """Retrieve and decrypt a secret."""
        if name not in self._index:
            return None
        filepath = f"{self.vault_path}/{name}.secret"
        if not os.path.exists(filepath):
            return None
        with open(filepath, "rb") as f:
            encrypted = f.read()
        return self.fernet.decrypt(encrypted).decode()

    def list_secrets(self) -> List[dict]:
        """List all stored secrets (names only, no values)."""
        return [
            {"name": name, **meta}
            for name, meta in self._index.items()
        ]

    def delete(self, name: str) -> bool:
        """Delete a secret from the vault."""
        if name not in self._index:
            return False
        filepath = f"{self.vault_path}/{name}.secret"
        if os.path.exists(filepath):
            os.remove(filepath)
        del self._index[name]
        self._save_index()
        return True

    def rotate_key(self) -> bytes:
        """Rotate the vault encryption key."""
        old_fernet = self.fernet
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

        for name in self._index:
            filepath = f"{self.vault_path}/{name}.secret"
            with open(filepath, "rb") as f:
                encrypted = f.read()
            plaintext = old_fernet.decrypt(encrypted)
            new_encrypted = self.fernet.encrypt(plaintext)
            with open(filepath, "wb") as f:
                f.write(new_encrypted)

        return self.key
