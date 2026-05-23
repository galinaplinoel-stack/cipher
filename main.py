"""CIPHER - AI Privacy & Data Agent

A comprehensive privacy agent that encrypts data, anonymizes PII,
manages secrets, and audits data exposure.
"""

from agent.encryptor import Encryptor
from agent.anonymizer import Anonymizer, PIIDetector
from agent.vault import Vault
from agent.audit import AuditLog


class Cipher:
    """Main CIPHER agent orchestrating all privacy operations."""

    def __init__(self, vault_path: str = ".cipher_vault"):
        self.encryptor = Encryptor()
        self.anonymizer = Anonymizer(strategy="mask")
        self.detector = PIIDetector()
        self.vault = Vault(vault_path=vault_path)
        self.audit = AuditLog()

    def protect(self, text: str) -> dict:
        """Full protection pipeline: scan, anonymize, encrypt."""
        scan_result = self.anonymizer.scan(text)
        self.audit.log("scan", {"pii_found": scan_result["pii_detected"]})

        if scan_result["pii_detected"]:
            anon_result = self.anonymizer.anonymize(text)
            self.audit.log("anonymize", {
                "items_anonymized": anon_result["items_anonymized"]
            })
            text = anon_result["anonymized_text"]

        encrypted = self.encryptor.encrypt(text)
        self.audit.log("encrypt", {"algorithm": encrypted["algorithm"]})

        return {
            "protected_text": text,
            "encrypted": encrypted,
            "pii_detected": scan_result["pii_detected"],
            "pii_breakdown": scan_result["breakdown"],
        }

    def reveal(self, encrypted: dict) -> str:
        """Decrypt and return original text."""
        result = self.encryptor.decrypt(encrypted)
        self.audit.log("decrypt", {"success": True})
        return result

    def status(self) -> dict:
        """Get CIPHER agent status."""
        return {
            "encryption": "AES-256-GCM",
            "vault_secrets": len(self.vault.list_secrets()),
            "audit_events": self.audit.summary()["total_events"],
            "anonymizer_strategy": self.anonymizer.strategy,
        }


if __name__ == "__main__":
    cipher = Cipher()
    print("CIPHER Agent initialized.")
    print(f"Status: {cipher.status()}")
