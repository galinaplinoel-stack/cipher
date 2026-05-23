"""PII Detection and Anonymization Engine for CIPHER Agent."""

import re
import hashlib
from typing import Dict, List, Optional


class PIIDetector:
    """Detects personally identifiable information in text."""

    PATTERNS = {
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "date_of_birth": r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b",
    }

    def detect(self, text: str) -> Dict[str, List[str]]:
        """Detect PII patterns in text."""
        findings = {}
        for pii_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[pii_type] = matches
        return findings

    def has_pii(self, text: str) -> bool:
        """Check if text contains any PII."""
        return bool(self.detect(text))


class Anonymizer:
    """Anonymizes detected PII in text."""

    STRATEGIES = ["mask", "hash", "replace"]

    def __init__(self, strategy: str = "mask"):
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Strategy must be one of {self.STRATEGIES}")
        self.strategy = strategy
        self.detector = PIIDetector()

    def anonymize(self, text: str) -> dict:
        """Anonymize all PII in text."""
        findings = self.detector.detect(text)
        result = text
        replacements = []

        for pii_type, matches in findings.items():
            for match in matches:
                replacement = self._get_replacement(match, pii_type)
                result = result.replace(match, replacement)
                replacements.append({
                    "type": pii_type,
                    "original_length": len(match),
                    "replacement": replacement,
                })

        return {
            "anonymized_text": result,
            "pii_found": len(replacements) > 0,
            "items_anonymized": len(replacements),
            "details": replacements,
        }

    def _get_replacement(self, value: str, pii_type: str) -> str:
        """Generate replacement based on strategy."""
        if self.strategy == "mask":
            return "[REDACTED_" + pii_type.upper() + "]"
        elif self.strategy == "hash":
            h = hashlib.sha256(value.encode()).hexdigest()[:12]
            return f"[HASH:{h}]"
        elif self.strategy == "replace":
            fake_data = {
                "email": "[EMAIL_REDACTED]",
                "phone": "[PHONE_REDACTED]",
                "ssn": "[SSN_REDACTED]",
                "credit_card": "[CC_REDACTED]",
                "ip_address": "[IP_REDACTED]",
                "date_of_birth": "[DOB_REDACTED]",
            }
            return fake_data.get(pii_type, "[REDACTED]")
        return "[REDACTED]"

    def scan(self, text: str) -> dict:
        """Scan text for PII without anonymizing."""
        findings = self.detector.detect(text)
        total = sum(len(v) for v in findings.values())
        return {
            "pii_detected": total > 0,
            "total_items": total,
            "breakdown": {k: len(v) for k, v in findings.items()},
            "details": findings,
        }
