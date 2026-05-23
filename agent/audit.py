"""Audit Logging Engine for CIPHER Agent."""

import json
import time
import os
from typing import List, Optional
from datetime import datetime


class AuditLog:
    """Tracks and audits all data operations."""

    EVENT_TYPES = [
        "encrypt", "decrypt", "anonymize", "scan",
        "vault_store", "vault_retrieve", "vault_delete",
        "vault_rotate", "export", "import", "access_denied",
    ]

    def __init__(self, log_path: str = ".cipher_audit.jsonl"):
        self.log_path = log_path
        self._buffer: List[dict] = []
        self._load_existing()

    def _load_existing(self):
        """Load existing audit log entries."""
        if os.path.exists(self.log_path):
            with open(self.log_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._buffer.append(json.loads(line))

    def log(self, event_type: str, details: dict = None, severity: str = "info"):
        """Log an audit event."""
        if event_type not in self.EVENT_TYPES:
            raise ValueError(f"Unknown event type: {event_type}")

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "epoch": time.time(),
            "event": event_type,
            "severity": severity,
            "details": details or {},
        }

        self._buffer.append(entry)
        self._persist(entry)
        return entry

    def _persist(self, entry: dict):
        """Write a single entry to the log file."""
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def query(
        self,
        event_type: Optional[str] = None,
        since: Optional[float] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """Query audit log with filters."""
        results = self._buffer

        if event_type:
            results = [e for e in results if e["event"] == event_type]
        if since:
            results = [e for e in results if e["epoch"] >= since]
        if severity:
            results = [e for e in results if e["severity"] == severity]

        return results[-limit:]

    def summary(self) -> dict:
        """Generate audit log summary."""
        if not self._buffer:
            return {"total_events": 0, "breakdown": {}}

        breakdown = {}
        for entry in self._buffer:
            event = entry["event"]
            breakdown[event] = breakdown.get(event, 0) + 1

        severity_counts = {}
        for entry in self._buffer:
            sev = entry["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_events": len(self._buffer),
            "breakdown": breakdown,
            "severity": severity_counts,
            "first_event": self._buffer[0]["timestamp"] if self._buffer else None,
            "last_event": self._buffer[-1]["timestamp"] if self._buffer else None,
        }

    def export_log(self, output_path: str):
        """Export audit log to a file."""
        with open(output_path, "w") as f:
            json.dump(self._buffer, f, indent=2)
        return {"exported": len(self._buffer), "path": output_path}

    def clear(self):
        """Clear the audit log (requires confirmation)."""
        self._buffer = []
        if os.path.exists(self.log_path):
            os.remove(self.log_path)
