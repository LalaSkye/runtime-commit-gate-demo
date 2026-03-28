"""
Audit Log.

Append-only. Every gate attempt logged.
No deletion. No editing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_AUDIT_PATH = Path(__file__).parent.parent / "data" / "audit.jsonl"


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or DEFAULT_AUDIT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()

    def append(
        self,
        event_type: str,
        action: str,
        object_id: str,
        actor_id: str,
        decision_id: Optional[str],
        outcome: str,
        reason: str,
        environment: Optional[str] = None,
    ) -> dict:
        """Write one audit entry. Returns the entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "action": action,
            "object_id": object_id,
            "actor_id": actor_id,
            "decision_id": decision_id,
            "environment": environment,
            "outcome": outcome,
            "reason": reason,
        }
        with open(self._path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def read_all(self) -> list:
        """Return all audit entries."""
        entries = []
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def clear(self) -> None:
        """Clear log. For testing only."""
        with open(self._path, "w") as f:
            f.write("")
