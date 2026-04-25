"""
Audit Log.

Append-only JSONL. Hash-linked entries (V3): each entry includes
seq (monotonic int) and prev_hash (sha256 of the previous entry's
canonical-JSON form, including its own seq+prev_hash).

verify_chain() detects post-hoc edits, truncation, insertion,
reordering, duplication.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple


DEFAULT_AUDIT_PATH = Path(__file__).parent.parent / "data" / "audit.jsonl"

GENESIS_PREV_HASH = "0" * 64


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _hash_entry(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or DEFAULT_AUDIT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        self._lock = threading.Lock()

    def _read_last_entry(self) -> Optional[dict]:
        """Return the last well-formed entry, or None if log is empty/missing.

        If the log file has been deleted (B06 attack), recreate it. Chaining
        from None means the new entry becomes a fresh genesis. The discontinuity
        is detectable via verify_chain across an externally-anchored prior head.
        """
        if not self._path.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.touch()
            return None
        last = None
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    # Malformed tail line; ignore for chaining purposes.
                    # verify_chain() will catch this as corruption.
                    continue
        return last

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
        """Write one audit entry with seq + prev_hash. Returns the entry."""
        with self._lock:
            last = self._read_last_entry()
            if last is None:
                seq = 0
                prev_hash = GENESIS_PREV_HASH
            else:
                seq = int(last.get("seq", -1)) + 1
                prev_hash = _hash_entry(last)

            entry = {
                "seq": seq,
                "prev_hash": prev_hash,
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
            line = _canonical(entry) + "\n"
            with open(self._path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
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
        with self._lock:
            with open(self._path, "w") as f:
                f.write("")

    def verify_chain(self) -> Tuple[bool, Optional[int], str]:
        """
        Verify the hash chain.

        Returns (ok, error_index, message).
        - (True, None, "OK") on success.
        - (False, idx, msg) on first detected break.

        Detects:
        - Edited fields (any change to entry contents)
        - Inserted forged entries (hash mismatch at insertion point)
        - Truncated tail (chain verifies up to truncation; head_hash
          will not match an externally-anchored head)
        - Reordering (hash mismatch)
        - Duplication (seq mismatch — duplicates produce repeated seq)
        - Malformed JSON lines (parse failure)
        """
        expected_prev = GENESIS_PREV_HASH
        expected_seq = 0
        with open(self._path, "r") as f:
            for line_no, raw in enumerate(f):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return (False, line_no, f"Malformed JSON at line {line_no}: {e}")

                if not isinstance(entry, dict):
                    return (False, line_no, f"Non-object entry at line {line_no}")

                seq = entry.get("seq")
                prev_hash = entry.get("prev_hash")

                if seq is None or prev_hash is None:
                    return (False, line_no, f"Missing seq or prev_hash at line {line_no}")

                if seq != expected_seq:
                    return (
                        False,
                        line_no,
                        f"Seq mismatch at line {line_no}: expected {expected_seq}, got {seq}",
                    )

                if prev_hash != expected_prev:
                    return (
                        False,
                        line_no,
                        f"prev_hash mismatch at line {line_no}: chain broken",
                    )

                expected_prev = _hash_entry(entry)
                expected_seq = seq + 1

        return (True, None, "OK")

    def head_hash(self) -> str:
        """Hash of the last entry (the chain head). For external anchoring."""
        last = self._read_last_entry()
        if last is None:
            return GENESIS_PREV_HASH
        return _hash_entry(last)
