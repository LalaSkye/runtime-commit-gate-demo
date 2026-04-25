"""
Durable Nonce Ledger.

Append-only JSONL. Rebuilds in-memory set on construction.
Fail-closed on corruption unless explicit repair=True.
fsync after each append for cross-process replay protection.

Pre-registered design: PRE_REGISTRATION_v3.md, section "V3 design choices".
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set

try:
    import fcntl  # POSIX only
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover — Windows
    _HAS_FCNTL = False


DEFAULT_LEDGER_PATH = Path(__file__).parent.parent / "data" / "nonce_ledger.jsonl"

REQUIRED_FIELDS = ("nonce", "decision_id", "consumed_at")


class NonceLedgerCorruption(Exception):
    """Raised when the on-disk ledger cannot be parsed."""


class NonceLedger:
    """
    Durable, append-only nonce ledger.

    Cross-process replay protection: after a successful append + fsync,
    a fresh NonceLedger constructed against the same path will see the
    nonce as consumed.
    """

    def __init__(self, path: Optional[Path] = None, repair: bool = False):
        self._path = path or DEFAULT_LEDGER_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            # touch atomically
            with open(self._path, "a"):
                pass
        self._lock = threading.Lock()
        self._used: Set[str] = set()
        self._rebuild(repair=repair)

    def _rebuild(self, repair: bool) -> None:
        """Stream the ledger file and rebuild the in-memory set.

        Reads in binary mode and decodes per line so non-UTF8 garbage is
        surfaced as NonceLedgerCorruption rather than UnicodeDecodeError
        (FINDING_C04 fix).
        """
        try:
            with open(self._path, "rb") as f:
                raw_bytes = f.read()
        except OSError as e:
            raise NonceLedgerCorruption(f"Cannot read ledger: {e}") from e

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            if repair:
                text = raw_bytes.decode("utf-8", errors="replace")
            else:
                raise NonceLedgerCorruption(
                    f"Non-UTF8 content in ledger: {e}"
                ) from e

        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                if repair:
                    continue
                raise NonceLedgerCorruption(
                    f"Malformed JSON at line {line_no}: {e}"
                ) from e

            if not isinstance(entry, dict):
                if repair:
                    continue
                raise NonceLedgerCorruption(
                    f"Non-object entry at line {line_no}"
                )

            missing = [f for f in REQUIRED_FIELDS if f not in entry]
            if missing:
                if repair:
                    continue
                raise NonceLedgerCorruption(
                    f"Missing fields {missing} at line {line_no}"
                )

            nonce = entry["nonce"]
            if not isinstance(nonce, str):
                if repair:
                    continue
                raise NonceLedgerCorruption(
                    f"Non-string nonce at line {line_no}"
                )

            self._used.add(nonce)

    def _refresh_from_disk(self) -> None:
        """Re-read the ledger file under the active lock. For cross-process
        coordination: another process may have appended since our last read.
        """
        try:
            with open(self._path, "rb") as f:
                raw_bytes = f.read()
        except OSError:
            return
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return  # corruption surfaced elsewhere
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("nonce"), str):
                self._used.add(entry["nonce"])

    def contains(self, nonce: str) -> bool:
        """Exact-match check. No whitespace, case, or type coercion."""
        if not isinstance(nonce, str):
            return False
        with self._lock:
            return nonce in self._used

    def consume(self, nonce: str, decision_id: str) -> bool:
        """
        Atomically record a nonce as consumed.

        Returns True if newly consumed, False if already present.
        Append + fsync happens before returning True.
        """
        if not isinstance(nonce, str) or not isinstance(decision_id, str):
            raise TypeError("nonce and decision_id must be strings")

        with self._lock:
            # Open file once, take an OS-level exclusive lock, refresh from
            # disk under the lock, check, append, fsync, release lock.
            # This makes the contains-check + append atomic across processes
            # (POSIX). FINDING_C05 fix.
            with open(self._path, "a+b") as f:
                if _HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # Refresh in-memory set from disk under lock
                    self._refresh_from_disk()
                    if nonce in self._used:
                        return False

                    entry = {
                        "nonce": nonce,
                        "decision_id": decision_id,
                        "consumed_at": datetime.now(timezone.utc).isoformat(),
                    }
                    line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
                    # Seek to end (a+b should already be at end on most platforms,
                    # but be explicit for portability).
                    f.seek(0, 2)
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
                    self._used.add(nonce)
                    return True
                finally:
                    if _HAS_FCNTL:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def all_nonces(self) -> Set[str]:
        with self._lock:
            return set(self._used)

    def reset(self) -> None:
        """Wipe ledger. For testing only."""
        with self._lock:
            with open(self._path, "w") as f:
                f.write("")
                f.flush()
                os.fsync(f.fileno())
            self._used.clear()
