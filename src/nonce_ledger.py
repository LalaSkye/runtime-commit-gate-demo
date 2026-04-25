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
        """Stream the ledger file and rebuild the in-memory set."""
        with open(self._path, "r") as f:
            for line_no, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    if repair:
                        # Skip malformed line; do not include any nonce from it.
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
            if nonce in self._used:
                return False

            entry = {
                "nonce": nonce,
                "decision_id": decision_id,
                "consumed_at": datetime.now(timezone.utc).isoformat(),
            }
            line = json.dumps(entry, sort_keys=True) + "\n"

            # Append + fsync. This is the durability boundary.
            with open(self._path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

            self._used.add(nonce)
            return True

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
