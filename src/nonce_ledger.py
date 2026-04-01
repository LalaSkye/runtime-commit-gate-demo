from __future__ import annotations

import json
import os
from pathlib import Path


class NonceLedger:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def seen(self, nonce: str) -> bool:
        if not self.path.exists():
            return False

        with self.path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    print(
                        f"WARNING: skipping malformed nonce ledger line {line_no}",
                        flush=True,
                    )
                    continue

                if record.get("nonce") == nonce:
                    return True

        return False

    def consume(self, nonce: str) -> None:
        if self.seen(nonce):
            return

        record = {"nonce": nonce}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()
