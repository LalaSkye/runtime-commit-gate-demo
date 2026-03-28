"""
State Store.

JSON-backed. Three governed objects.
Mutations only via apply_mutation().
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_STATE_PATH = Path(__file__).parent.parent / "data" / "state.json"

INITIAL_STATE = {
    "invoices": {
        "inv_001": {"status": "pending", "amount": 5000.00, "approved_by": None}
    },
    "limits": {
        "acct_778": {"daily_limit": 10000.00, "last_changed_by": None}
    },
    "environments": {
        "env_1": {"status": "active", "deleted": False, "deleted_by": None}
    },
}


class StateStore:
    """Read freely. Write only via apply_mutation()."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or DEFAULT_STATE_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._write(INITIAL_STATE)

    def _write(self, data: dict) -> None:
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)

    def read(self) -> dict:
        with open(self._path, "r") as f:
            return json.load(f)

    def reset(self) -> None:
        """Reset to initial state. For testing only."""
        self._write(INITIAL_STATE)

    def apply_mutation(self, action: str, object_id: str, actor_id: str, params: Optional[Dict[str, Any]] = None) -> dict:
        """
        Apply mutation. Called by commit gate after all checks pass.
        server.py never calls this directly.
        """
        state = self.read()
        params = params or {}

        if action == "approve_invoice":
            if object_id not in state["invoices"]:
                raise ValueError(f"Unknown invoice: {object_id}")
            state["invoices"][object_id]["status"] = "approved"
            state["invoices"][object_id]["approved_by"] = actor_id

        elif action == "change_limit":
            if object_id not in state["limits"]:
                raise ValueError(f"Unknown account: {object_id}")
            new_limit = params.get("new_limit", state["limits"][object_id]["daily_limit"])
            state["limits"][object_id]["daily_limit"] = new_limit
            state["limits"][object_id]["last_changed_by"] = actor_id

        elif action == "delete_env":
            if object_id not in state["environments"]:
                raise ValueError(f"Unknown environment: {object_id}")
            state["environments"][object_id]["status"] = "deleted"
            state["environments"][object_id]["deleted"] = True
            state["environments"][object_id]["deleted_by"] = actor_id

        else:
            raise ValueError(f"Unknown action: {action}")

        self._write(state)
        return state

    def snapshot(self) -> dict:
        """Return a deep copy of current state for comparison."""
        return deepcopy(self.read())
