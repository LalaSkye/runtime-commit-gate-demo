"""
Crash recovery / consistency verification.

Deterministic, side-effect free.

Pre-registered semantics: PRE_REGISTRATION_v3.md, design choice 5.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .audit import AuditLog
from .nonce_ledger import NonceLedger
from .state_store import StateStore


# Verdict tokens
CONSISTENT = "CONSISTENT"
STATE_AHEAD = "STATE_AHEAD"
LEDGER_AHEAD = "LEDGER_AHEAD"


@dataclass(frozen=True)
class ConsistencyDiscrepancy:
    """One discrepancy item."""
    kind: str  # STATE_AHEAD or LEDGER_AHEAD
    detail: str


@dataclass(frozen=True)
class ConsistencyReport:
    """Result of verify_consistency. Read-only, deterministic."""
    verdict: str  # CONSISTENT, STATE_AHEAD, LEDGER_AHEAD, or "MIXED"
    discrepancies: tuple = field(default_factory=tuple)

    def is_ok(self) -> bool:
        return self.verdict == CONSISTENT


# Module-level lock so concurrent verify_consistency() calls do not corrupt
# their own intermediate computations. Reads are still independent.
_VERIFY_LOCK = threading.Lock()


def verify_consistency(
    store: StateStore,
    ledger: NonceLedger,
    audit: AuditLog,
) -> ConsistencyReport:
    """
    Compare state, nonce ledger, and audit log for consistency.

    Returns a ConsistencyReport. Does NOT mutate any of the three.

    Detects:
    - LEDGER_AHEAD: nonce in ledger has no matching ALLOWED audit entry.
      Indicates crash between ledger-write and (mutation+audit-write).
    - STATE_AHEAD: state object shows mutation that has no matching
      ALLOWED audit entry referencing it. Indicates crash between
      mutation and audit-write.
    """
    with _VERIFY_LOCK:
        ledger_nonces = set(ledger.all_nonces())
        audit_entries = audit.read_all()
        state = store.read()

    # Index audit entries by nonce-equivalent — we use decision_id since
    # audit entries don't carry the nonce. We assume a 1:1 between
    # decision_id and nonce within a session, which is enforced by the
    # decision-record construction.
    allowed_decision_ids = {
        e["decision_id"]
        for e in audit_entries
        if e.get("outcome") == "ALLOWED" and e.get("decision_id")
    }

    # Read ledger entries to map nonce -> decision_id.
    nonce_to_decision = {}
    ledger_path: Path = ledger._path  # type: ignore[attr-defined]
    if ledger_path.exists():
        with open(ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and "nonce" in entry and "decision_id" in entry:
                    nonce_to_decision[entry["nonce"]] = entry["decision_id"]

    discrepancies: List[ConsistencyDiscrepancy] = []

    # LEDGER_AHEAD: nonces in ledger whose decision_id has no ALLOWED audit
    for nonce in ledger_nonces:
        decision_id = nonce_to_decision.get(nonce)
        if decision_id is None:
            discrepancies.append(ConsistencyDiscrepancy(
                kind=LEDGER_AHEAD,
                detail=f"Nonce {nonce} present without decision_id mapping",
            ))
            continue
        if decision_id not in allowed_decision_ids:
            discrepancies.append(ConsistencyDiscrepancy(
                kind=LEDGER_AHEAD,
                detail=f"Nonce consumed for decision {decision_id} but no ALLOWED audit entry",
            ))

    # STATE_AHEAD: state mutations without matching ALLOWED audit entry.
    # We detect mutations by looking for non-initial fields on each object.
    # This is a heuristic appropriate for the demo state shape.
    initial_environments_state = {"status": "active", "deleted": False, "deleted_by": None}

    # Audit entries that reference a state-mutating action by object_id+action
    audit_object_actions = {
        (e["object_id"], e["action"])
        for e in audit_entries
        if e.get("outcome") == "ALLOWED"
    }

    for env_id, env_data in state.get("environments", {}).items():
        if env_data.get("deleted") is True:
            if (env_id, "delete_env") not in audit_object_actions:
                discrepancies.append(ConsistencyDiscrepancy(
                    kind=STATE_AHEAD,
                    detail=f"Environment {env_id} marked deleted without ALLOWED audit entry",
                ))

    for inv_id, inv_data in state.get("invoices", {}).items():
        if inv_data.get("status") == "approved":
            if (inv_id, "approve_invoice") not in audit_object_actions:
                discrepancies.append(ConsistencyDiscrepancy(
                    kind=STATE_AHEAD,
                    detail=f"Invoice {inv_id} approved without ALLOWED audit entry",
                ))

    for acct_id, acct_data in state.get("limits", {}).items():
        if acct_data.get("last_changed_by") is not None:
            if (acct_id, "change_limit") not in audit_object_actions:
                discrepancies.append(ConsistencyDiscrepancy(
                    kind=STATE_AHEAD,
                    detail=f"Limit {acct_id} changed without ALLOWED audit entry",
                ))

    if not discrepancies:
        return ConsistencyReport(verdict=CONSISTENT, discrepancies=())

    kinds = {d.kind for d in discrepancies}
    if len(kinds) == 1:
        verdict = next(iter(kinds))
    else:
        verdict = "MIXED"

    return ConsistencyReport(verdict=verdict, discrepancies=tuple(discrepancies))
