"""
Commit Gate.

Only path to mutation. Fail-closed.
Invariant: no valid decision record -> no state mutation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .audit import AuditLog
from .decision_record import DecisionRecord, verify_signature
from .nonce_ledger import NonceLedger
from .state_store import StateStore


# Closed set of governed actions
GOVERNED_ACTIONS = frozenset({"approve_invoice", "change_limit", "delete_env"})

# Accepted policy versions
ACCEPTED_POLICY_VERSIONS = frozenset({"2026-03-28.1"})


@dataclass(frozen=True)
class GateResult:
    """Immutable result of a gate evaluation."""
    allowed: bool
    reason: str
    decision_id: Optional[str] = None
    action: Optional[str] = None
    object_id: Optional[str] = None


class CommitGate:
    """
    Validates decision records, consumes nonces,
    delegates to state store on full pass, logs all attempts.
    """

    def __init__(self, store: StateStore, audit: AuditLog, nonce_ledger_path: str | os.PathLike[str] = "var/nonces.jsonl"):
        self._store = store
        self._audit = audit
        self._nonce_ledger = NonceLedger(nonce_ledger_path)

    def reset_nonces(self) -> None:
        """Clear nonce registry. For testing only."""
        self._nonce_ledger.clear()

    def execute(
        self,
        action: str,
        object_id: str,
        environment: str,
        actor_id: str,
        decision: Optional[DecisionRecord] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> GateResult:
        """
        Single entry point for mutations.
        Checks run in order. First failure stops evaluation.
        """

        # ── CHECK 1: Decision record exists ──
        if decision is None:
            result = GateResult(
                allowed=False,
                reason="NO_DECISION_RECORD",
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, None)
            return result

        # ── CHECK 2: Verdict is ALLOW ──
        if decision.verdict != "ALLOW":
            result = GateResult(
                allowed=False,
                reason=f"VERDICT_NOT_ALLOW:{decision.verdict}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 3: Signature valid ──
        if not verify_signature(decision):
            result = GateResult(
                allowed=False,
                reason="INVALID_SIGNATURE",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 4: Not expired ──
        now = datetime.now(timezone.utc)
        try:
            expires = datetime.fromisoformat(decision.expires_at)
        except (ValueError, TypeError):
            result = GateResult(
                allowed=False,
                reason="INVALID_EXPIRY_FORMAT",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        if now > expires:
            result = GateResult(
                allowed=False,
                reason="DECISION_EXPIRED",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 5: Nonce not replayed ──
        if self._nonce_ledger.seen(decision.nonce):
            result = GateResult(
                allowed=False,
                reason="NONCE_REPLAYED",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 6: Action matches ──
        if decision.action != action:
            result = GateResult(
                allowed=False,
                reason=f"ACTION_MISMATCH:requested={action},decision={decision.action}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 7: Object matches ──
        if decision.object_id != object_id:
            result = GateResult(
                allowed=False,
                reason=f"OBJECT_MISMATCH:requested={object_id},decision={decision.object_id}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 8: Environment matches ──
        if decision.environment != environment:
            result = GateResult(
                allowed=False,
                reason=f"ENVIRONMENT_MISMATCH:requested={environment},decision={decision.environment}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 9: Policy version accepted ──
        if decision.policy_version not in ACCEPTED_POLICY_VERSIONS:
            result = GateResult(
                allowed=False,
                reason=f"POLICY_VERSION_REJECTED:{decision.policy_version}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # ── CHECK 10: Action is governed ──
        if action not in GOVERNED_ACTIONS:
            result = GateResult(
                allowed=False,
                reason=f"UNKNOWN_ACTION:{action}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # Extension point: add further checks here before mutation.

        # ── ALL CHECKS PASSED — mutate then consume nonce ──
        try:
            self._store.apply_mutation(action, object_id, actor_id, params)
        except Exception as e:
            result = GateResult(
                allowed=False,
                reason=f"MUTATION_ERROR:{str(e)}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        self._nonce_ledger.consume(decision.nonce)

        result = GateResult(
            allowed=True,
            reason="ALL_CHECKS_PASSED",
            decision_id=decision.decision_id,
            action=action,
            object_id=object_id,
        )
        self._log(result, actor_id, environment, decision.decision_id)
        return result

    def _log(self, result: GateResult, actor_id: str, environment: str, decision_id: Optional[str]) -> None:
        self._audit.append(
            event_type="GATE_EVALUATION",
            action=result.action or "unknown",
            object_id=result.object_id or "unknown",
            actor_id=actor_id,
            decision_id=decision_id,
            environment=environment,
            outcome="ALLOWED" if result.allowed else "BLOCKED",
            reason=result.reason,
        )
