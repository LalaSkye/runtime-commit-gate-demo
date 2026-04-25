"""
Commit Gate.

Only path to mutation. Fail-closed.
Invariant: no valid decision record -> no state mutation.

V3: optional durable NonceLedger (FINDING_B07 fix); issued_at-in-future
check (FINDING_B22 fix); ledger-first ordering for crash-recovery semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from .audit import AuditLog
from .decision_record import DecisionRecord, verify_signature
from .state_store import StateStore
from .nonce_ledger import NonceLedger


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


class _InMemoryNonceSet:
    """
    Legacy in-memory replay protection for V1/V2 compatibility.

    Same interface as NonceLedger.contains/consume but no durability.
    """

    def __init__(self) -> None:
        self._used: Set[str] = set()

    def contains(self, nonce: str) -> bool:
        if not isinstance(nonce, str):
            return False
        return nonce in self._used

    def consume(self, nonce: str, decision_id: str) -> bool:
        if nonce in self._used:
            return False
        self._used.add(nonce)
        return True

    def reset(self) -> None:
        self._used.clear()


class CommitGate:
    """
    Validates decision records, consumes nonces (durably if a NonceLedger
    is provided), delegates to state store on full pass, logs all attempts.
    """

    def __init__(
        self,
        store: StateStore,
        audit: AuditLog,
        nonce_ledger: Optional[NonceLedger] = None,
    ):
        self._store = store
        self._audit = audit
        self._nonces = nonce_ledger if nonce_ledger is not None else _InMemoryNonceSet()
        # Back-compat shim: tests that touch _used_nonces expect a set-like.
        # We expose the underlying set when in legacy mode for tests only.
        if isinstance(self._nonces, _InMemoryNonceSet):
            self._used_nonces = self._nonces._used  # type: ignore[attr-defined]
        else:
            # For durable ledger, expose the in-memory cache as a read-only view.
            self._used_nonces = self._nonces.all_nonces()  # snapshot

    def reset_nonces(self) -> None:
        """Clear nonce registry. For testing only."""
        self._nonces.reset()

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

        # ── CHECK 4: Issuance and expiry windows are well-formed ──
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

        try:
            issued = datetime.fromisoformat(decision.issued_at)
        except (ValueError, TypeError):
            result = GateResult(
                allowed=False,
                reason="INVALID_ISSUANCE_FORMAT",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        # V3 (FINDING_B22 fix): zero-tolerance future issued_at.
        if now < issued:
            result = GateResult(
                allowed=False,
                reason="ISSUED_AT_IN_FUTURE",
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
        if self._nonces.contains(decision.nonce):
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

        # ── ALL CHECKS PASSED ──
        # V3 ordering: durably consume nonce BEFORE mutation.
        # If consume returns False here, a concurrent caller already
        # claimed the nonce. Treat as replay.
        consumed = self._nonces.consume(decision.nonce, decision.decision_id)
        if not consumed:
            result = GateResult(
                allowed=False,
                reason="NONCE_REPLAYED",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        try:
            self._store.apply_mutation(action, object_id, actor_id, params)
        except Exception as e:
            # Pre-registered design: ledger-first ordering means the nonce
            # is now consumed even though the mutation did not occur. The
            # operator must reissue with a new nonce. This is the
            # conservative choice (no partial mutation).
            result = GateResult(
                allowed=False,
                reason=f"MUTATION_ERROR:{str(e)}",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

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
