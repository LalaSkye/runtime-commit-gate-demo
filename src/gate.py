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
from .decision_record import (
    DecisionRecord,
    canonical_params,
    hash_params,
    verify_signature,
)
from .state_store import StateStore
from .nonce_ledger import NonceLedger


# Closed set of governed actions
GOVERNED_ACTIONS = frozenset({"approve_invoice", "change_limit", "delete_env"})

# Accepted policy versions
ACCEPTED_POLICY_VERSIONS = frozenset({"2026-03-28.1"})

# V4: actions that legitimately take no params. Records with both
# params_hash=None and params=None are accepted only for these actions
# (legacy unbound mode). All other governed actions require V4 binding.
PARAMETERLESS_ACTIONS = frozenset({"delete_env"})


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

        # ── CHECK 11 (V4): Parameter binding ──
        # Three legitimate cases for the legacy `execute()` path:
        #   (i)   decision.params_hash is None AND decision.params is None
        #         AND caller params is None  -> legacy unbound mode.
        #         Allowed only for PARAMETERLESS_ACTIONS.
        #   (ii)  decision.params_hash is not None AND decision.params is None
        #         -> Mode A. Hash caller params and compare.
        #   (iii) decision.params is not None -> Mode B record was sent
        #         to the wrong path. Reject.
        if decision.params is not None:
            result = GateResult(
                allowed=False,
                reason="WRONG_GATE_PATH",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(result, actor_id, environment, decision.decision_id)
            return result

        if decision.params_hash is None:
            # Legacy unbound mode.
            if params is not None:
                # Caller-supplied params with no binding == ambient authority.
                # Reject: this is the V4 gap closure.
                result = GateResult(
                    allowed=False,
                    reason="PARAMS_NOT_BOUND",
                    decision_id=decision.decision_id,
                    action=action,
                    object_id=object_id,
                )
                self._log(result, actor_id, environment, decision.decision_id)
                return result
            if action not in PARAMETERLESS_ACTIONS:
                # Action takes params but record carries no binding.
                result = GateResult(
                    allowed=False,
                    reason="PARAMS_NOT_BOUND",
                    decision_id=decision.decision_id,
                    action=action,
                    object_id=object_id,
                )
                self._log(result, actor_id, environment, decision.decision_id)
                return result
            # else: parameterless action, no params, no binding. Continue.
        else:
            # Mode A: re-hash caller params, compare to signed hash.
            try:
                actual = hash_params(params)
            except Exception as e:
                result = GateResult(
                    allowed=False,
                    reason=f"INVALID_PARAMS_TYPE:{e}",
                    decision_id=decision.decision_id,
                    action=action,
                    object_id=object_id,
                )
                self._log(result, actor_id, environment, decision.decision_id)
                return result
            if actual != decision.params_hash:
                result = GateResult(
                    allowed=False,
                    reason="PARAMS_HASH_MISMATCH",
                    decision_id=decision.decision_id,
                    action=action,
                    object_id=object_id,
                )
                self._log(result, actor_id, environment, decision.decision_id)
                return result

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

    def execute_bound(
        self,
        action: str,
        object_id: str,
        environment: str,
        actor_id: str,
        decision: Optional[DecisionRecord] = None,
    ) -> GateResult:
        """V4 Mode B path. Reads params from `decision.params` and applies
        them. Caller cannot supply or override params. A record without
        embedded params is rejected with WRONG_GATE_PATH.
        """
        if decision is None:
            r = GateResult(allowed=False, reason="NO_DECISION_RECORD",
                           action=action, object_id=object_id)
            self._log(r, actor_id, environment, None)
            return r
        if decision.params is None:
            r = GateResult(
                allowed=False,
                reason="WRONG_GATE_PATH",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        if decision.params_hash is not None:
            # Mode B records must not carry params_hash.
            r = GateResult(
                allowed=False,
                reason="WRONG_GATE_PATH",
                decision_id=decision.decision_id,
                action=action,
                object_id=object_id,
            )
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # Delegate to execute() with params taken from the record. We pass
        # them as the params argument so all V1-V11 checks still run, but
        # we also synthesise a hash so the binding check sees a Mode A
        # equivalent. To avoid that, we use a small internal flag-shaped
        # call: bypass the binding check by providing matching hash.
        # Cleanest path is to call into the same checks directly.
        return self._execute_with_bound_params(
            action, object_id, environment, actor_id, decision
        )

    def _execute_with_bound_params(
        self,
        action: str,
        object_id: str,
        environment: str,
        actor_id: str,
        decision: DecisionRecord,
    ) -> GateResult:
        """Internal: same checks as execute() but params come from the
        record itself. Used by execute_bound().
        """
        # Synthesise a Mode A surrogate record so we reuse execute().
        # The surrogate has params_hash set, params=None, signature
        # recomputed for verification. But we can't recompute the
        # signature (we don't have the secret). Instead, run the checks
        # inline.
        # ── verdict ──
        if decision.verdict != "ALLOW":
            r = GateResult(allowed=False, reason=f"VERDICT_NOT_ALLOW:{decision.verdict}",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # ── signature ──
        if not verify_signature(decision):
            r = GateResult(allowed=False, reason="INVALID_SIGNATURE",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # ── time windows ──
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        try:
            expires = datetime.fromisoformat(decision.expires_at)
        except (ValueError, TypeError):
            r = GateResult(allowed=False, reason="INVALID_EXPIRY_FORMAT",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        try:
            issued = datetime.fromisoformat(decision.issued_at)
        except (ValueError, TypeError):
            r = GateResult(allowed=False, reason="INVALID_ISSUANCE_FORMAT",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        if now < issued:
            r = GateResult(allowed=False, reason="ISSUED_AT_IN_FUTURE",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        if now > expires:
            r = GateResult(allowed=False, reason="DECISION_EXPIRED",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # ── nonce replay ──
        if self._nonces.contains(decision.nonce):
            r = GateResult(allowed=False, reason="NONCE_REPLAYED",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # ── action / object / env / policy match ──
        for got, want, code in [
            (decision.action, action, "ACTION_MISMATCH"),
            (decision.object_id, object_id, "OBJECT_MISMATCH"),
            (decision.environment, environment, "ENVIRONMENT_MISMATCH"),
        ]:
            if got != want:
                r = GateResult(
                    allowed=False,
                    reason=f"{code}:requested={want},decision={got}",
                    decision_id=decision.decision_id,
                    action=action,
                    object_id=object_id,
                )
                self._log(r, actor_id, environment, decision.decision_id)
                return r
        if decision.policy_version not in ACCEPTED_POLICY_VERSIONS:
            r = GateResult(allowed=False, reason=f"POLICY_VERSION_REJECTED:{decision.policy_version}",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        if action not in GOVERNED_ACTIONS:
            r = GateResult(allowed=False, reason=f"UNKNOWN_ACTION:{action}",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        # ── consume nonce + apply mutation with embedded params ──
        consumed = self._nonces.consume(decision.nonce, decision.decision_id)
        if not consumed:
            r = GateResult(allowed=False, reason="NONCE_REPLAYED",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        try:
            self._store.apply_mutation(action, object_id, actor_id, decision.params)
        except Exception as e:
            r = GateResult(allowed=False, reason=f"MUTATION_ERROR:{str(e)}",
                           decision_id=decision.decision_id, action=action, object_id=object_id)
            self._log(r, actor_id, environment, decision.decision_id)
            return r
        r = GateResult(allowed=True, reason="ALL_CHECKS_PASSED",
                       decision_id=decision.decision_id, action=action, object_id=object_id)
        self._log(r, actor_id, environment, decision.decision_id)
        return r

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
