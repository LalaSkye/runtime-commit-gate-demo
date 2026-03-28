"""
Entry Condition Guard.

Validates that an action packet has a well-formed condition
before it reaches the commit gate.

Checks: presence, testability, binding, context.
Fail -> HOLD. No propagation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


# Allowed test forms
ALLOWED_TEST_TYPES = frozenset({"expression", "predicate_ref", "structured"})

# Disallowed condition patterns (free prose indicators)
PROSE_INDICATORS = frozenset({
    "looks good", "seems safe", "should be fine",
    "probably ok", "i think so", "maybe",
})


@dataclass(frozen=True)
class GuardResult:
    """Immutable result of entry guard evaluation."""
    passed: bool
    failed_check: Optional[str] = None
    reason: Optional[str] = None


def _is_prose(value: str) -> bool:
    """Check if a string is free prose (not machine-checkable)."""
    lower = value.strip().lower()
    if lower in PROSE_INDICATORS:
        return True
    # No structured markers -> likely prose
    if not any(c in value for c in ("==", ">=", "<=", "!=", "&&", "||", "(", ")")):
        # Check if it looks like a predicate reference
        if value.replace("_", "").replace(".", "").isalnum():
            return False  # could be a predicate ref like "window_active"
        return True
    return False


def validate_entry(packet: Dict[str, Any]) -> GuardResult:
    """
    Validate an action packet's condition structure.

    Checks run in order. First failure stops.

    C1: condition present and non-empty
    C2: test is machine-checkable
    C3: binding links condition to execution
    C4: evaluation context variables declared
    """

    # ── C1: CONDITION_PRESENT ──
    condition = packet.get("condition")
    if condition is None:
        return GuardResult(
            passed=False,
            failed_check="C1_CONDITION_PRESENT",
            reason="condition field missing",
        )
    if isinstance(condition, str) and not condition.strip():
        return GuardResult(
            passed=False,
            failed_check="C1_CONDITION_PRESENT",
            reason="condition field empty",
        )

    # ── C2: CONDITION_TESTABLE ──
    test = packet.get("test")
    if test is None:
        return GuardResult(
            passed=False,
            failed_check="C2_CONDITION_TESTABLE",
            reason="test field missing",
        )

    if isinstance(test, str):
        if _is_prose(test):
            return GuardResult(
                passed=False,
                failed_check="C2_CONDITION_TESTABLE",
                reason="test is free prose, not machine-checkable",
            )
        # String test must declare boolean output somewhere
        # Accept if it looks like an expression
    elif isinstance(test, dict):
        returns = test.get("returns")
        if returns != "boolean":
            return GuardResult(
                passed=False,
                failed_check="C2_CONDITION_TESTABLE",
                reason=f"test.returns must be 'boolean', got '{returns}'",
            )
        expr = test.get("expr") or test.get("predicate")
        if not expr:
            return GuardResult(
                passed=False,
                failed_check="C2_CONDITION_TESTABLE",
                reason="test has no expr or predicate",
            )
    else:
        return GuardResult(
            passed=False,
            failed_check="C2_CONDITION_TESTABLE",
            reason=f"test must be string or dict, got {type(test).__name__}",
        )

    # ── C3: CONDITION_BOUND ──
    binding = packet.get("binding")
    if binding is None:
        return GuardResult(
            passed=False,
            failed_check="C3_CONDITION_BOUND",
            reason="binding field missing",
        )
    if not isinstance(binding, dict):
        return GuardResult(
            passed=False,
            failed_check="C3_CONDITION_BOUND",
            reason=f"binding must be dict, got {type(binding).__name__}",
        )

    on_false = binding.get("on_false")
    on_unevaluable = binding.get("on_unevaluable")
    if on_false is None:
        return GuardResult(
            passed=False,
            failed_check="C3_CONDITION_BOUND",
            reason="binding.on_false not defined",
        )
    if on_false != "hold":
        return GuardResult(
            passed=False,
            failed_check="C3_CONDITION_BOUND",
            reason=f"binding.on_false must be 'hold', got '{on_false}'",
        )

    # ── C4: EVALUATION_CONTEXT_BOUND ──
    if isinstance(test, dict):
        declared_context = set(test.get("context", []))
        expr = test.get("expr", "")
        # Extract variable-like tokens from expression
        import re
        tokens = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', expr))
        # Remove common operators/keywords
        keywords = {"true", "false", "and", "or", "not", "in", "is", "none", "null"}
        tokens -= keywords
        # Check all tokens are in declared context
        undeclared = tokens - declared_context
        if undeclared:
            return GuardResult(
                passed=False,
                failed_check="C4_EVALUATION_CONTEXT_BOUND",
                reason=f"undeclared context variables: {sorted(undeclared)}",
            )

    # ── ALL CHECKS PASSED ──
    return GuardResult(passed=True)
