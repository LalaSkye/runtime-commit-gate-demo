"""
Predicate Registry — FINDING_A20 fix (V2).

Closed registry of legitimate predicate references.
Any test field that is a bare identifier MUST be in this registry.
Anything not registered is treated as prose, not as a predicate reference.

This is the v2 remediation for FINDING_A20 documented in RESULTS_v1.md:
"Entry guard's _is_prose() cannot distinguish prose-shaped identifiers
('subjective_review') from legitimate predicate references ('window_active')."

Fix: use a positive list, not a heuristic. Bare identifiers must be
explicitly registered.
"""

from __future__ import annotations

from typing import FrozenSet


# Closed set of legitimate predicate references.
# In production, this would be loaded from a versioned registry artefact
# managed by the same governance discipline as policy versions.
REGISTERED_PREDICATES: FrozenSet[str] = frozenset({
    # Time-window predicates
    "window_active",
    "deployment_window_open",
    "business_hours",

    # State predicates
    "inventory_below_threshold",
    "balance_above_minimum",
    "approval_present",

    # Capability predicates
    "user_authenticated",
    "session_valid",
    "two_person_review_complete",

    # Environment predicates
    "production_lockdown_clear",
    "incident_freeze_lifted",
})


def is_registered_predicate(name: str) -> bool:
    """Return True if the bare identifier is a registered predicate."""
    if not isinstance(name, str):
        return False
    return name in REGISTERED_PREDICATES


def list_registered() -> FrozenSet[str]:
    """Read-only access to the registry."""
    return REGISTERED_PREDICATES
