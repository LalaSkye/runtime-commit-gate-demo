"""
Entry guard wiring integration tests.

Verifies that the entry guard is called in the /execute pipeline
BEFORE the commit gate, and that failures at the entry guard
never reach the gate or mutation path.
"""

from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from src.server import app, store, audit, gate


client = TestClient(app)


def setup_function():
    """Fresh state per test."""
    store.reset()
    audit.clear()
    gate.reset_nonces()


# -- TEST 1: Prose condition rejected before gate evaluation --

def test_prose_condition_blocked_before_gate():
    """
    A request with a prose condition (free text, not machine-checkable)
    must be blocked by the entry guard. The commit gate must never see it.
    State must not change. Audit must have no GATE_EVALUATION entry.
    """
    state_before = store.read()

    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
        "decision": None,
        "entry_condition": {
            "condition": "looks good",
            "test": "seems safe",
            "binding": {"on_false": "hold"},
        },
    })

    data = response.json()

    # Entry guard must block
    assert data["allowed"] is False
    assert "ENTRY_GUARD_HOLD" in data["reason"]
    assert "C2_CONDITION_TESTABLE" in data["reason"]

    # State must not have changed
    assert store.read() == state_before

    # Audit must be empty — request never reached the gate
    assert len(audit.read_all()) == 0


def test_missing_condition_blocked_before_gate():
    """
    A request with entry_condition but no condition field
    must be blocked at C1 before the gate.
    """
    state_before = store.read()

    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
        "decision": None,
        "entry_condition": {
            "test": "window_active",
            "binding": {"on_false": "hold"},
        },
    })

    data = response.json()

    assert data["allowed"] is False
    assert "ENTRY_GUARD_HOLD" in data["reason"]
    assert "C1_CONDITION_PRESENT" in data["reason"]
    assert store.read() == state_before
    assert len(audit.read_all()) == 0


def test_binding_bypass_attempt_blocked():
    """
    A request with on_false != 'hold' must be blocked at C3.
    """
    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
        "entry_condition": {
            "condition": "window check",
            "test": "window_active",
            "binding": {"on_false": "allow"},
        },
    })

    data = response.json()

    assert data["allowed"] is False
    assert "ENTRY_GUARD_HOLD" in data["reason"]
    assert "C3_CONDITION_BOUND" in data["reason"]


# -- TEST 2: Valid request passes entry guard + commit gate --

def test_valid_entry_condition_passes_to_gate_and_succeeds():
    """
    A request with a valid entry condition AND a valid decision record
    must pass both the entry guard and the commit gate. State must mutate.
    """
    state_before = store.read()
    assert state_before["environments"]["env_1"]["deleted"] is False

    # First, get a signed decision record via /decide
    decide_response = client.post("/decide", json={
        "actor_id": "user_123",
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "verdict": "ALLOW",
        "expires_in_seconds": 300,
    })
    decision = decide_response.json()

    # Execute with valid entry condition + valid decision
    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
        "decision": decision,
        "entry_condition": {
            "condition": "deployment window active",
            "test": "window_active",
            "binding": {"on_false": "hold"},
        },
    })

    data = response.json()

    # Both layers passed
    assert data["allowed"] is True
    assert data["reason"] == "ALL_CHECKS_PASSED"

    # State mutated
    state_after = store.read()
    assert state_after["environments"]["env_1"]["deleted"] is True
    assert state_after["environments"]["env_1"]["deleted_by"] == "user_123"


def test_valid_entry_condition_but_no_decision_still_blocked_by_gate():
    """
    Entry guard passes, but no decision record means the gate blocks.
    This proves the two layers are independent: passing one does not
    bypass the other.
    """
    state_before = store.read()

    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
        "decision": None,
        "entry_condition": {
            "condition": "deployment window active",
            "test": "window_active",
            "binding": {"on_false": "hold"},
        },
    })

    data = response.json()

    # Entry guard passed, but gate blocked (no decision)
    assert data["allowed"] is False
    assert data["reason"] == "NO_DECISION_RECORD"
    assert store.read() == state_before


# -- Backward compatibility --

def test_no_entry_condition_skips_guard():
    """
    Requests without entry_condition must work exactly as before.
    No regression. Gate still evaluates normally.
    """
    state_before = store.read()

    # No entry_condition, no decision -> gate blocks
    response = client.post("/execute", json={
        "action": "delete_env",
        "object_id": "env_1",
        "environment": "prod",
        "actor_id": "user_123",
    })

    data = response.json()

    assert data["allowed"] is False
    assert data["reason"] == "NO_DECISION_RECORD"
    assert store.read() == state_before
