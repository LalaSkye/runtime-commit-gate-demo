"""
Adversarial tests. One per layer.

These attempt to bypass each control surface.
All must fail. If any succeeds, the boundary is broken.
"""

from datetime import datetime, timezone, timedelta
from src.entry_guard import validate_entry
from src.gate import CommitGate
from src.state_store import StateStore
from src.audit import AuditLog
from src.decision_record import make_record, DecisionRecord
from pathlib import Path
import pytest


# ── Fixtures ──

@pytest.fixture
def tmp_env(tmp_path):
    store = StateStore(path=tmp_path / "state.json")
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    gate = CommitGate(store, audit)
    return store, audit, gate


# ── LAYER 1: Entry guard adversarial ──

def test_adv_entry_inject_extra_fields():
    """Extra fields in packet must not bypass checks."""
    result = validate_entry({
        "action": "deploy",
        "condition": "",
        "test": "window_active",
        "binding": {"on_false": "hold"},
        "bypass": True,
        "admin_override": True,
    })
    assert not result.passed
    assert result.failed_check == "C1_CONDITION_PRESENT"


def test_adv_entry_null_condition():
    """None as condition must not pass."""
    result = validate_entry({
        "action": "deploy",
        "condition": None,
        "test": "x",
        "binding": {"on_false": "hold"},
    })
    assert not result.passed


def test_adv_entry_binding_bypass_attempt():
    """on_false set to 'allow' instead of 'hold' -> must fail."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window check",
        "test": "window_active",
        "binding": {"on_false": "allow"},
    })
    assert not result.passed
    assert result.failed_check == "C3_CONDITION_BOUND"


# ── LAYER 2: Commit gate adversarial ──

def test_adv_gate_no_decision_no_mutation(tmp_env):
    """Core invariant: no ALLOW -> no mutation."""
    store, audit, gate = tmp_env
    state_before = store.snapshot()

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="attacker",
        decision=None,
    )

    assert not result.allowed
    assert store.read() == state_before


def test_adv_gate_forged_signature_no_mutation(tmp_env):
    """Forged signature must not reach mutation."""
    store, audit, gate = tmp_env
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    forged = DecisionRecord(
        decision_id="dr_forged",
        actor_id="attacker",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        verdict="ALLOW",
        policy_version="2026-03-28.1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        reason_codes=("AUTH_VALID",),
        nonce="forged_nonce",
        signature="0000000000000000000000000000000000000000000000000000000000000000",
    )

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="attacker",
        decision=forged,
    )

    assert not result.allowed
    assert result.reason == "INVALID_SIGNATURE"
    assert store.read() == state_before


def test_adv_gate_scope_swap_no_mutation(tmp_env):
    """Decision for action A, attempt action B -> no mutation."""
    store, audit, gate = tmp_env
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="approve_invoice",
        object_id="inv_001",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )

    assert not result.allowed
    assert "ACTION_MISMATCH" in result.reason
    assert store.read() == state_before


def test_adv_gate_triple_replay_no_mutation(tmp_env):
    """Same decision used 3 times. Only first succeeds."""
    store, audit, gate = tmp_env
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    r1 = gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="user_123", decision=decision)
    assert r1.allowed

    store.reset()

    r2 = gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="user_123", decision=decision)
    assert not r2.allowed
    assert r2.reason == "NONCE_REPLAYED"

    r3 = gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="user_123", decision=decision)
    assert not r3.allowed
    assert r3.reason == "NONCE_REPLAYED"


# ── LAYER 3: State store direct access attempt ──

def test_adv_state_direct_mutation_is_possible_but_ungoverned(tmp_env):
    """
    state_store.apply_mutation() CAN be called directly.
    This test documents that the architectural constraint is:
    server.py and gate.py never do this without checks.

    In a production system, this would be enforced by encapsulation.
    Here it is enforced by architecture + audit.
    """
    store, audit, gate = tmp_env
    state_before = store.snapshot()
    assert state_before["environments"]["env_1"]["deleted"] is False

    # Direct mutation bypasses the gate — this is the risk
    store.apply_mutation("delete_env", "env_1", "bypasser")

    state_after = store.read()
    assert state_after["environments"]["env_1"]["deleted"] is True

    # But audit has NO record of this — that's the detection surface
    entries = audit.read_all()
    assert len(entries) == 0  # No gate evaluation was logged


# ── INVARIANT: No ALLOW -> no mutation ──

def test_invariant_no_allow_no_mutation(tmp_env):
    """
    The core invariant across all paths.
    Every non-ALLOW path must leave state unchanged.
    """
    store, audit, gate = tmp_env
    now = datetime.now(timezone.utc)
    past = datetime(2025, 1, 1, tzinfo=timezone.utc)

    state_before = store.snapshot()

    # Path 1: no decision
    gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="u", decision=None)

    # Path 2: DENY verdict
    deny = make_record(actor_id="u", action="delete_env", object_id="env_1", environment="prod", verdict="DENY",
                       issued_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="u", decision=deny)

    # Path 3: expired
    expired = make_record(actor_id="u", action="delete_env", object_id="env_1", environment="prod",
                          issued_at=past.isoformat(), expires_at=(past + timedelta(minutes=5)).isoformat())
    gate.execute(action="delete_env", object_id="env_1", environment="prod", actor_id="u", decision=expired)

    # Path 4: wrong object
    wrong_obj = make_record(actor_id="u", action="delete_env", object_id="env_1", environment="prod",
                            issued_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    gate.execute(action="delete_env", object_id="env_2", environment="prod", actor_id="u", decision=wrong_obj)

    # Path 5: wrong environment
    wrong_env = make_record(actor_id="u", action="delete_env", object_id="env_1", environment="prod",
                            issued_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    gate.execute(action="delete_env", object_id="env_1", environment="staging", actor_id="u", decision=wrong_env)

    # After all 5 non-ALLOW paths: state must be unchanged
    assert store.read() == state_before
