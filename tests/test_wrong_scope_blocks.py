"""
Wrong scope -> no state mutation.
Object, environment, and action must match.
"""

from datetime import datetime, timezone, timedelta
from src.decision_record import make_record


def test_wrong_object_blocks(gate, store):
    """Decision(env_1) + request(env_2) -> BLOCKED."""
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="delete_env",
        object_id="env_2",  # MISMATCH
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )

    assert result.allowed is False
    assert "OBJECT_MISMATCH" in result.reason
    assert store.read() == state_before


def test_wrong_environment_blocks(gate, store):
    """Decision(prod) + request(staging) -> BLOCKED."""
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="staging",  # MISMATCH
        actor_id="user_123",
        decision=decision,
    )

    assert result.allowed is False
    assert "ENVIRONMENT_MISMATCH" in result.reason
    assert store.read() == state_before


def test_wrong_action_blocks(gate, store):
    """Decision(delete_env) + request(change_limit) -> BLOCKED."""
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="change_limit",  # MISMATCH
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )

    assert result.allowed is False
    assert "ACTION_MISMATCH" in result.reason
    assert store.read() == state_before
