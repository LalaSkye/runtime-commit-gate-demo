"""
TEST: Wrong scope -> no state mutation.

A decision scoped to object A cannot authorise mutation of object B.
A decision scoped to environment X cannot authorise mutation in environment Y.
A decision scoped to action P cannot authorise action Q.
"""

from datetime import datetime, timezone, timedelta
from src.decision_record import make_record


def test_wrong_object_blocks(gate, store):
    """Decision for env_1, request targets env_2. Must be blocked."""
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
    """Decision for prod, request targets staging. Must be blocked."""
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
    """Decision for delete_env, request attempts change_limit. Must be blocked."""
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
