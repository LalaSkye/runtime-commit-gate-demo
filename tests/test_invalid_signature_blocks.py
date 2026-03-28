"""
TEST: Invalid signature -> no state mutation.

A tampered or forged decision record is worthless.
"""

from datetime import datetime, timezone, timedelta
from src.decision_record import DecisionRecord


def test_invalid_signature_blocks(gate, store):
    """Decision with bad signature. Must be blocked."""
    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = DecisionRecord(
        decision_id="dr_forged",
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        verdict="ALLOW",
        policy_version="2026-03-28.1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        reason_codes=("AUTH_VALID", "SCOPE_VALID"),
        nonce="forged_nonce_001",
        signature="definitely_not_a_valid_signature",
    )

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )

    assert result.allowed is False
    assert result.reason == "INVALID_SIGNATURE"
    assert store.read() == state_before


def test_deny_verdict_blocks(gate, store):
    """Decision with verdict=DENY. Must be blocked even if signed."""
    from src.decision_record import make_record

    state_before = store.snapshot()
    now = datetime.now(timezone.utc)

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        verdict="DENY",
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

    assert result.allowed is False
    assert "VERDICT_NOT_ALLOW" in result.reason
    assert store.read() == state_before
