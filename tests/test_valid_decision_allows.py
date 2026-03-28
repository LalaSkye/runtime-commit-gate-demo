"""
TEST: Valid decision record -> action executes.

The happy path. All checks pass. State mutates. Audit records it.
"""

from datetime import datetime, timezone, timedelta
from src.decision_record import make_record


def test_valid_decision_allows_delete_env(gate, store, audit_log, valid_decision):
    """Valid decision for delete_env/env_1/prod. Must execute."""
    state_before = store.snapshot()
    assert state_before["environments"]["env_1"]["deleted"] is False

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=valid_decision,
    )

    assert result.allowed is True
    assert result.reason == "ALL_CHECKS_PASSED"

    state_after = store.read()
    assert state_after["environments"]["env_1"]["deleted"] is True
    assert state_after["environments"]["env_1"]["deleted_by"] == "user_123"

    # Audit log should record the allowed event
    entries = audit_log.read_all()
    assert len(entries) >= 1
    last = entries[-1]
    assert last["outcome"] == "ALLOWED"
    assert last["decision_id"] == valid_decision.decision_id


def test_valid_decision_allows_approve_invoice(gate, store, audit_log):
    """Valid decision for approve_invoice/inv_001/prod. Must execute."""
    now = datetime.now(timezone.utc)
    decision = make_record(
        actor_id="user_456",
        action="approve_invoice",
        object_id="inv_001",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="approve_invoice",
        object_id="inv_001",
        environment="prod",
        actor_id="user_456",
        decision=decision,
    )

    assert result.allowed is True
    state_after = store.read()
    assert state_after["invoices"]["inv_001"]["status"] == "approved"
    assert state_after["invoices"]["inv_001"]["approved_by"] == "user_456"


def test_valid_decision_allows_change_limit(gate, store, audit_log):
    """Valid decision for change_limit/acct_778/prod. Must execute."""
    now = datetime.now(timezone.utc)
    decision = make_record(
        actor_id="user_789",
        action="change_limit",
        object_id="acct_778",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="change_limit",
        object_id="acct_778",
        environment="prod",
        actor_id="user_789",
        decision=decision,
        params={"new_limit": 50000.00},
    )

    assert result.allowed is True
    state_after = store.read()
    assert state_after["limits"]["acct_778"]["daily_limit"] == 50000.00
    assert state_after["limits"]["acct_778"]["last_changed_by"] == "user_789"
