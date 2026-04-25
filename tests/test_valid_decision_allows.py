"""
Valid decision record -> action executes.
All checks pass. State mutates. Audit records it.
"""

from datetime import datetime, timezone, timedelta
from src.decision_record import make_record, make_record_with_params_hash


def test_valid_decision_allows_delete_env(gate, store, audit_log, valid_decision):
    """Valid decision + delete_env/env_1/prod -> ALLOWED."""
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
    """Valid decision + approve_invoice/inv_001/prod -> ALLOWED."""
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
    """Valid decision + change_limit/acct_778/prod -> ALLOWED.

    V4 adjustment (recorded in RESULTS_v4.md, FINDING_D-PRE):
    change_limit now requires V4 parameter binding because it passes
    params through to state_store. Previously this test used the legacy
    `make_record()` + caller-supplied params path, which is exactly the
    V4 gap. Adjusted to use `make_record_with_params_hash()` (Mode A).
    The previous version is preserved in the git history for audit.
    """
    now = datetime.now(timezone.utc)
    params = {"new_limit": 50000.00}
    decision = make_record_with_params_hash(
        actor_id="user_789",
        action="change_limit",
        object_id="acct_778",
        environment="prod",
        params=params,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    result = gate.execute(
        action="change_limit",
        object_id="acct_778",
        environment="prod",
        actor_id="user_789",
        decision=decision,
        params=params,
    )

    assert result.allowed is True
    state_after = store.read()
    assert state_after["limits"]["acct_778"]["daily_limit"] == 50000.00
    assert state_after["limits"]["acct_778"]["last_changed_by"] == "user_789"
