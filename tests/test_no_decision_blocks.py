"""
No decision record -> no state mutation.
"""


def test_no_decision_blocks_delete_env(gate, store):
    """No decision + delete_env -> BLOCKED."""
    state_before = store.snapshot()

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=None,
    )

    assert result.allowed is False
    assert result.reason == "NO_DECISION_RECORD"
    assert store.read() == state_before


def test_no_decision_blocks_approve_invoice(gate, store):
    """No decision + approve_invoice -> BLOCKED."""
    state_before = store.snapshot()

    result = gate.execute(
        action="approve_invoice",
        object_id="inv_001",
        environment="prod",
        actor_id="user_123",
        decision=None,
    )

    assert result.allowed is False
    assert result.reason == "NO_DECISION_RECORD"
    assert store.read() == state_before


def test_no_decision_blocks_change_limit(gate, store):
    """No decision + change_limit -> BLOCKED."""
    state_before = store.snapshot()

    result = gate.execute(
        action="change_limit",
        object_id="acct_778",
        environment="prod",
        actor_id="user_123",
        decision=None,
    )

    assert result.allowed is False
    assert result.reason == "NO_DECISION_RECORD"
    assert store.read() == state_before
