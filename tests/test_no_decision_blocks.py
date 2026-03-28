"""
TEST: No decision record -> no state mutation.

This is the core invariant. If this fails, nothing else matters.
"""


def test_no_decision_blocks_delete_env(gate, store):
    """Attempt delete_env with no decision. Must be blocked."""
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
    """Attempt approve_invoice with no decision. Must be blocked."""
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
    """Attempt change_limit with no decision. Must be blocked."""
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
