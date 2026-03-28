"""
Expired decision record -> no state mutation.
"""


def test_expired_decision_blocks(gate, store, expired_decision):
    """Expired decision + delete_env -> BLOCKED."""
    state_before = store.snapshot()

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=expired_decision,
    )

    assert result.allowed is False
    assert result.reason == "DECISION_EXPIRED"
    assert store.read() == state_before
