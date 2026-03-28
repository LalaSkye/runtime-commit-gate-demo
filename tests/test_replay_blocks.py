"""
Replayed decision -> no state mutation.
Nonce is single-use. Second use is BLOCKED.
"""


def test_replay_blocks(gate, store, valid_decision):
    """First use -> ALLOWED. Same nonce again -> BLOCKED."""

    # First use: should pass
    result1 = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=valid_decision,
    )
    assert result1.allowed is True

    # Reset state so we can see if replay mutates
    store.reset()
    state_before = store.snapshot()

    # Replay: same decision, same nonce. Must block.
    result2 = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=valid_decision,
    )

    assert result2.allowed is False
    assert result2.reason == "NONCE_REPLAYED"
    assert store.read() == state_before
