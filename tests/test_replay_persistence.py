"""
Replay persistence tests.
Nonce ledger survives process restart (re-instantiation).
Bulkhead invariant #5: Replay never executes.
"""

from datetime import datetime, timezone, timedelta
from src.state_store import StateStore
from src.audit import AuditLog
from src.gate import CommitGate
from src.decision_record import make_record


def _fresh_decision():
    """Create a valid signed decision record."""
    now = datetime.now(timezone.utc)
    return make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        verdict="ALLOW",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )


def test_replay_survives_restart(tmp_path):
    """Consume a nonce, re-instantiate the gate, nonce must still be seen."""
    nonce_path = tmp_path / "nonces.jsonl"
    state_path = tmp_path / "state.json"
    audit_path = tmp_path / "audit.jsonl"

    store = StateStore(path=state_path)
    audit = AuditLog(path=audit_path)
    decision = _fresh_decision()

    # Gate 1: consume the nonce
    gate1 = CommitGate(store, audit, nonce_ledger_path=nonce_path)
    r1 = gate1.execute(
        action="delete_env", object_id="env_1",
        environment="prod", actor_id="user_123",
        decision=decision,
    )
    assert r1.allowed is True

    # Gate 2: new instance, same ledger file — simulates restart
    store2 = StateStore(path=state_path)
    audit2 = AuditLog(path=audit_path)
    gate2 = CommitGate(store2, audit2, nonce_ledger_path=nonce_path)

    r2 = gate2.execute(
        action="delete_env", object_id="env_1",
        environment="prod", actor_id="user_123",
        decision=decision,
    )
    assert r2.allowed is False
    assert r2.reason == "NONCE_REPLAYED"


def test_duplicate_consume_no_double_append(tmp_path):
    """Calling consume() twice must not duplicate the nonce record."""
    from src.nonce_ledger import NonceLedger

    nonce_path = tmp_path / "nonces.jsonl"
    ledger = NonceLedger(nonce_path)

    ledger.consume("abc-123")
    ledger.consume("abc-123")

    lines = [l for l in nonce_path.read_text().strip().split("\n") if l.strip()]
    assert len(lines) == 1


def test_malformed_jsonl_line_skipped(tmp_path):
    """A corrupt line in the ledger must not crash seen()."""
    from src.nonce_ledger import NonceLedger

    nonce_path = tmp_path / "nonces.jsonl"
    # Write a good record then a corrupt line then another good record
    nonce_path.write_text(
        '{"nonce": "aaa"}\n'
        'NOT-JSON\n'
        '{"nonce": "bbb"}\n'
    )

    ledger = NonceLedger(nonce_path)
    assert ledger.seen("aaa") is True
    assert ledger.seen("bbb") is True
    assert ledger.seen("ccc") is False


def test_nonce_not_consumed_on_mutation_failure(tmp_path):
    """If apply_mutation raises, nonce must NOT be persisted."""
    from unittest.mock import MagicMock

    nonce_path = tmp_path / "nonces.jsonl"
    audit_path = tmp_path / "audit.jsonl"

    store = MagicMock()
    store.apply_mutation.side_effect = RuntimeError("boom")
    audit = AuditLog(path=audit_path)

    decision = _fresh_decision()
    gate = CommitGate(store, audit, nonce_ledger_path=nonce_path)

    r = gate.execute(
        action="delete_env", object_id="env_1",
        environment="prod", actor_id="user_123",
        decision=decision,
    )
    assert r.allowed is False
    assert "MUTATION_ERROR" in r.reason

    # Nonce must not be in the ledger
    from src.nonce_ledger import NonceLedger
    ledger = NonceLedger(nonce_path)
    assert ledger.seen(decision.nonce) is False


def test_reset_clears_ledger(tmp_path):
    """reset_nonces() must delete the ledger file."""
    from src.nonce_ledger import NonceLedger

    nonce_path = tmp_path / "nonces.jsonl"
    state_path = tmp_path / "state.json"
    audit_path = tmp_path / "audit.jsonl"

    store = StateStore(path=state_path)
    audit = AuditLog(path=audit_path)
    decision = _fresh_decision()

    gate = CommitGate(store, audit, nonce_ledger_path=nonce_path)
    r = gate.execute(
        action="delete_env", object_id="env_1",
        environment="prod", actor_id="user_123",
        decision=decision,
    )
    assert r.allowed is True

    # Nonce is seen
    ledger = NonceLedger(nonce_path)
    assert ledger.seen(decision.nonce) is True

    # Reset
    gate.reset_nonces()

    # Nonce is gone
    ledger2 = NonceLedger(nonce_path)
    assert ledger2.seen(decision.nonce) is False
