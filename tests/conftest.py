"""
Shared fixtures. Fresh gate, store, audit per test.
"""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from src.state_store import StateStore
from src.audit import AuditLog
from src.gate import CommitGate
from src.decision_record import make_record, DecisionRecord, sign_record


@pytest.fixture
def tmp_paths(tmp_path):
    """Provide isolated paths for state and audit."""
    return {
        "state": tmp_path / "state.json",
        "audit": tmp_path / "audit.jsonl",
        "nonces": tmp_path / "nonces.jsonl",
    }


@pytest.fixture
def store(tmp_paths):
    return StateStore(path=tmp_paths["state"])


@pytest.fixture
def audit_log(tmp_paths):
    return AuditLog(path=tmp_paths["audit"])


@pytest.fixture
def gate(store, audit_log, tmp_paths):
    return CommitGate(store, audit_log, nonce_ledger_path=tmp_paths["nonces"])


@pytest.fixture
def valid_decision():
    """A valid, signed, fresh decision record for delete_env/env_1/prod."""
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


@pytest.fixture
def expired_decision():
    """A signed but expired decision record."""
    past = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        verdict="ALLOW",
        issued_at=past.isoformat(),
        expires_at=(past + timedelta(minutes=5)).isoformat(),
    )
