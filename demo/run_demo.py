#!/usr/bin/env python3
"""
Runtime Commit Gate — 5-Step Proof Sequence

Run this to see the gate in action. No server needed.
Each step prints what happened and why.

    python demo/run_demo.py
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.state_store import StateStore
from src.audit import AuditLog
from src.gate import CommitGate
from src.decision_record import make_record, DecisionRecord


def banner(step: int, title: str):
    print(f"\n{'='*60}")
    print(f"  STEP {step}: {title}")
    print(f"{'='*60}\n")


def show_result(result, store):
    status = "ALLOWED" if result.allowed else "BLOCKED"
    print(f"  Gate result:  {status}")
    print(f"  Reason:       {result.reason}")
    print(f"  Decision ID:  {result.decision_id or 'none'}")
    env_state = store.read()["environments"]["env_1"]
    print(f"  env_1 state:  deleted={env_state['deleted']}, deleted_by={env_state['deleted_by']}")


def main():
    # Use temp paths so the demo is self-contained
    demo_dir = Path(__file__).parent / "demo_data"
    demo_dir.mkdir(exist_ok=True)
    state_path = demo_dir / "state.json"
    audit_path = demo_dir / "audit.jsonl"

    # Clean start
    if state_path.exists():
        state_path.unlink()
    if audit_path.exists():
        audit_path.unlink()

    store = StateStore(path=state_path)
    audit = AuditLog(path=audit_path)
    gate = CommitGate(store, audit)

    now = datetime.now(timezone.utc)
    past = datetime(2025, 1, 1, tzinfo=timezone.utc)

    print("\n" + "=" * 60)
    print("  RUNTIME COMMIT GATE — PROOF SEQUENCE")
    print("  Invariant: No valid decision -> no state mutation")
    print("=" * 60)

    # ── STEP 1: No decision -> BLOCKED ──
    banner(1, "delete_env with NO decision record")
    print("  Attempting to delete env_1 without any decision...")

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=None,
    )
    show_result(result, store)
    assert not result.allowed, "INVARIANT VIOLATION: mutation without decision!"

    # ── STEP 2: Valid decision -> ALLOWED ──
    banner(2, "delete_env with VALID decision record")

    decision = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    print(f"  Decision ID:  {decision.decision_id}")
    print(f"  Nonce:        {decision.nonce}")
    print(f"  Signed:       {decision.signature[:24]}...")
    print()

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )
    show_result(result, store)
    assert result.allowed, "Valid decision should have been allowed!"

    # Reset state for remaining tests (keep nonces to prove replay)
    store.reset()

    # ── STEP 3: Replay same decision -> BLOCKED ──
    banner(3, "REPLAY same decision (same nonce)")
    print("  Re-using the exact decision from Step 2...")

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=decision,
    )
    show_result(result, store)
    assert not result.allowed, "INVARIANT VIOLATION: replay should be blocked!"

    # ── STEP 4: Decision for env_1, request targets env_2 -> BLOCKED ──
    banner(4, "Decision scoped to env_1, request targets env_2")

    decision_env1 = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )

    print(f"  Decision scoped to: env_1")
    print(f"  Request targets:    env_2")
    print()

    result = gate.execute(
        action="delete_env",
        object_id="env_2",  # MISMATCH
        environment="prod",
        actor_id="user_123",
        decision=decision_env1,
    )
    show_result(result, store)
    assert not result.allowed, "INVARIANT VIOLATION: scope mismatch should block!"

    # ── STEP 5: Expired decision -> BLOCKED ──
    banner(5, "EXPIRED decision record")

    expired = make_record(
        actor_id="user_123",
        action="delete_env",
        object_id="env_1",
        environment="prod",
        issued_at=past.isoformat(),
        expires_at=(past + timedelta(minutes=5)).isoformat(),
    )

    print(f"  Issued at:  {expired.issued_at}")
    print(f"  Expired at: {expired.expires_at}")
    print()

    result = gate.execute(
        action="delete_env",
        object_id="env_1",
        environment="prod",
        actor_id="user_123",
        decision=expired,
    )
    show_result(result, store)
    assert not result.allowed, "INVARIANT VIOLATION: expired decision should block!"

    # ── FINAL: Show audit log ──
    print(f"\n{'='*60}")
    print("  AUDIT LOG (all 5 attempts)")
    print(f"{'='*60}\n")

    entries = audit.read_all()
    for i, entry in enumerate(entries, 1):
        print(f"  [{i}] {entry['outcome']:8s} | {entry['reason']:40s} | {entry['action']}/{entry['object_id']}")

    print(f"\n{'='*60}")
    print("  PROOF COMPLETE")
    print()
    print("  5 attempts. 1 allowed. 4 blocked.")
    print("  No valid decision -> no state mutation.")
    print(f"{'='*60}\n")

    # Cleanup
    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
