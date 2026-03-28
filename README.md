# runtime-commit-gate-demo

This repo demonstrates a runtime commit boundary for governed actions.

**Invariant:**
No valid decision record -> no state mutation.

The system includes:
- A decision record contract (signed, scoped, time-bound)
- A commit gate (the only path to mutation)
- Append-only audit log
- Replay protection
- Conformance tests that try to cheat the gate

## Quick Start

```bash
git clone https://github.com/LalaSkye/runtime-commit-gate-demo.git
cd runtime-commit-gate-demo
pip install -r requirements.txt
python demo/run_demo.py
```

## What It Proves

Five attempts. One allowed. Four blocked.

| Step | Attempt | Result | Reason |
|---|---|---|---|
| 1 | `delete_env` with no decision | BLOCKED | `NO_DECISION_RECORD` |
| 2 | `delete_env` with valid decision | ALLOWED | `ALL_CHECKS_PASSED` |
| 3 | Replay same decision | BLOCKED | `NONCE_REPLAYED` |
| 4 | Decision for `env_1`, target `env_2` | BLOCKED | `OBJECT_MISMATCH` |
| 5 | Expired decision | BLOCKED | `DECISION_EXPIRED` |

## Run Tests

```bash
python -m pytest tests/ -v
```

## Architecture

```
client request
  -> decision validator
  -> commit gate
  -> mutation handler
  -> state store
  -> append-only audit log
```

The mutation handler cannot be called directly. Every mutation passes through the gate.

## Governed Actions

Three actions. Closed set. Nothing else is accepted.

| Action | Object | Effect |
|---|---|---|
| `approve_invoice` | Invoice ID | Sets status to approved |
| `change_limit` | Account ID | Updates daily limit |
| `delete_env` | Environment ID | Marks environment as deleted |

## Gate Checks

Ten checks, evaluated in order. First failure blocks.

1. Decision record exists
2. Verdict is ALLOW
3. Signature valid (HMAC-SHA256)
4. Not expired
5. Nonce not replayed
6. Action matches request
7. Object matches request
8. Environment matches request
9. Policy version accepted
10. Action is governed

## Files

```
src/
  decision_record.py   — the licence contract
  gate.py              — the enforcement boundary
  state_store.py       — the thing that changes (or doesn't)
  audit.py             — append-only proof
  server.py            — FastAPI endpoints

tests/
  test_no_decision_blocks.py
  test_expired_decision_blocks.py
  test_wrong_scope_blocks.py
  test_replay_blocks.py
  test_valid_decision_allows.py
  test_invalid_signature_blocks.py

docs/
  decision_record_spec.md
  commit_gate_rules.md

demo/
  run_demo.py          — 5-step proof sequence
  run_demo.sh          — full demo + test run
```

## API (Optional)

Start the server:

```bash
uvicorn src.server:app --reload
```

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/decide` | Issue a signed decision record |
| `POST` | `/execute` | Attempt a governed action |
| `GET` | `/state` | Read current state |
| `GET` | `/audit` | Read audit log |

## Docs

- [Decision Record Spec](docs/decision_record_spec.md)
- [Commit Gate Rules](docs/commit_gate_rules.md)

## Licence

MIT

## Author

Ricky Dean Jones
Os-Trilogy LMT
