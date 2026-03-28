# runtime-commit-gate-demo

Invariant:
No valid decision record -> no state mutation.

## Run

```bash
pip install -r requirements.txt
python demo/run_demo.py
```

## Tests

```bash
python -m pytest tests/ -v
```

13 tests. All passing.

## What it does

Three governed actions. One gate. No bypass.

| Action | Object | Mutation |
|---|---|---|
| `approve_invoice` | Invoice ID | status -> approved |
| `change_limit` | Account ID | daily_limit updated |
| `delete_env` | Environment ID | deleted -> true |

## Proof sequence

| Step | Input | Result | Reason |
|---|---|---|---|
| 1 | No decision | BLOCKED | `NO_DECISION_RECORD` |
| 2 | Valid decision | ALLOWED | `ALL_CHECKS_PASSED` |
| 3 | Replay same decision | BLOCKED | `NONCE_REPLAYED` |
| 4 | Decision(env_1), request(env_2) | BLOCKED | `OBJECT_MISMATCH` |
| 5 | Expired decision | BLOCKED | `DECISION_EXPIRED` |

## Gate checks

Ten checks. Evaluation order. First failure stops.

| # | Check | Failure code |
|---|---|---|
| 1 | Decision record exists | `NO_DECISION_RECORD` |
| 2 | verdict == ALLOW | `VERDICT_NOT_ALLOW` |
| 3 | HMAC-SHA256 signature valid | `INVALID_SIGNATURE` |
| 4 | expires_at > now | `DECISION_EXPIRED` |
| 5 | Nonce unused | `NONCE_REPLAYED` |
| 6 | action matches request | `ACTION_MISMATCH` |
| 7 | object_id matches request | `OBJECT_MISMATCH` |
| 8 | environment matches request | `ENVIRONMENT_MISMATCH` |
| 9 | policy_version in accepted set | `POLICY_VERSION_REJECTED` |
| 10 | action in governed set | `UNKNOWN_ACTION` |

## Flow

```
request -> gate -> [10 checks] -> mutation -> state store
                                -> audit log (append-only)
```

If any check fails: no mutation, reason logged.

## Files

```
src/
  decision_record.py   decision contract + HMAC signing
  gate.py              10-check gate, fail-closed
  state_store.py       JSON-backed, 3 objects
  audit.py             append-only JSONL
  server.py            FastAPI (optional)

tests/
  test_no_decision_blocks.py
  test_expired_decision_blocks.py
  test_wrong_scope_blocks.py
  test_replay_blocks.py
  test_valid_decision_allows.py
  test_invalid_signature_blocks.py

demo/
  run_demo.py          5-step proof
```

## API (optional)

```bash
uvicorn src.server:app --reload
```

| Method | Endpoint | Returns |
|---|---|---|
| POST | `/decide` | signed decision record |
| POST | `/execute` | gate result (ALLOWED/BLOCKED + reason) |
| GET | `/state` | current state |
| GET | `/audit` | all gate attempts |

## Docs

- [Decision record spec](docs/decision_record_spec.md)
- [Gate rules](docs/commit_gate_rules.md)

## Licence

MIT. Copyright (c) 2026 Ricky Dean Jones / Os-Trilogy LMT.

See [PROVENANCE.md](PROVENANCE.md).
