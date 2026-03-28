# runtime-commit-gate-demo

**Invariant:**
No valid decision record -> no state mutation.

## What this repo shows

A minimal execution boundary for governed actions.

- Deterministic checks
- Fail-closed behaviour
- Replay resistance
- Scope binding
- Append-only audit

No policy engine. No AI. No narrative.

## Run

```bash
python demo/run_demo.py
```

Expected:

1. No decision -> BLOCKED
2. Valid decision -> ALLOWED
3. Replay same decision -> BLOCKED
4. Wrong object -> BLOCKED
5. Expired decision -> BLOCKED

## Decision record (input contract)

```json
{
  "decision_id": "dr_001",
  "actor_id": "user_123",
  "action": "delete_env",
  "object_id": "env_1",
  "environment": "prod",
  "verdict": "ALLOW",
  "policy_version": "2026-03-28.1",
  "issued_at": "2026-03-28T18:00:00Z",
  "expires_at": "2026-03-28T18:05:00Z",
  "nonce": "abc123xyz",
  "signature": "HMAC-SHA256(...)"
}
```

## Gate checks (evaluation order)

1. record exists
2. verdict == ALLOW
3. signature valid
4. not expired
5. nonce unused
6. action matches
7. object matches
8. environment matches
9. policy version accepted
10. action is governed

First failure -> stop.

## API (optional)

```bash
uvicorn src.server:app --reload
```

| Method | Endpoint | Returns |
|---|---|---|
| POST | `/decide` | decision record |
| POST | `/execute` | gate result |
| GET | `/state` | current state |
| GET | `/audit` | append-only log |

## Files

```
src/decision_record.py   input contract + signing
src/gate.py              enforcement boundary
src/state_store.py       mutation target
src/audit.py             append-only log
tests/                   conformance tests
demo/run_demo.py         proof sequence
```

## Tests

```bash
python -m pytest tests/ -v
```

13 tests covering: missing record, expired record, replayed nonce, scope mismatch, invalid signature, DENY verdict, valid path (3 actions).

## Docs

- [Decision record spec](docs/decision_record_spec.md)
- [Gate rules](docs/commit_gate_rules.md)

## Provenance

See [PROVENANCE.md](PROVENANCE.md).

## Licence

MIT — see [LICENSE](LICENSE).

---

This repository demonstrates a deterministic control boundary using standard engineering techniques. No proprietary frameworks or external implementations are used.
