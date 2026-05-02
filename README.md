# runtime-commit-gate-demo
New to this work? Start here:
[https://github.com/LalaSkye/start-here](https://github.com/LalaSkye/start-here)

**Invariant:**
No valid decision record -> no state mutation.

## What this repo shows

A minimal execution boundary for governed actions.

- Entry condition guard (condition structure validation)
- Deterministic commit gate (10 checks, first-fail)
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

## Pipeline

```
request -> entry guard -> commit gate -> mutation -> state store
```

Entry guard validates condition structure. Commit gate validates decision record.
Both must pass. Neither trusts the other.

## Entry guard checks

If `entry_condition` is present on the request:

1. condition present and non-empty
2. test is machine-checkable (not prose)
3. binding links condition to execution (`on_false` == `hold`)
4. evaluation context variables declared

First failure -> HOLD. Request never reaches the gate.

See [entry guard spec](docs/entry_guard_spec.md).

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
src/entry_guard.py       condition structure validation (Layer 1)
src/gate.py              commit gate — enforcement boundary (Layer 2)
src/decision_record.py   input contract + signing
src/server.py            API — wires entry guard before gate
src/state_store.py       mutation target
src/audit.py             append-only log
tests/                   conformance + integration tests
demo/run_demo.py         proof sequence
```

## Tests

```bash
python -m pytest tests/ -v
```

42 tests covering: entry guard wiring (6 integration), entry guard unit (13), commit gate adversarial (9), replay, scope mismatch, expiry, signature, valid paths (3 actions). 1 xfail (deferred double-approval).

## Modify the system

This repository is intentionally small enough to change.

Try one modification:

1. Open `src/gate.py`
2. Remove the expiry check (CHECK 4)
3. Run:

```bash
python demo/run_demo.py
python -m pytest tests/ -v
```

Expected: expired decisions will no longer be blocked. The invariant is violated.

Restore the check to re-enforce the invariant.

### Extension path

Fork the repository and modify the decision checks.

Suggested extensions:

- Add a new governed action
- Require two approvals before ALLOW
- Add dependency checks between actions
- Add pre-state verification

Controlled challenges: [docs/challenges.md](docs/challenges.md)

Editable payloads: [examples/](examples/)

## Docs

- [Entry guard spec](docs/entry_guard_spec.md)
- [Decision record spec](docs/decision_record_spec.md)
- [Gate rules](docs/commit_gate_rules.md)
- [Challenges](docs/challenges.md)

## Provenance

See [PROVENANCE.md](PROVENANCE.md).

## Licence

MIT — see [LICENSE](LICENSE).

---

This repository demonstrates a deterministic control boundary using standard engineering techniques. No proprietary frameworks or external implementations are used.
