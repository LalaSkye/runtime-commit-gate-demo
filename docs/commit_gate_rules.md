# Commit Gate Rules

**Version:** 0.1.0
**Status:** ACTIVE

## Invariant

**No valid decision record -> no state mutation.**

## Architecture

```
client request
  -> decision validator
  -> commit gate
  -> mutation handler
  -> state store
  -> append-only audit log
```

The mutation handler cannot be called directly. If it can, the system is broken.

## Gate Checks (Evaluation Order)

The gate runs these checks in sequence. First failure stops evaluation and blocks the action.

| # | Check | Failure Reason |
|---|---|---|
| 1 | Decision record exists | `NO_DECISION_RECORD` |
| 2 | Verdict is `ALLOW` | `VERDICT_NOT_ALLOW:{verdict}` |
| 3 | Signature is valid (HMAC-SHA256) | `INVALID_SIGNATURE` |
| 4 | Record has not expired | `DECISION_EXPIRED` |
| 5 | Nonce has not been used before | `NONCE_REPLAYED` |
| 6 | Action matches request | `ACTION_MISMATCH` |
| 7 | Object matches request | `OBJECT_MISMATCH` |
| 8 | Environment matches request | `ENVIRONMENT_MISMATCH` |
| 9 | Policy version is accepted | `POLICY_VERSION_REJECTED` |
| 10 | Action is in governed set | `UNKNOWN_ACTION` |

## Fail-Closed Principle

If any check fails, the gate returns a `GateResult` with `allowed=False`. No state mutation occurs. The attempt is logged to the audit trail.

If all checks pass:
1. The nonce is consumed (burned)
2. The mutation handler executes the action
3. The result is logged to the audit trail

## Audit

Every attempt is logged, whether allowed or blocked:
- Timestamp
- Event type
- Action, object, environment
- Actor
- Decision ID (if present)
- Outcome (ALLOWED / BLOCKED)
- Reason

The audit log is append-only. No entries are deleted or modified.

## Bypass Resistance

The test suite includes explicit bypass attempts:
- No decision at all
- Expired decision
- Wrong object scope
- Wrong environment scope
- Wrong action scope
- Replayed nonce
- Forged signature
- DENY verdict

All must be blocked for the gate to be valid.
