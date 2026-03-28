# Commit Gate Rules

Version: 0.1.0

## Invariant

No valid decision record -> no state mutation.

## Flow

```
request -> gate -> [checks] -> mutation -> state store
                             -> audit log
```

Mutation handler is not callable directly.

## Checks (evaluation order)

First failure stops. No mutation occurs.

| # | Check | Failure code |
|---|---|---|
| 1 | Decision record exists | `NO_DECISION_RECORD` |
| 2 | verdict == ALLOW | `VERDICT_NOT_ALLOW` |
| 3 | Signature valid | `INVALID_SIGNATURE` |
| 4 | Not expired | `DECISION_EXPIRED` |
| 5 | Nonce unused | `NONCE_REPLAYED` |
| 6 | Action matches | `ACTION_MISMATCH` |
| 7 | Object matches | `OBJECT_MISMATCH` |
| 8 | Environment matches | `ENVIRONMENT_MISMATCH` |
| 9 | Policy version accepted | `POLICY_VERSION_REJECTED` |
| 10 | Action in governed set | `UNKNOWN_ACTION` |

## On pass

1. Nonce consumed
2. Mutation applied
3. Result logged (ALLOWED)

## On fail

1. No mutation
2. Reason logged (BLOCKED + failure code)

## Audit

Every attempt logged. ALLOWED and BLOCKED.
Append-only. No deletion. No editing.

Entry fields: timestamp, action, object_id, actor_id, decision_id, environment, outcome, reason.

## Bypass resistance (tested)

- No decision -> BLOCKED
- Expired decision -> BLOCKED
- Wrong object -> BLOCKED
- Wrong environment -> BLOCKED
- Wrong action -> BLOCKED
- Replayed nonce -> BLOCKED
- Bad signature -> BLOCKED
- verdict=DENY -> BLOCKED
