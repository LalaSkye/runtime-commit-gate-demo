# Decision Record Specification

**Version:** 0.1.0
**Status:** ACTIVE

## Purpose

A decision record is a signed, scoped, time-bound authorisation for a single governed action. Without one, no state mutation occurs.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `decision_id` | string | yes | Unique identifier (e.g. `dr_a1b2c3d4e5f6`) |
| `actor_id` | string | yes | Who is authorised to act |
| `action` | string | yes | What action is authorised (closed set) |
| `object_id` | string | yes | What object the action targets |
| `environment` | string | yes | Where the action may execute |
| `verdict` | string | yes | `ALLOW` or `DENY` (only `ALLOW` authorises) |
| `policy_version` | string | yes | Which policy version issued this record |
| `issued_at` | ISO 8601 | yes | When the record was created |
| `expires_at` | ISO 8601 | yes | When the record becomes invalid |
| `reason_codes` | array | yes | Why this verdict was reached |
| `nonce` | string | yes | Single-use token for replay protection |
| `signature` | string | yes | HMAC-SHA256 of canonical payload |

## Governed Actions (Closed Set)

- `approve_invoice`
- `change_limit`
- `delete_env`

No other actions are accepted by the gate.

## Canonical Payload

The signature covers all fields except `signature` itself, serialised as deterministic JSON (sorted keys, no whitespace):

```
HMAC-SHA256(secret, canonical_json(record_without_signature))
```

## Constraints

1. `verdict` must be `ALLOW` for the gate to proceed
2. `expires_at` must be in the future at time of evaluation
3. `nonce` must not have been previously consumed
4. `action`, `object_id`, and `environment` must exactly match the request
5. `policy_version` must be in the accepted set
6. `signature` must be valid against the canonical payload

Failure on any constraint blocks the action. First failure stops evaluation.

## Example

```json
{
  "decision_id": "dr_001",
  "actor_id": "user_123",
  "action": "change_limit",
  "object_id": "acct_778",
  "environment": "prod",
  "verdict": "ALLOW",
  "policy_version": "2026-03-28.1",
  "issued_at": "2026-03-28T18:00:00Z",
  "expires_at": "2026-03-28T18:05:00Z",
  "reason_codes": ["AUTH_VALID", "SCOPE_VALID"],
  "nonce": "abc123xyz",
  "signature": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```
