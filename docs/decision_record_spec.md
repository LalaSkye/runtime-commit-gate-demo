# Decision Record Spec

Version: 0.1.0

## Structure

| Field | Type | Required | Purpose |
|---|---|---|---|
| `decision_id` | string | yes | Unique ID |
| `actor_id` | string | yes | Who acts |
| `action` | string | yes | What action (closed set) |
| `object_id` | string | yes | Target object |
| `environment` | string | yes | Where |
| `verdict` | string | yes | ALLOW or DENY |
| `policy_version` | string | yes | Policy version |
| `issued_at` | ISO 8601 | yes | When issued |
| `expires_at` | ISO 8601 | yes | When invalid |
| `reason_codes` | array | yes | Why |
| `nonce` | string | yes | Single-use token |
| `signature` | string | yes | HMAC-SHA256 |

## Governed actions (closed set)

- `approve_invoice`
- `change_limit`
- `delete_env`

## Signature

```
HMAC-SHA256(secret, canonical_json(all_fields_except_signature))
```

Canonical JSON: sorted keys, no whitespace.

## Checks (all must pass)

1. verdict == ALLOW
2. expires_at > now
3. nonce not previously consumed
4. action, object_id, environment match the request
5. policy_version in accepted set
6. signature matches canonical payload

Any failure -> BLOCKED.

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
  "signature": "e3b0c44..."
}
```
