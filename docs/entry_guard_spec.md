# Entry Condition Guard Spec

Version: 0.1.0

## Invariant

No valid condition structure -> no evaluation -> no execution.

## Input

Action packet with required keys:

| Key | Type | Required | Purpose |
|---|---|---|---|
| `action` | string | yes | What action |
| `condition` | string | yes | What must be true |
| `test` | string or dict | yes | How to evaluate the condition |
| `binding` | dict | yes | What happens on true/false/unevaluable |

## Checks (evaluation order)

First failure stops. Verdict: HOLD.

| # | Check | Rule | Failure |
|---|---|---|---|
| C1 | CONDITION_PRESENT | `condition` exists and is non-empty | HOLD |
| C2 | CONDITION_TESTABLE | `test` is machine-checkable, returns boolean | HOLD |
| C3 | CONDITION_BOUND | `binding.on_false` == "hold" | HOLD |
| C4 | EVALUATION_CONTEXT_BOUND | all variables in `test.expr` declared in `test.context` | HOLD |

## Test forms

### Allowed
- Structured: `{"expr": "...", "returns": "boolean", "context": [...]}`
- Predicate reference: `"window_active"` (named, not prose)
- Expression string with operators

### Disallowed
- Free prose: "looks good", "seems safe"
- Ambiguous natural language
- Undeclared output type

## Binding requirements

```json
{
  "on_true": "pass_to_next_stage",
  "on_false": "hold",
  "on_unevaluable": "hold"
}
```

`on_false` must be `"hold"`. No other value accepted.

## Position in pipeline

```
action packet -> entry guard -> commit gate -> mutation -> state store
```

Entry guard runs before commit gate. If it fails, the packet does not reach the gate.

## Terminal behaviour

Any failed check:
- VERDICT = HOLD
- No propagation
- No execution
- No fallback
