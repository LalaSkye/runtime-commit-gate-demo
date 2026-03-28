# Challenges

Controlled modifications to test the execution boundary.

## Challenge 1 — Remove nonce protection

Observe replay behaviour when nonce uniqueness is not enforced.

1. In `src/gate.py`, disable CHECK 5 (nonce replay)
2. Run `python demo/run_demo.py`
3. Observe: a previously used decision record executes again

Expected: Step 3 (replay) changes from BLOCKED to ALLOWED.

Restore the check afterwards.

## Challenge 2 — Add a new action

Add `transfer_funds` as a governed action.

Requirements:
- Must be in `GOVERNED_ACTIONS`
- Must require a valid decision record
- Must respect scope, expiry, and environment checks
- Must have at least one pass test and one fail test

## Challenge 3 — Break scope enforcement

Disable object matching (CHECK 7).

Run the demo using a decision record for `env_1` against `env_2`.

Expected: the wrong object is accepted.

Restore the check afterwards.

## Challenge 4 — Add double approval

Implement a new rule: sensitive actions require two valid decision records.

Both must be:
- unexpired
- matching action, object, and environment
- from different actors

Use tests to prove the rule.

A scaffold test exists: `tests/test_double_approval_extension.py`

## Rule

If a modification allows mutation without a valid decision path, the invariant has failed.
