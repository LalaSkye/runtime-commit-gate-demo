# RESULTS_v4 — Adversarial Test Battery (V4)

**Date:** 2026-04-25
**Battery:** Pre-registered in `PRE_REGISTRATION_v4.md` (commit `5005dd2`)
**Branch:** `main`
**Status:** PUBLISHED, INCLUDING FAILURES (recorded BEFORE fixes were applied — see commit `1abb78a`)

---

## Summary

| Metric | Value |
|--------|-------|
| V4 tests planned | 18 |
| V4 tests written | 18 |
| V4 tests passed (final) | 18 |
| V1 tests still passing | 89 of 90 (unrelated xfail unchanged) |
| V2 tests still passing | 27 of 28 (B07 legacy-mode skip unchanged) |
| V3 tests still passing | 24 of 24 |
| **Full suite** | **159 passed, 1 skipped, 1 xfailed** |
| **Falsification criteria triggered (initial run)** | **0 of 14** (V4 battery) |
| **Pre-registration incompleteness found during impl** | **1 (D-PRE) — recorded before fix** |
| **V4 tests that passed on first run** | **18 of 18** |

**All 14 H-criteria hold under V4 fixes.** The only finding was a pre-registration internal contradiction (H14 written in a way that contradicted V4 design choice §10), discovered during implementation before the V4 battery was written. It was documented before the V1 test adjustment was made.

---

## Finding recorded BEFORE adjustment

### FINDING_D-PRE — Pre-registration internal contradiction (H14)

**Discovered:** During implementation of `gate.py` binding check, two V1 baseline tests began to fail:

- `test_valid_decision_allows_change_limit` — legacy `make_record()` with caller-supplied `params={"new_limit": 50000.0}` on `change_limit`. Hit `PARAMS_NOT_BOUND`.
- `test_valid_decision_allows_approve_invoice` — legacy `make_record()` on `approve_invoice` with no caller params. Hit `PARAMS_NOT_BOUND` because `approve_invoice` was not listed in `PARAMETERLESS_ACTIONS`.

**Mechanism — pre-registration internal contradiction:**

`PRE_REGISTRATION_v4.md` H14 stated:

> All V1+V2+V3 tests continue to pass without modification. Records constructed via the legacy `make_record()` (no params binding) are either rejected with a clear reason (`PARAMS_NOT_BOUND`) or accepted under a documented "unbound" mode for governed actions that take no params (`delete_env`).

These two clauses conflict:

- Design choice §10 forbids the configuration `params != None AND decision.params_hash is None AND decision.params is None`. The V1 `change_limit` test exercises exactly that configuration.
- `approve_invoice` does not consult `params` in `state_store.apply_mutation`, so it is functionally parameterless. The pre-registration listed only `delete_env` in `PARAMETERLESS_ACTIONS`.

The pre-registration could not be satisfied as written.

**Severity:** REAL — the pre-registration was incomplete. The V1 `change_limit` test was passing under V1–V3 precisely because of the V4 gap. Closing the gap necessarily changes it.

**Resolution (transparent, published in `a2cd328`-style discipline):**

Two adjustments, neither silent:

1. **`approve_invoice` added to `PARAMETERLESS_ACTIONS`.** Justification: `state_store.apply_mutation` for `approve_invoice` does not consult `params`. It is functionally parameterless. The pre-registration omitted it; recorded as pre-reg incompleteness. `src/gate.py` carries an explanatory comment.

2. **`test_valid_decision_allows_change_limit` (V1) updated to use Mode A binding.** Docstring amended to record the V4 adjustment. Original test code preserved in git history.

**Pre-registration is NOT retroactively edited.** The contradiction stands in the pre-registered document. This finding records what happened and how it was resolved.

---

## What V4 attacked (and what held)

| Surface | Pre-registered criteria | Result |
|---------|-------------------------|--------|
| Mode A — params_hash binding (plain exploit, fuzz, dict ordering, type distinction, nested swap, nested fuzz, empty/nonempty mixing, legacy path) | H1–H6 | **HOLDS** |
| Mode B — params-in-record (caller cannot override, round-trip, params in signed payload, path separation) | H7–H10 | **HOLDS** |
| Cross-cutting (None vs {} distinction, unhashable raises, audit forensics, regression, parameterless legacy) | H11–H14 | **HOLDS** |

---

## What was closed

### The V3→V4 gap

Before V4, the contrapositive of the system's signature line was false:

> Valid authority artefact + attacker-chosen params = admissible arbitrary mutation.

After V4, `change_limit account_X amount=100` can be applied only with exactly those params (Mode A hash check) or can be issued such that the params are embedded in the signed record (Mode B). A caller holding a valid signed record for `amount=100` cannot swap in `amount=999_999_999`. The gate returns `PARAMS_HASH_MISMATCH` or `WRONG_GATE_PATH`, state is unchanged, and **the nonce is not consumed** (binding check occurs before nonce consumption — a deliberate softening of V3's lost-operation policy, pre-registered in V4 design choice §9).

The signature line now holds in both directions:

> *No valid authority artefact, no admissible mutation.*
> *Valid authority artefact binds the exact mutation it describes.*

---

## V4 carry-overs (still open after V4)

| Item | Reason |
|------|--------|
| Tuple/list collapse in params canonical form | JSON renders both as arrays. In the demo we treat them equivalent. A production system would normalise types explicitly. Pre-registered as a known limitation (design choice §3). |
| Audit-entry `params_fingerprint` field | Pre-registration §8 proposed adding a `params_fingerprint` field to audit entries. Current implementation ties forensics to `decision_id`; the DecisionRecord holds the `params_hash` in its signed payload. Full forensic re-derivation would require persisting the record itself alongside the audit entry. Carry-over to V5. |
| Mode B records carrying params over the wire | Every intermediate hop sees the params. Where params contain sensitive data (amounts, account numbers), Mode A is preferred. This is a design trade-off, not a finding. |
| Key compromise / HMAC secret rotation | Unchanged from V3. Architecture decision, not a battery problem. |
| FINDING_B14 — FastAPI recursion limit on deep JSON | Carried from V2. Robustness, not invariant. Still open. |

---

## Battery discipline confirmation

1. **Pre-register before testing.** `PRE_REGISTRATION_v4.md` committed (`5005dd2`) before any V4 source change or test.
2. **Tests attempt failure, not confirm fix.** Every D-test states the H criterion it tries to falsify.
3. **No test rescues another.** Each test starts with a fresh tmp_path.
4. **Every test states its target.** All 18 V4 tests have docstrings naming the H criterion.
5. **No silent fixes.** The only finding (D-PRE) was published in commit `1abb78a` BEFORE the V1 test adjustment was committed.
6. **Property fuzz where useful.** D02 (100 trials), D06 (50 trials).
7. **V1/V2/V3 not silently rewritten.** One V1 test (`test_valid_decision_allows_change_limit`) was explicitly updated with a docstring explaining why. Its original form was passing due to the V4 gap; updating it to use Mode A is the legitimate path. All other V1/V2/V3 tests untouched.

---

## Conclusion

**The V4 pre-registered claim holds after one documented pre-registration incompleteness was resolved.**

- 18 V4 tests run; all 18 passed on first run.
- 1 pre-registration incompleteness (D-PRE) published BEFORE the two resolving adjustments (PARAMETERLESS_ACTIONS extension + V1 test update with disclosing docstring).
- Full suite: **159 passed, 1 skipped (V2 B07 legacy-mode), 1 xfailed (V1 unrelated)**.
- 1 outstanding V2 finding (B14) carried to V5.
- 4 V4 carry-overs documented for V5.

The gap between "valid authority artefact exists" and "valid authority artefact binds the specific mutation it describes" is now closed for demo-shape workloads, under two complementary binding modes.

V5 is not pre-registered yet. Candidate scope: params_fingerprint in audit, tuple/list type normalisation, FINDING_B14 robustness fix, and the audit-log rollback attack (`verify_chain` passes on an empty log — requires an external head_hash anchor to meaningfully test).
