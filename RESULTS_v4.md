# RESULTS_v4 — Adversarial Test Battery (V4)

**Date:** 2026-04-25
**Battery:** Pre-registered in `PRE_REGISTRATION_v4.md` (commit `5005dd2`)
**Branch:** `main`
**Status:** PUBLISHED, INCLUDING FAILURES (recorded BEFORE any fix)

---

## Findings recorded BEFORE fixes are applied

This section is written first, before any further source change, as required by the
"no silent fixes" discipline.

---

### FINDING_D-PRE — Pre-registration internal contradiction (H14)

**Discovered:** During implementation. After adding the binding check to `gate.execute()`, two V1 baseline tests began to fail:

- `test_valid_decision_allows_change_limit` — uses `make_record()` (no params binding) on action `change_limit` with caller-supplied `params={"new_limit": 50000.00}`.
- `test_valid_decision_allows_approve_invoice` — uses `make_record()` on action `approve_invoice` with no caller params.

Both now hit `PARAMS_NOT_BOUND` because `change_limit` and `approve_invoice` are governed actions outside `PARAMETERLESS_ACTIONS = {"delete_env"}` per the pre-registered design.

**Mechanism — pre-registration internal contradiction:**

`PRE_REGISTRATION_v4.md` H14 stated:

> All V1+V2+V3 tests continue to pass without modification. Records constructed via the legacy `make_record()` (no params binding) are either rejected with a clear reason (`PARAMS_NOT_BOUND`) or accepted under a documented "unbound" mode for governed actions that take no params (`delete_env`).

These two clauses conflict for the V1 tests:
- The change_limit V1 test exercises exactly the configuration `params != None AND decision.params_hash is None AND decision.params is None` — which design choice §10 explicitly forbids.
- The approve_invoice V1 test uses a governed action that is functionally parameterless in `state_store.apply_mutation` but was not listed in `PARAMETERLESS_ACTIONS`.

The pre-registration could not be satisfied as written.

**Severity:** REAL — the pre-registration was incomplete. The V1 change_limit test was passing previously precisely because of the V4 gap. Closing the gap necessarily breaks that test as written.

**Resolution (transparent, post-publication):**

Two adjustments, neither silent:

1. **`approve_invoice` added to `PARAMETERLESS_ACTIONS`.** Justification: `state_store.apply_mutation` for `approve_invoice` does not consult `params`. It is functionally parameterless. The pre-registration omitted it from the set; this is a pre-reg incompleteness, recorded here. The V1 `test_valid_decision_allows_approve_invoice` continues to pass without test modification.

2. **`test_valid_decision_allows_change_limit` (V1) updated to use Mode A binding.** Docstring amended to record the V4 adjustment. The original test was passing because of the V4 gap; updating it to use `make_record_with_params_hash()` is the legitimate path forward. Old test code preserved as comment for transparency.

**Pre-registration is NOT retroactively edited.** The contradiction stands in the pre-registered document. This finding records what happened and how it was resolved.

---

(Section continues after V4 battery runs and any further findings emerge.)
