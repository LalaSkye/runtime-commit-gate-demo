# PRE_REGISTRATION_v4 — Adversarial Test Battery (Parameter Binding)

**Date pre-registered:** 2026-04-25
**Status:** WRITTEN BEFORE V4 SOURCE CHANGES OR TESTS ARE IMPLEMENTED
**Repo state at registration:** `main` after commit `136f1bb` (V3 complete: 141 passed, 1 skipped, 1 xfailed).
**Predecessors:** `PRE_REGISTRATION_v1.md`, `RESULTS_v1.md`, `_v2`, `_v3`.

This document is committed before any V4 source change or test is written.
If any test in the V4 battery produces the failure modes listed below, the corresponding criterion is falsified. Failures will be published in `RESULTS_v4.md` and in test output. **Failures will not be silently fixed before publication.**

---

## What V4 attacks

V1–V3 verified that **the gate** correctly evaluates a DecisionRecord against an attempted action. V4 attacks the assumption that the gate's evaluation **describes the mutation that actually occurs**.

The current `CommitGate.execute(action, object_id, environment, actor_id, decision, params)` signature has a structural gap: `params` is a separate, unsigned argument passed straight to `state_store.apply_mutation`. A holder of any valid signed DecisionRecord for `change_limit account_X` can submit `params={"amount": 999_999_999}` and the gate will pass it through without objection. Every other check holds; the mutation does not.

This falsifies the contrapositive of the system's signature line:

> *No valid authority artefact, no admissible mutation.*

Currently: **valid authority artefact + attacker-chosen params = admissible arbitrary mutation.** That gap closes here.

---

## Claim under test (V4)

After the V4 fixes, the pipeline `entry_guard → commit_gate → state_store + audit + ledger` enforces that **the parameters actually applied to the mutation are exactly the parameters that were signed into the DecisionRecord**.

Two binding modes are introduced. Both must hold the claim.

- **Mode A — params_hash binding (primary).** `DecisionRecord` gains a signed `params_hash` field (sha256 over canonical-JSON of the params dict). `execute()` recomputes the hash of received params and compares.
- **Mode B — params-in-record (alternate constructor).** `make_record_with_params()` produces a record with `params` directly embedded as a signed field. `execute_bound()` reads params from the record itself, ignoring any caller-supplied params argument.

Mode B is the stricter shape (no caller-supplied params at all). Mode A allows out-of-band params transit but binds them by hash.

---

## Falsification criteria (H1–H14)

The claim is **falsified** if any of the following occurs.

### Mode A — params_hash binding (H1–H6)

**H1.** Plain exploit succeeds: holder of a valid `change_limit / account_X / amount=100` DecisionRecord submits `params={"amount": 999999999}` and the mutation applies the attacker amount.

**H2.** Param dict re-ordering (`{"a":1,"b":2}` vs `{"b":2,"a":1}`) produces different hashes and the legitimate caller is rejected. (Canonical form must be order-invariant.)

**H3.** Param value type-coercion (`amount=100` int vs `amount=100.0` float vs `amount="100"` str) silently passes hash check. (Must be exact-type and exact-value bound.)

**H4.** Nested params (`{"limits": {"daily": 100, "monthly": 1000}}`) — attacker swaps a nested key value while preserving the top-level shape. Hash must detect.

**H5.** Empty / missing / null params: gate accepts a record with `params_hash = hash({})` plus caller-submitted non-empty params, or vice versa. (Empty must be a distinct, signed state.)

**H6.** A record signed under Mode A is accepted via the legacy unsigned `execute()` path, bypassing the hash check entirely. (Mode-mixing attack: legacy path must be removed or itself enforce.)

### Mode B — params-in-record (H7–H10)

**H7.** Plain exploit succeeds against `execute_bound()`: caller supplies an extra `params` kwarg that overrides the embedded params.

**H8.** A record built with `make_record_with_params({"amount": 100})` is verifiable: signature still validates after the params field is embedded.

**H9.** Two records identical except for embedded params produce different signatures (so the params field is in the signed payload, not adjacent to it).

**H10.** Mode A and Mode B records are distinguishable at the gate. A Mode B record without `params_hash` is not silently accepted by Mode A's path; a Mode A record without embedded `params` is not silently accepted by Mode B's path.

### Cross-cutting (H11–H14)

**H11.** Type confusion: `params=None`, `params={}`, and `params=missing` are all distinct, separately enforceable states. None silently coerces to another.

**H12.** Unhashable types in params (`params={"x": set()}`) raise an explicit error at record construction, not silently truncate or stringify.

**H13.** Audit log records the params (or their hash) of every ALLOWED mutation, so post-hoc forensics can answer "what was actually applied?"

**H14.** All V1+V2+V3 tests continue to pass without modification. Records constructed via the legacy `make_record()` (no params binding) are either rejected with a clear reason (`PARAMS_NOT_BOUND`) or accepted under a documented "unbound" mode for governed actions that take no params (`delete_env`).

---

## Battery design principles (carried from V1/V2/V3)

1. Tests are written to attempt the failure, not to confirm the fix.
2. No test rescues another. Each test starts with a clean state, ledger, and audit log.
3. Every test states the failure mode it targets.
4. **No silent fixes.** If a test reveals a real failure, it is recorded here, in `RESULTS_v4.md`, and in test output before any patch is applied.
5. Property-based fuzzing where useful, with explicit trial counts.
6. After each fix, V1–V3 tests must continue to pass without modification. Any required adjustment is documented in the test docstring, not silently rewritten.

---

## Battery contents (planned)

| ID | Target | Method |
|----|--------|--------|
| D01 | H1 | Plain exploit: valid Mode A record for `amount=100`, attacker submits `amount=999_999_999`. Expect `PARAMS_HASH_MISMATCH`, state unchanged, nonce NOT consumed. |
| D02 | H1 | Property fuzz, 100 trials: random legitimate amount, attacker tries random different amount. Always blocked. |
| D03 | H2 | Build params as ordered dict A then ordered dict B with same content. Both must produce same hash. Verify gate accepts either ordering of equivalent params. |
| D04 | H3 | Three records signed for `amount=100`, `amount=100.0`, `amount="100"` respectively. Each pair must be distinguishable: gate rejects cross-type submission. |
| D05 | H4 | Record signed with nested params; attacker mutates nested value. Block. |
| D06 | H4 | Property fuzz, 50 trials: random nested params, random nested mutation. Always blocked. |
| D07 | H5 | Record signed with `params_hash = hash({})`. Caller submits `params={"amount": 100}`. Block. |
| D08 | H5 | Record signed with `params_hash = hash({"amount":100})`. Caller submits `params={}`. Block. |
| D09 | H6 | Mode A record submitted via the legacy `execute()` (no params hash check) path. Either path is removed or rejects with `PARAMS_BINDING_REQUIRED`. |
| D10 | H7 | Mode B record submitted via `execute_bound()` with extra `params` kwarg. Caller-supplied params must be ignored or path must reject extra args. |
| D11 | H8 | Round-trip: `make_record_with_params({"amount":100})` → sign → verify. Signature valid. |
| D12 | H9 | Two records identical except for embedded params. Different signatures. |
| D13 | H10 | Mode A record submitted via Mode B path: rejected. Mode B record submitted via Mode A path: rejected. |
| D14 | H11 | Three records: `params=None` signed, `params={}` signed, no-params (legacy). Each goes only through its corresponding path; cross-submission rejected. |
| D15 | H12 | `make_record_with_params({"x": set()})` raises at construction. No record produced. |
| D16 | H13 | After a successful ALLOWED mutation, audit log entry contains the params hash (or the params themselves under Mode B). Verifiable from disk. |
| D17 | H14 | Run full V1+V2+V3 suite with V4 source changes in place. All pass. |
| D18 | regression | Existing legacy `make_record()` path: documented behaviour. Either rejects all governed actions with `PARAMS_NOT_BOUND`, or routes only `delete_env`-shape (parameterless) actions. Pre-registered choice: **legacy path accepted ONLY for actions that take no params, identified by `params is None` AND `decision.params_hash is None`**. |

Total: 18 V4 tests + V1/V2/V3 regression confirmation.

---

## V4 design choices (pre-registered, frozen before code is written)

These are committed in this document so the implementation cannot retro-fit to pass.

1. **Canonical form for params.** `json.dumps(params, sort_keys=True, separators=(",", ":"), default=...)`. Default raises on unhashable / unserialisable types. No silent coercion. Tuples serialise as JSON arrays (lossy but determined; document as a known limitation, see §3).

2. **Hash function.** `sha256(canonical_form.encode("utf-8")).hexdigest()`. 64 lowercase hex chars.

3. **Type-strict comparison.** The hash is computed over the canonical JSON, which already collapses int vs str distinctions because JSON renders `100` and `"100"` differently. Float vs int distinction is preserved (`100` vs `100.0` produce different JSON). Tuple vs list is collapsed by JSON (both → array); this is a documented limitation. **In the demo we treat any sequence-typed value as equivalent.** A production system would normalise types explicitly. Pre-registered: this is a known carry-over.

4. **Empty params policy.** `params=None` signs as the JSON `null`. `params={}` signs as `{}`. These are distinct hashes. Both are valid; legacy unbound path is `params=None` AND `params_hash=None`.

5. **DecisionRecord changes.** Adds optional fields: `params_hash: Optional[str]`, `params: Optional[dict]`. Both default `None`. Canonical payload includes both fields. Existing V1–V3 records (no params binding) hash and verify correctly because the new fields are `None` and serialise to `null`. **This is a forward-compatible extension; signature mismatch on old records would be a regression.**

6. **Gate paths.**
   - `execute(action, object_id, environment, actor_id, decision, params=None)` — current path. Behaviour:
     - If `decision.params_hash is None` and `decision.params is None` and `params is None`: **legacy unbound mode**. Accepted for actions explicitly listed in `PARAMETERLESS_ACTIONS` (currently `{"delete_env"}`). Rejected with `PARAMS_NOT_BOUND` otherwise.
     - If `decision.params_hash is not None`: Mode A. Compute `hash(params)` and compare. Mismatch → `PARAMS_HASH_MISMATCH`. Caller-supplied params is what gets applied.
     - If `decision.params is not None`: rejected with `WRONG_GATE_PATH` (use `execute_bound`).
   - `execute_bound(action, object_id, environment, actor_id, decision)` — new path for Mode B.
     - If `decision.params is None`: rejected with `WRONG_GATE_PATH` (use `execute`).
     - Otherwise: applies `decision.params` to the mutation. Caller cannot override.

7. **Reasons added.** `PARAMS_HASH_MISMATCH`, `PARAMS_NOT_BOUND`, `WRONG_GATE_PATH`, `INVALID_PARAMS_TYPE`.

8. **Audit log.** Each entry gains optional `params_fingerprint: Optional[str]` field — the params_hash for Mode A or a hash of the embedded params for Mode B. `None` for unbound legacy. Hash chain accommodates the new field because canonical form already includes it via `sort_keys`.

9. **Nonce-consumption ordering.** Same as V3: ledger-first. **But params-hash check happens BEFORE nonce consumption.** Failed binding does not consume the nonce. (This is a deliberate softening from V3's lost-operation policy because the binding check is a pure function of inputs and does not require durability to enforce.)

10. **No legacy ambient-params shortcut.** There is no path that accepts `params != None` AND `decision.params_hash is None` AND `decision.params is None`. That is the gap V4 closes; that combination always rejects with `PARAMS_NOT_BOUND`.

---

## Order of operations (strict)

1. Commit this pre-registration to public repo (this commit).
2. Implement V4 changes:
   - Modify: `src/decision_record.py` — add `params_hash`, `params`, `make_record_with_params()`, `make_record_with_params_hash()`.
   - Modify: `src/gate.py` — split paths, add binding checks, add reason codes.
   - Modify: `src/audit.py` — add optional `params_fingerprint` field.
3. Implement V4 tests in `tests/test_adversarial_battery_v4.py`.
4. Run full suite. Document results, including any failures, in `RESULTS_v4.md`.
5. Commit V4 changes + battery + results in transparent commits.

If a real failure surfaces, it is recorded in `RESULTS_v4.md` before any patch is applied to make the test pass.

---

**This document is committed before any V4 source change or V4 test is written.**
