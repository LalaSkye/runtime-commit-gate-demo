# PRE_REGISTRATION_v1 — Adversarial Test Battery

**Date pre-registered:** 2026-04-25
**Status:** WRITTEN BEFORE TESTS RUN
**Repo state at registration:** `main` branch, 41 passing + 1 xfail tests.

This document records the falsification criteria for the adversarial test battery **before any of those tests are written or run**.

If any test in the battery succeeds in producing the failure modes listed below, the claim under test is falsified. Failures will be published in this repository, in this document, and in the test output. Failures will not be silently fixed before publication.

---

## Claim under test

**The pipeline `entry_guard → commit_gate → state_store` enforces the invariant: no valid `DecisionRecord` → no state mutation. This invariant holds under hostile input, hostile timing, hostile encoding, and hostile state, within the limits documented below.**

## Scope of the claim

In scope:
- The `CommitGate.execute()` path
- The `validate_entry()` path
- The pipeline composition in `server.py`
- The signature verification, expiry check, nonce check, and scope-binding checks in `gate.py`

Explicitly **out of scope** (not claimed):
- Direct calls to `StateStore.apply_mutation()` (already documented as ungoverned in `test_adv_state_direct_mutation_is_possible_but_ungoverned`)
- Persistence of nonces across process restarts (in-memory by design, known limitation)
- Concurrency safety beyond single-threaded execution (not claimed)
- Network-level attacks against the FastAPI server
- Compromise of the HMAC secret itself (out of scope; assumed protected)

---

## Falsification criteria

The claim is **falsified** if any of the following occurs:

### F1. Mutation without a valid signature
A request with `decision = None`, with a forged signature, with a tampered field, or with a signature over different content reaches `state_store.apply_mutation()` and changes state.

### F2. Replay produces mutation
A `DecisionRecord` whose nonce has previously been consumed produces a second mutation.

### F3. Scope bypass produces mutation
A `DecisionRecord` valid for action A on object O₁ in env E₁ produces a mutation for action B, or object O₂, or env E₂.

### F4. Expiry bypass
A `DecisionRecord` whose `expires_at` is strictly before `now()` produces a mutation.

### F5. Verdict bypass
A `DecisionRecord` with `verdict ≠ "ALLOW"` produces a mutation.

### F6. Policy version bypass
A `DecisionRecord` with `policy_version` outside `ACCEPTED_POLICY_VERSIONS` produces a mutation.

### F7. Action-set bypass
An action outside `GOVERNED_ACTIONS` reaches `apply_mutation` via the gate path.

### F8. Audit log silently fails
A gate evaluation produces no audit entry, or an audit entry whose `outcome` field disagrees with the actual mutation outcome.

### F9. Entry guard bypass
A request with `entry_condition` set to a packet that should fail any of C1–C4 reaches the commit gate evaluation.

### F10. Pipeline ordering inversion
The commit gate evaluates an `ExecuteRequest` carrying a malformed `entry_condition` before the entry guard rejects it.

### F11. Encoding-based confusion attack
A field that decodes differently in different layers (e.g., Unicode normalisation, JSON number parsing, ISO timestamp parsing) produces a successful bypass of any of the checks above.

### F12. Time-of-check time-of-use
A check that passes in `gate.execute()` is invalidated by the time `state_store.apply_mutation()` runs, and the mutation still occurs.

### F13. Nonce uniqueness collision
Two distinct `DecisionRecord`s with the same nonce both succeed (only the first should).

### F14. Signature substitution attack
A valid signature from one `DecisionRecord` is grafted onto a different record and accepted.

### F15. Empty / null / sentinel-value abuse
Empty strings, `None`, integer 0, boolean `False`, or unicode invisible characters in critical fields produce a successful mutation when they should not.

---

## Battery design principles

1. **Tests are written to attempt the failure**, not to confirm the fix. A test that asserts the system blocks an attack is acceptable; a test that asserts the system allows something is required to demonstrate the surface.
2. **No test rescues another test.** Each adversarial test starts from a clean store and clean nonce ledger.
3. **Every test states the failure mode it targets** in its docstring.
4. **No silent fixes.** If a test reveals a true failure, the failure is recorded in this document and in the test output before any patch is applied.
5. **Property-based fuzzing** is used where possible, with at least 100 trials per property.
6. **Encoding attacks** include ASCII control characters, Unicode normalisation forms, mixed UTF-8/16, and known JSON number edge cases.

---

## Battery contents (planned)

| ID | Target | Method |
|----|--------|--------|
| A01 | F2 | Triple replay across reset boundaries |
| A02 | F2 | Same nonce, different decision_id, both signed |
| A03 | F1, F14 | Signature substitution (valid sig from record A onto record B) |
| A04 | F1 | Mutate `signature` field after construction |
| A05 | F1 | Mutate `nonce` field after construction (sig stays the same) |
| A06 | F3 | Action mismatch with otherwise-valid record |
| A07 | F3 | Object mismatch |
| A08 | F3 | Environment mismatch |
| A09 | F4 | `expires_at` exactly equal to now (boundary) |
| A10 | F4 | `expires_at` 1 microsecond before now |
| A11 | F4 | `expires_at` malformed string |
| A12 | F4 | `expires_at` empty string |
| A13 | F5 | `verdict = "allow"` (lowercase) |
| A14 | F5 | `verdict = "ALLOW "` (trailing space) |
| A15 | F5 | `verdict = ""` |
| A16 | F6 | `policy_version` empty |
| A17 | F6 | `policy_version = "2026-03-28.1\n"` |
| A18 | F7 | Action outside governed set with otherwise-valid record |
| A19 | F8 | Audit append exception masking the failure mode |
| A20 | F9 | Entry guard with prose condition reaching the gate |
| A21 | F10 | Malformed entry_condition with valid decision |
| A22 | F11 | Unicode normalisation: NFC vs NFD on `nonce` |
| A23 | F11 | Unicode lookalikes in `action` field |
| A24 | F11 | JSON integer parsed differently in two layers |
| A25 | F12 | TOCTOU: gate passes, store catches inconsistency |
| A26 | F13 | Nonce collision across rapid concurrent calls |
| A27 | F14 | Cross-record signature graft |
| A28 | F15 | Empty string in every required field individually |
| A29 | F15 | Zero-width unicode in `actor_id` |
| A30 | F15 | Null bytes in `decision_id` |
| A31 | F1 | Property-based fuzz: random mutation of any single field |
| A32 | F2 | Property-based fuzz: nonce reuse with random other fields |
| A33 | F4 | Property-based fuzz: random `expires_at` strings |

Total: 33 adversarial tests. Each runs at least once. Property-based tests run at least 100 trials.

---

## What "passing" means

The battery **passes** if and only if:
- Every adversarial attempt is correctly blocked
- Every block is audited
- The state store is unchanged after every blocked attempt
- The 41 existing tests continue to pass

The battery **fails** if any single adversarial test produces a real failure mode listed above. Failures will be recorded here, in test output, and in a public commit.

---

**This document is committed to the repository before any of A01–A33 is written or executed.**
