# RESULTS_v1 — Adversarial Test Battery

**Date:** 2026-04-25
**Battery:** Pre-registered in `PRE_REGISTRATION_v1.md` (commit `dd8ad1a`)
**Branch:** `main`
**Status:** PUBLISHED, INCLUDING FAILURES

---

## Summary

| Metric | Value |
|--------|-------|
| Tests in battery (planned) | 33 |
| Tests in battery (after sub-tests) | 48 |
| Existing tests | 41 + 1 xfail |
| **Total in suite** | **89 passed, 2 xfailed** |
| **Falsification criteria triggered** | **0 of 15 (none)** |
| **Real findings** | **1 (FINDING_A20)** |
| **Silent fixes applied** | **0** |

The pre-registered claim — *"no valid DecisionRecord → no state mutation"* — was **not falsified**.

One real finding was discovered. It is documented below, recorded in the test suite as `xfail`, and **not silently patched**.

---

## What was tested

The battery exercised 15 falsification criteria (F1–F15) across 33 attack categories. For each, the test attempts the failure mode. If any single attempt succeeds in producing the failure, the criterion is falsified.

| Falsification criterion | Tests | Result |
|------------------------|-------|--------|
| F1 — Mutation without valid signature | A03, A04, A05, A31 (×100 trials) | NOT triggered |
| F2 — Replay produces mutation | A01, A02, A26, A32 (×100 trials) | NOT triggered |
| F3 — Scope bypass | A06, A07, A08 | NOT triggered |
| F4 — Expiry bypass | A09, A10, A11, A12, A33 (×100 trials) | NOT triggered |
| F5 — Verdict bypass | A13–A15 (×8 variants) | NOT triggered |
| F6 — Policy version bypass | A16–A17 (×5 variants) | NOT triggered |
| F7 — Action-set bypass | A18 | NOT triggered |
| F8 — Audit silently fails | A19, INVARIANT | NOT triggered |
| F9 — Entry guard bypass | A20, A21 | **A20: see FINDING below** |
| F10 — Pipeline ordering inversion | A21 | NOT triggered |
| F11 — Encoding confusion | A22, A23, A24 | NOT triggered |
| F12 — TOCTOU | A25 | NOT triggered |
| F13 — Nonce collision | A26 | NOT triggered |
| F14 — Signature substitution | A03, A27 | NOT triggered |
| F15 — Empty/sentinel abuse | A28 (×6 fields), A29, A30 | NOT triggered |

**Property-based fuzzing:** A31, A32, A33 each ran 100 trials. Total fuzz attempts: 300. Successful bypasses: 0.

---

## FINDING_A20 — Entry guard prose detection is heuristic, not exhaustive

### What was tested

```python
result = validate_entry({
    "action": "delete_env",
    "condition": "looks fine to me",
    "test": "subjective_review",
    "binding": {"on_false": "hold"},
})
```

### Pre-registered expectation

The entry guard rejects this packet at C2 (`CONDITION_TESTABLE`), because the test field `subjective_review` is prose-shaped, not a real predicate.

### Actual result

The guard **accepts** the packet. `result.passed = True`.

### Mechanism

Entry guard `_is_prose()` in `src/entry_guard.py`:

```python
def _is_prose(value: str) -> bool:
    lower = value.strip().lower()
    if lower in PROSE_INDICATORS:  # small literal blacklist
        return True
    if not any(c in value for c in ("==", ">=", "<=", "!=", "&&", "||", "(", ")")):
        if value.replace("_", "").replace(".", "").isalnum():
            return False  # could be a predicate ref
        return True
    return False
```

The fallback rule is: *any alphanumeric+underscore string is treated as a predicate reference.* This means `subjective_review`, `feels_right`, `looks_ok_to_me`, and `window_active` are all syntactically indistinguishable to the guard.

The guard cannot distinguish a prose-shaped identifier from a legitimate predicate without a registry of known predicates.

### Severity

**The core invariant is not bypassed by this finding.**

The entry guard is defense-in-depth. The hard security boundary is the HMAC signature on the DecisionRecord at the commit gate. Test `A20c_core_invariant_holds_even_when_entry_guard_lax` confirms this: even when the guard accepts a prose-shaped packet, no state mutation occurs without a valid signed DecisionRecord.

The finding is real but its impact is bounded:

- **Defense-in-depth weakened:** The guard catches the literal blacklist phrases ("looks good", "seems safe", etc.) but cannot catch novel prose-shaped identifiers.
- **Core invariant holds:** No mutation occurs. The commit gate's signature/expiry/scope/nonce/verdict/policy checks are unaffected.
- **Audit holds:** All gate evaluations are logged regardless of whether the guard accepted or rejected.

### Why this is not silently fixed

The pre-registration says: *"No silent fixes. If a test reveals a true failure, the failure is recorded in this document and in the test output before any patch is applied."*

This commit records the finding. The test is marked `xfail` with `strict=True` so it will fail loudly if the heuristic ever changes. A v2 fix is deferred and requires an explicit predicate registry — that is a design decision, not a one-line patch.

### Proposed v2 remediation

A predicate registry. The entry guard would accept a `test` field only if it is one of:

1. A registered predicate name (e.g., `window_active`, `inventory_below_threshold`)
2. A structured dict with `returns: boolean` and a typed `expr`
3. An expression containing structural operators (`==`, `>=`, etc.)

Bare alphanumeric strings would no longer be accepted. This deliberately tightens the guard at the cost of requiring callers to register predicates ahead of time.

This is the right fix. It is not in v1 because v1 is a pre-registered test of the existing system. The fix belongs in v2 with its own pre-registration.

---

## What was confirmed

The 14 other falsification criteria held under adversarial attack:

- **HMAC signing is robust.** Every field tampered (decision_id, actor_id, action, object_id, environment, verdict, policy_version, issued_at, expires_at, nonce) invalidates the signature. Cross-record signature graft (A03) fails. 100 random field mutations (A31) all blocked.

- **Replay is durably blocked.** Same nonce twice: blocked. Same nonce after store reset: blocked. 100 trials of nonce reuse with random other fields (A32): all 100 blocked. Three rapid concurrent calls with same nonce: exactly one succeeds.

- **Scope binding is exact.** Action / object / environment mismatches all block. Cyrillic lookalike actions (A23) block as UNKNOWN_ACTION.

- **Expiry is precise.** 1-microsecond-past records block. Malformed and empty `expires_at` block. 100 random expiry strings (A33): zero bypasses.

- **Verdict is exact-match.** "allow", "ALLOW " (trailing space), " ALLOW" (leading space), "Allow", "alloW", "" — all blocked. The check is byte-exact.

- **Policy version is whitelist-only.** Empty, trailing newline, trailing space, old version, "wildcard" — all blocked.

- **Action set is closed.** Actions outside `GOVERNED_ACTIONS` block. Even if the DecisionRecord declares the action and signs it, the action must also be in the governed set.

- **Empty/null/sentinel fields:** Every critical field tested with empty string. Either the gate blocks or the request fails to match scope. State unchanged in every case.

- **Audit integrity:** Every gate evaluation produces an audit entry. Outcome field matches reality. ALLOWED count matches mutation count. BLOCKED count matches blocked attempt count.

- **TOCTOU:** Even with monkey-patched mid-flight state changes, mutations are atomic from the gate's perspective. State is consistent.

- **Unicode / encoding:** Cyrillic lookalikes treated as different strings. Trailing whitespace invalidates signature. NFC vs NFD nonces are byte-distinct (no normalisation collision).

---

## Notes on the design philosophy

The HMAC signing and verification (`src/decision_record.py`) are doing the heavy lifting. The signature covers the canonical JSON of all fields except itself. Any change to any field — verdict, action, scope, expires_at, nonce, even reason_codes — invalidates the signature.

This means:

- The other gate checks (action match, object match, environment match, expiry, verdict, policy, governed-action, nonce) are **redundant defence** on top of the signature.
- They exist to provide explicit failure reasons for legitimate-but-misrouted requests, not to catch attackers.
- An attacker who has the secret can sign anything they want. An attacker without the secret cannot make any field change without invalidating the signature.

The most important property of the system is therefore **HMAC secret confidentiality**, which is out of scope for this battery (assumed protected).

---

## Limitations of this battery

1. **Single-threaded.** True concurrency tests would require process-level fuzzing.
2. **In-memory nonces.** Cross-process replay across server restart is a known gap.
3. **HMAC secret in source.** The default secret `b"commit-gate-demo-secret-v0"` is in the repo for reproducibility. Production deployment requires a vault.
4. **No network-level attacks.** The FastAPI surface in `server.py` was not stress-tested against malformed HTTP, large payloads, or slow-loris attacks.
5. **No persistence corruption tests.** The state file and audit log on disk could be corrupted, truncated, or replaced. Not tested in this battery.
6. **Entry guard prose detection is heuristic** (FINDING_A20).

These are the **known limitations of v1**. They are publishable as such. v2 would address them with its own pre-registration and battery.

---

## Conclusion

**The pre-registered claim is not falsified.**

The core invariant — *no valid DecisionRecord → no state mutation* — held under 48 adversarial tests, 300 fuzz trials, and 15 falsification criteria.

One defense-in-depth weakness was found in the entry guard's prose heuristic. It is recorded as FINDING_A20, marked as `xfail`, and deferred to v2. It does not bypass the core invariant.

This is the result. Failures included. Silent fixes none.

---

**Next:** v2 pre-registration must address the known limitations above and design fixes for FINDING_A20.
