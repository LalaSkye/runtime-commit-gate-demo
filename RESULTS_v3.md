# RESULTS_v3 — Adversarial Test Battery (V3)

**Date:** 2026-04-25
**Battery:** Pre-registered in `PRE_REGISTRATION_v3.md` (commit `4cc662b`)
**Branch:** `main`
**Status:** PUBLISHED, INCLUDING FAILURES (recorded BEFORE fixes were applied — see commit `a2cd328`)

---

## Summary

| Metric | Value |
|--------|-------|
| V3 tests planned | 24 |
| V3 tests written | 24 |
| V3 tests passed (final) | 24 |
| V1 tests still passing | 89 of 90 (xfail flipped to pass via V2 fix; unrelated `test_double_approval_required_for_sensitive_action` xfail unchanged) |
| V2 tests still passing | 27 of 28 (B07 remains `pytest.skip` because it constructs `CommitGate` in legacy-mode without a ledger — V3 introduced the ledger as **opt-in**) |
| **Full suite** | **141 passed, 1 skipped, 1 xfailed** |
| **Falsification criteria triggered (initial run)** | **2 of 20 (H2 partial, H3)** — both recorded before any fix |
| **Falsification criteria still triggered after fixes** | **0 of 20** |
| **Real findings** | **2 (C04 UnicodeDecodeError, C05 cross-process race) — both documented before fixing** |
| **V2 findings closed in V3** | **2 (B07, B22)** |

The pre-registered V3 claim was initially **falsified at H2 (partial) and H3** by the V3 battery. Both findings were recorded in this document before any source change. The fixes were then applied and re-tested; both H criteria now hold.

---

## Findings recorded BEFORE fixes were applied

This section was written first, before any source change, as required by the
"no silent fixes" discipline. Commit `a2cd328` froze this state.

---

### FINDING_C04 — Non-UTF8 garbage in nonce ledger raised UnicodeDecodeError, not NonceLedgerCorruption

**Pre-registration target:** H2.
**Test:** `test_C04_garbage_ledger_raises_corruption`.
**Initial symptom:** When the ledger file contains non-UTF8 bytes (e.g., `\xff`), the constructor raised `UnicodeDecodeError` from the underlying `open(..., "r")` instead of the expected `NonceLedgerCorruption`.

**Severity:** Bounded. The system DID fail closed (the constructor refused to return a usable ledger), but the exception type was wrong. An operator catching `NonceLedgerCorruption` only would have missed this path.

**Mechanism:** `open(self._path, "r")` in `_rebuild()` decoded as UTF-8 by default. Non-UTF8 bytes raised during line iteration before the `json.JSONDecodeError` catch could see them.

**Fix applied (post-publication):** Open in binary mode, attempt UTF-8 decode of the whole buffer with `try/except UnicodeDecodeError`, and convert any decode failure into `NonceLedgerCorruption`. `repair=True` mode replaces invalid bytes and continues. See `src/nonce_ledger.py:_rebuild`.

**Verification:** `test_C04_garbage_ledger_raises_corruption` now passes. The expected exception type is raised.

---

### FINDING_C05 — Cross-process concurrent same-nonce race produced multiple ALLOW

**Pre-registration target:** H3.
**Test:** `test_C05_concurrent_same_nonce_against_shared_ledger`.
**Initial symptom:** 8 threads, each with its own `NonceLedger` instance against a shared ledger file, submitting the same nonce simultaneously. Result: **5 of 8 ALLOW outcomes** for the same nonce. H3 expected at most 1.

**Mechanism:** Each `NonceLedger` instance had its own `threading.Lock` and its own private `_used` set built from the file at construction. The `consume()` method protected only against intra-process races. Between independent ledger instances (whether in the same process or different processes), the sequence "contains-check → append → fsync" was not atomic at the file level. Multiple instances saw the file as empty at construction, all passed `contains()`, all appended, all returned True.

**Severity:** REAL — falsified H3 as written. This is a genuine concurrency bypass of replay protection in the demo's pre-fix shape.

**Note on the pre-registration:** `PRE_REGISTRATION_v3.md` design choice 2 specified "Append + fsync. This is the durability boundary." That specification covered durability but not inter-process atomicity. The pre-registration was incomplete. The V3 battery surfaced the gap. **Pre-registration was not retroactively edited to make the system pass.** The system was changed to satisfy what the pre-registration intended.

**Fix applied (post-publication):**
- POSIX file lock (`fcntl.LOCK_EX`) acquired around the contains-check + append + fsync sequence.
- `_refresh_from_disk()` re-reads the ledger under the lock to pick up writes from other instances since construction.
- Lock held only during the critical section. Released before threads return.
- See `src/nonce_ledger.py:consume`.

**Trade-offs:**
- POSIX-only via `fcntl`. On Windows, the lock falls back to no-op (the `_HAS_FCNTL` guard preserves intra-process protection). Documented in `WINDOWS_LIMITATION` for future work.
- Per-call file open/close overhead. For demo / governance-scale workloads this is acceptable; for high-throughput paths a connection-pooled file handle would be preferred.

**Verification:** `test_C05_concurrent_same_nonce_against_shared_ledger` now passes — exactly one of 8 concurrent same-nonce attempts succeeds; the others return `NONCE_REPLAYED`.

**Test integrity note:** The test was not modified to make the system pass. The system was modified to satisfy the test as originally written.

---

## What V3 attacked (and what held)

| Surface | Pre-registered criteria | Result |
|---------|-------------------------|--------|
| Durable nonce ledger (cross-restart, fuzzed, concurrent, exact-match, divergence) | H1–H5 | **HOLDS** after C05 fix |
| Issued-at validation (1 day future, 1 second future, legitimate past, malformed) | H6–H9 | **HOLDS** — zero-tolerance future-issuance check operational |
| Audit chain integrity (edit, truncate, insert, reorder, duplicate, clean fuzz) | H10–H15 | **HOLDS** — hash-linked entries detect every tested tamper |
| Crash recovery (state-unchanged on crash, divergence detected, retry allowed, deterministic, concurrent-safe) | H16–H20 | **HOLDS** — ledger-first ordering with `verify_consistency()` reporter |

---

## V2 findings closed by V3

### FINDING_B07 — Durable nonce ledger

**V2 status:** Confirmed gap. In-memory `_used_nonces`. Cross-process replay possible.
**V3 status:** **FIXED** via opt-in `NonceLedger` passed to `CommitGate(store, audit, nonce_ledger=...)`.

`CommitGate.__init__` now accepts an optional `nonce_ledger` parameter. When supplied, all replay protection is durable (JSONL-backed, fsynced, file-locked). When omitted, falls back to the V1/V2 in-memory behaviour for back-compat with existing tests and the demo `server.py`.

V2's `test_B07_nonce_replay_across_simulated_restart` continues to skip with the documented finding because it explicitly does not pass a ledger — that test verifies legacy-mode behaviour. V3's `test_C01_nonce_replay_across_simulated_restart` confirms the durable-mode behaviour. Both are correct in their respective scopes.

### FINDING_B22 — Issued-at validation

**V2 status:** Gate accepted records with `issued_at` in the future.
**V3 status:** **FIXED** via `now < issued_at` check in `gate.py`. Zero-tolerance: any future issuance blocks with `ISSUED_AT_IN_FUTURE`. Malformed `issued_at` blocks with `INVALID_ISSUANCE_FORMAT`.

V2's `test_B22_issued_in_future` (which was `pytest.skip` documenting the gap) now flips to `PASS`. The V2 test was written defensively to assert state unchanged regardless of allow/deny verdict — that assertion still holds, and now the gate explicitly denies.

---

## V3 carry-overs (still open after V3)

| Item | Reason |
|------|--------|
| FINDING_B14 — FastAPI recursion limit on deep JSON | Robustness, not invariant. Out of scope per `PRE_REGISTRATION_v3.md`. Carried to V4 backlog. |
| Windows file-locking | `fcntl` is POSIX-only. Windows path uses `_HAS_FCNTL=False` and reverts to in-process-only locking. Documented; carry to V4 if Windows deployment becomes a target. |
| `verify_consistency()` heuristic detection | Current STATE_AHEAD detection is shape-specific to the demo's three governed objects. A production system would need either an explicit per-mutation-type detector or a hash-anchored state snapshot. Acceptable for the demo. |
| External head_hash anchor | `verify_chain` detects internal corruption; `head_hash` is the external anchor. The repository does not currently publish or pin a head_hash. A V4 step would commit the head_hash periodically to a separate, signed location. |

---

## Battery discipline confirmation

1. **Pre-register before testing.** ✅ `PRE_REGISTRATION_v3.md` committed (4cc662b) before any V3 source change or test.
2. **Tests attempt failure, not confirm fix.** ✅ Every C-test states the H criterion it tries to falsify.
3. **No test rescues another.** ✅ Each test starts with a fresh tmp_path.
4. **Every test states its target.** ✅ All 24 V3 tests have docstrings naming the H criterion.
5. **No silent fixes.** ✅ Findings C04 and C05 published in commit `a2cd328` BEFORE the fix commit.
6. **Property fuzz where useful.** ✅ C02 (100 trials), C18 (50 trials).
7. **V1/V2 not silently rewritten.** ✅ V1 and V2 test files are untouched. `CommitGate` accepts the new `nonce_ledger` parameter as optional, so no existing constructor call breaks. The audit log gained `seq` and `prev_hash` fields, but `read_all()` and `clear()` semantics are unchanged. The B22 V2 test flips from skip to pass via gate behaviour change, not via test rewrite.

---

## Conclusion

**The V3 pre-registered claim was initially falsified at two points (C04, C05) and is now upheld after fixes.**

- 24 V3 tests run; 2 initially failed; 2 findings published BEFORE patches; both fixes applied; all 24 now pass.
- Full suite: **141 passed, 1 skipped (V2 B07 legacy-mode), 1 xfailed (V1 unrelated)**.
- 2 outstanding V2 findings (B07, B22) closed.
- 4 carry-overs documented for V4.

This is the result of V3. Failures included. Fixes applied only after the failures were published.

V4 is not pre-registered yet. The carry-over list above is the candidate scope.
