# RESULTS_v3 — Adversarial Test Battery (V3)

**Date:** 2026-04-25
**Battery:** Pre-registered in `PRE_REGISTRATION_v3.md` (commit `4cc662b`)
**Branch:** `main`
**Status:** PUBLISHED, INCLUDING FAILURES (recorded BEFORE any patch)

---

## Findings recorded BEFORE fixes are applied

This section is written first, before any source change, as required by the
"no silent fixes" discipline.

---

### FINDING_C04 — Non-UTF8 garbage in nonce ledger raises UnicodeDecodeError, not NonceLedgerCorruption

**Pre-registration target:** H2.
**Test:** `test_C04_garbage_ledger_raises_corruption`.
**Symptom:** When the ledger file contains non-UTF8 bytes (e.g., `\xff`), the constructor raises `UnicodeDecodeError` from the underlying `open(..., "r")` instead of the expected `NonceLedgerCorruption`.

**Severity:** Bounded. The system DOES fail closed (the constructor refuses to return a usable ledger), but the exception type is wrong. An operator may not catch `UnicodeDecodeError` if their handler is keyed on `NonceLedgerCorruption`.

**Mechanism:** `open(self._path, "r")` in `_rebuild()` decodes as UTF-8 by default. Non-UTF8 bytes raise during line iteration, not during my JSON parse, so the catch in `_rebuild` doesn't see them.

**Fix design:** Open in binary mode and decode per line with `errors="replace"`, then attempt `json.loads`. Or wrap the entire `_rebuild` in `try: except (UnicodeDecodeError, OSError): raise NonceLedgerCorruption`.

This finding is a real falsification of H2 in the strict reading: H2 says *fail-closed without raising or recording a corruption event*. The current code does fail closed, but with a non-corruption exception. Recording as a finding for transparency.

---

### FINDING_C05 — Cross-process concurrent same-nonce race produces multiple ALLOW

**Pre-registration target:** H3.
**Test:** `test_C05_concurrent_same_nonce_against_shared_ledger`.
**Symptom:** 8 threads, each with its own `NonceLedger` instance against a shared ledger file, submitting the same nonce simultaneously. Result: **5 ALLOW outcomes** for the same nonce. H3 expected ≤ 1.

**Mechanism:** Each `NonceLedger` instance has its own `threading.Lock` and its own private `_used` set built from the file at construction time. The `consume()` method protects only against intra-process races. Between processes (or between independent ledger instances in the same process), the sequence "contains-check → append → fsync" is not atomic at the file level. Multiple instances all see the file as empty at construction, all pass `contains()`, all append, all return True.

**Severity:** REAL — falsifies H3 as written.

This is a genuine cross-process concurrency bypass of replay protection in the demo's current shape. The pre-registered design called for "Append + fsync. This is the durability boundary." That covers durability but NOT inter-process atomicity. The pre-registration was incomplete, and the V3 battery surfaced the gap.

**Fix design:**
- Add OS-level file lock (`fcntl.flock` on POSIX) around the contains-check + append + fsync sequence.
- Re-read the file under the lock to refresh `_used` from disk before the contains check.
- Lock held during the critical section only. Released before threads return.
- Pre-registered behaviour (zero tolerance) is unchanged for legitimate users.

**Note on test:** The test is correct as written. It was designed to falsify H3 if such a race existed, and it succeeded. The test is NOT being adjusted to make the system pass; the SYSTEM is being adjusted to pass the test.

---

## Summary (after fixes applied)

(filled in after C04 + C05 fixes, then full re-run.)

---
