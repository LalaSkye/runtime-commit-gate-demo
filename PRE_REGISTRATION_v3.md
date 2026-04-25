# PRE_REGISTRATION_v3 — Adversarial Test Battery (B07/B22 Fixes + Audit Chain + Crash Recovery)

**Date pre-registered:** 2026-04-25
**Status:** WRITTEN BEFORE V3 FIXES OR TESTS ARE IMPLEMENTED
**Repo state at registration:** `main` after commit `dbeccc7` (V2 battery published, 116 passed, 2 skipped, 1 xfailed).
**Predecessors:** `PRE_REGISTRATION_v1.md`, `RESULTS_v1.md`, `PRE_REGISTRATION_v2.md`, `RESULTS_v2.md`.

This document is committed before any V3 source change or test is written.
If any test in the V3 battery produces the failure modes listed below, the corresponding criterion is falsified. Failures will be published in `RESULTS_v3.md` and in the test output. **Failures will not be silently fixed before publication.**

---

## What V3 attacks

V2 left three findings open and called out two further surfaces. V3 attacks all five.

| V2 outstanding | V3 attack target |
|----------------|------------------|
| FINDING_B07 — nonce ledger in-memory only, replay across process restart possible | H1–H5 |
| FINDING_B22 — gate accepts records with `issued_at` in the future | H6–H9 |
| FINDING_B14 — FastAPI recursion limit on deep JSON | OUT OF SCOPE for V3 (robustness, not invariant). Documented as carry-over. |
| **NEW** — no tamper detection on audit log entries | H10–H15 |
| **NEW** — crash-mid-mutation recovery semantics undefined | H16–H20 |

V3 does not re-attack V1 or V2 surfaces. It assumes V1+V2 holds and verifies the new fixes do not regress them.

---

## Claim under test (V3)

After the V3 fixes, the pipeline `entry_guard → commit_gate → state_store + nonce_ledger + audit_chain` enforces:

1. **Durable replay protection** — a nonce consumed in process A cannot produce a successful mutation in successor process B.
2. **Issuance bounds** — a DecisionRecord with `issued_at` in the future is rejected before mutation.
3. **Audit tamper evidence** — any post-hoc modification, truncation, reordering, or duplication of audit entries is detectable by a deterministic chain-verification procedure.
4. **Crash recovery** — for any crash between the start and end of an `execute()` call, the post-restart state of `(state_store, nonce_ledger, audit_log)` is consistent with one of two explicit outcomes: *attempt fully applied* or *attempt fully rejected/lost*. No partial mutation. No silent loss of replay protection.

The claim is narrower than V1/V2. V1+V2 already established the invariant under hostile input, encoding, timing, persistence corruption, concurrency, and HTTP attack. V3 establishes durability across process restart and tamper evidence on the audit surface.

---

## Falsification criteria (H1–H20)

The claim is **falsified** if any of the following occurs.

### Durable nonce ledger (H1–H5)

**H1.** A nonce consumed in `CommitGate` instance A produces a successful mutation when replayed in instance B constructed against the same persistent ledger.

**H2.** A truncated or corrupted nonce ledger file causes the gate to start with an empty `_used_nonces` set without raising or recording a corruption event.

**H3.** Two concurrent gate instances against the same ledger file accept the same nonce without one receiving `NONCE_REPLAYED` or a write-conflict equivalent. (At least one of N concurrent attempts must fail.)

**H4.** Nonce-ledger lookup matches inexactly (whitespace, case, prefix, hex/bytes confusion, JSON-escape collision).

**H5.** A nonce is recorded in the ledger but never written through `audit.jsonl`, leaving the ledger and audit out of sync in a way that cannot be reconciled deterministically.

### Issued-at validation (H6–H9)

**H6.** A DecisionRecord with `issued_at = now + 1 day` and `expires_at = now + 2 days` produces a successful mutation. (V2 confirmed this is the current behaviour; H6 is falsified iff the V3 fix has not landed correctly.)

**H7.** A DecisionRecord with `issued_at = now + 1 second` (just-future, within clock-skew tolerance window if any) is accepted. *Pre-registered policy: V3 implements zero-tolerance — any future `issued_at` blocks. No skew window.*

**H8.** A DecisionRecord with `issued_at = now - 1 hour` (legitimate past) is rejected by the new check. (Regression: this must continue to pass once expiry is also valid.)

**H9.** A DecisionRecord with `issued_at` field missing or non-ISO is silently treated as 0 / epoch / now.

### Audit chain integrity (H10–H15)

**H10.** A post-hoc edit of one historical audit field (e.g., flipping `outcome` from `BLOCKED` to `ALLOWED`) survives the chain-verification routine.

**H11.** Truncating the audit log to remove the last N entries is undetectable: chain-verification reports OK on the truncated file.

**H12.** Inserting a forged entry between two real entries is undetectable: chain-verification reports OK.

**H13.** Reordering two adjacent entries is undetectable.

**H14.** Duplicating an entry (appending a copy) is undetectable.

**H15.** A real, untampered audit log fails verification, producing a false-positive corruption alarm.

### Crash recovery (H16–H20)

The V3 design choice is **ledger-first ordering**: write the nonce to the durable ledger (with fsync) before the state mutation. The trade-off is explicit and pre-registered:

- Crash after ledger-write, before mutation → nonce is locked, mutation never occurred. Recovery: operator must issue a new DecisionRecord with a new nonce. State is unchanged. **Conservative loss of one operation, no partial state.**
- Crash after mutation, before audit-write → state is mutated, audit missing. Detectable via audit-vs-state divergence at restart.

**H16.** After a simulated crash between ledger-write and `apply_mutation`, the post-restart state shows the mutation applied. (Falsified expectation: state must be unchanged.)

**H17.** After a simulated crash between `apply_mutation` and the audit-write, the audit log shows no record of the mutation, and there is no detectable divergence flag at restart. (Falsified expectation: audit-vs-state divergence must be detectable by a defined procedure.)

**H18.** A legitimate retry (new DecisionRecord, new nonce, same action+object) after an H16-style crash is also blocked by an unrelated defensive check.

**H19.** The recovery procedure (a defined function `verify_consistency()`) cannot return a deterministic verdict (`CONSISTENT` / `STATE_AHEAD` / `LEDGER_AHEAD`). It returns inconsistent results across calls on the same files.

**H20.** Concurrent calls to `verify_consistency()` corrupt the ledger or audit files.

---

## Battery design principles (carried from V1/V2)

1. Tests are written to attempt the failure, not to confirm the fix.
2. No test rescues another. Each test starts with a clean state, ledger, and audit log.
3. Every test states the failure mode it targets.
4. **No silent fixes.** If a test reveals a real failure, it is recorded here, in `RESULTS_v3.md`, and in test output before any patch is applied.
5. Property-based fuzzing where useful, with explicit trial counts.
6. After each fix, V1/V2 tests must continue to pass without modification. Any required adjustment is documented in the test docstring, not silently rewritten.

---

## Battery contents (planned)

| ID | Target | Method |
|----|--------|--------|
| C01 | H1 | Construct gate A, consume nonce, construct gate B against same ledger, replay nonce. Expect `NONCE_REPLAYED`. |
| C02 | H1 | Property fuzz, 100 trials: random nonce, random restart point, replay always blocked. |
| C03 | H2 | Truncate `nonce_ledger.jsonl` mid-line, construct gate, expect either fail-closed or recoverable rebuild with explicit log entry. |
| C04 | H2 | Replace ledger with garbage bytes, expect fail-closed at construction. |
| C05 | H3 | Two threads × same nonce against shared ledger file, expect at most one ALLOW. |
| C06 | H4 | Whitespace, case, hex-prefix, type-confusion variants of a consumed nonce, all rejected. |
| C07 | H5 | Inject ledger entry not present in audit, run reconciliation, expect divergence flag. |
| C08 | H6 | DecisionRecord with `issued_at = now + 1 day`. Expect `ISSUED_AT_IN_FUTURE`. |
| C09 | H7 | `issued_at = now + 1 second`. Expect `ISSUED_AT_IN_FUTURE` (zero tolerance). |
| C10 | H8 | `issued_at = now - 1 hour`, `expires_at = now + 1 hour`. Expect ALLOW (regression). |
| C11 | H9 | `issued_at` missing or malformed. Expect explicit reject, not silent epoch. |
| C12 | H10 | Pre-write valid chain, edit one historical `outcome` field, run `verify_chain()`, expect FAIL with specific entry index. |
| C13 | H11 | Truncate last 2 of 5 entries, expect chain still verifies up to truncation but `verify_chain` reports `length=3` and a head-hash that does not match an externally-stored anchor. |
| C14 | H12 | Insert forged entry between two real entries, expect FAIL at the inserted index. |
| C15 | H13 | Swap two adjacent entries, expect FAIL. |
| C16 | H14 | Duplicate the last entry, expect FAIL. |
| C17 | H15 | Run untouched chain through `verify_chain`, expect PASS. |
| C18 | H15 | Property fuzz, 50 trials: build chain of 1..20 random entries, verify always PASS. |
| C19 | H16 | Simulate crash between ledger-write and mutation by patching `state_store.apply_mutation` to raise. Verify ledger contains nonce, state unchanged, audit records `CRASH_BEFORE_MUTATION`. |
| C20 | H17 | Simulate crash between mutation and audit-write by patching audit.append after mutation. On restart, `verify_consistency()` returns `STATE_AHEAD` with the mutated object identified. |
| C21 | H18 | After C19-style crash, retry with NEW nonce on same action+object. Expect ALLOW (not collateral block). |
| C22 | H19 | `verify_consistency()` called twice on identical files, returns identical verdict. Property: deterministic. |
| C23 | H20 | 8 concurrent threads × `verify_consistency()`, expect no file corruption, all return same verdict. |
| C24 | regression | All V1 + V2 tests pass with V3 fixes in place. |

Total: 23 V3 tests + V1/V2 regression confirmation.

---

## What "passing" means (V3)

The battery **passes** if and only if:
- Every adversarial attempt is correctly blocked, fails closed, or is detected by `verify_chain` / `verify_consistency`
- All 116 V1+V2 passing tests continue to pass
- B07 (V2 skipped) and B22 (V2 skipped) flip to passing under their original pre-registration intents
- No V3 finding is silently fixed before publication

The battery **fails** if any single H-criterion is triggered.

---

## V3 design choices (pre-registered, frozen before code is written)

These are committed in this document so the implementation cannot retro-fit to pass.

1. **Nonce ledger format.** Append-only JSONL at `data/nonce_ledger.jsonl`. Each line: `{"nonce": "...", "decision_id": "...", "consumed_at": "ISO8601"}`. Rebuilds `_used_nonces` set on construction by streaming the file. Corruption (line not parseable, missing required field) raises at construction unless explicit `repair=True` is passed.

2. **Ledger durability.** `os.fsync(fileno)` after each append. Write happens BEFORE `apply_mutation`. If the mutation raises, the nonce remains consumed (lost operation, conservative).

3. **Issued-at policy.** Zero-tolerance future. `now < issued_at` (UTC, `datetime.now(timezone.utc)`) blocks with reason `ISSUED_AT_IN_FUTURE`. No skew window. Missing `issued_at` blocks with `INVALID_ISSUANCE_FORMAT`.

4. **Audit chain.** Each audit entry gains `seq` (monotonic int starting at 0) and `prev_hash` (sha256 of previous entry's canonical JSON, hex string, 64 chars). Genesis entry has `prev_hash = "0" * 64`. Hash is computed over the canonical JSON of the entry **excluding** its own `prev_hash` and `seq` fields — wait, no: hash is over the full previous entry as written, including its `prev_hash` and `seq`. This makes the chain truly linked.

   Canonical form: `json.dumps(entry, sort_keys=True, separators=(",", ":"))`.

   `verify_chain()` returns `(ok: bool, error_index: Optional[int], message: str)`.

5. **Crash recovery procedure.** `verify_consistency(state, ledger, audit)` returns one of:
   - `CONSISTENT`: every nonce in ledger has a matching `outcome=ALLOWED` audit entry; state reflects all such entries.
   - `STATE_AHEAD`: state mutation present without corresponding `ALLOWED` audit entry. Indicates crash between mutation and audit-write.
   - `LEDGER_AHEAD`: nonce in ledger without corresponding `ALLOWED` audit entry. Indicates crash between ledger-write and mutation. Operator-resolvable via new DecisionRecord.
   - Multiple discrepancies → list of all.

6. **No silent state mutation.** Recovery does not mutate state, ledger, or audit. It reports only.

---

## Order of operations (strict)

1. Commit this pre-registration to public repo (this commit).
2. Implement V3 fixes in `src/`:
   - New: `src/nonce_ledger.py`
   - Modify: `src/gate.py` — accept ledger, add issued_at check, change ordering
   - Modify: `src/audit.py` — add seq + prev_hash, add `verify_chain()`
   - New: `src/recovery.py` — `verify_consistency()`
3. Implement V3 tests in `tests/test_adversarial_battery_v3.py`.
4. Run full suite. Document results, including any failures, in `RESULTS_v3.md`.
5. Commit V3 fixes + battery + results in transparent commits.

If a real failure surfaces, it is recorded in `RESULTS_v3.md` before any patch is applied to make the test pass.

---

**This document is committed before any V3 source change or V3 test is written.**
