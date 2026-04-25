# PRE_REGISTRATION_v2 — Adversarial Test Battery (Surfaces V1 Excluded)

**Date pre-registered:** 2026-04-25
**Status:** WRITTEN BEFORE V2 TESTS RUN
**Repo state at registration:** `main` branch after commit `19dda05` (V1 battery published).
**Predecessor:** `PRE_REGISTRATION_v1.md` and `RESULTS_v1.md`.

This document is committed before any V2 test is implemented or run.
If any test in the V2 battery succeeds in producing the failure modes listed below, the corresponding criterion is falsified. Failures will be published in this repository, in `RESULTS_v2.md`, and in the test output. **Failures will not be silently fixed before publication.**

---

## What V2 attacks

V1 explicitly excluded several attack surfaces. V2 attacks them.

| V1 exclusion | V2 attack target |
|--------------|-----------------|
| Persistence of nonces across process restart | G6, G7 |
| Concurrency safety beyond single-threaded | G8, G9, G10 |
| HTTP-level attacks against FastAPI | G11, G12, G13, G14 |
| Persistence corruption (state file, audit log) | G1, G2, G3, G4, G5 |
| Audit log truncation / replay | G15, G16 |
| FINDING_A20 (entry guard prose heuristic) | A20_FIX verification |

---

## Claim under test (V2)

**The pipeline `entry_guard → commit_gate → state_store` enforces the invariant `no valid DecisionRecord → no state mutation` under:**

1. **Persistence corruption** — a tampered state file or audit log must not enable a bypass that reaches mutation.
2. **Process restart** — nonces consumed in one process must not be replayable in a successor process if a durable nonce ledger is enabled.
3. **Concurrency** — parallel calls with the same nonce must produce exactly one mutation, not multiple.
4. **HTTP layer** — malformed bodies, oversized payloads, header injection, and method confusion must not enable a bypass.

This claim is narrower than V1's. V1 already established: hostile input, hostile timing, hostile encoding, hostile state. V2 establishes: hostile filesystem, hostile process boundary, hostile concurrency, hostile network surface.

---

## Falsification criteria (G1–G20)

The claim is **falsified** if any of the following occurs:

### Persistence integrity (G1–G5)

**G1.** A pre-existing corrupted state file enables a request to mutate state into an attacker-chosen invariant-violating shape (e.g., flipping `"deleted": true` directly via file edit and then having the gate "confirm" it as legitimate).

**G2.** A truncated state file (incomplete JSON) causes the gate to silently treat it as valid and allow a mutation that should have failed.

**G3.** A symlink or path-traversal attack on `state.json` allows writes outside the intended directory.

**G4.** A pre-existing tampered audit log entry causes a real ALLOW to be reported as BLOCKED, or vice versa, downstream.

**G5.** Removing or replacing `audit.jsonl` between calls makes a successful mutation indistinguishable from no-mutation in subsequent inspection.

### Restart / nonce persistence (G6–G7)

**G6.** A nonce consumed in process A is replayable in process B (a successor process), producing two mutations from one DecisionRecord. *Note: V1 documented this as a known gap; V2 must confirm it and either fix it or formally accept it.*

**G7.** Even with a durable nonce ledger enabled, a crash between mutation and nonce-consume produces the inverse failure: a nonce-consumed record that was never actually applied to state, locking out a legitimate retry.

### Concurrency (G8–G10)

**G8.** N parallel threads (N ≥ 8) submit the same nonce. Result: more than one mutation occurs.

**G9.** Two parallel threads submit different valid records targeting the same object. Result: state corruption (lost write, interleaved fields, or audit log entries out of order with mutations).

**G10.** Audit log entries appear in the file before the corresponding mutation completes (or vice versa), producing an audit log that doesn't reflect actual mutation order.

### HTTP layer (G11–G14)

**G11.** An HTTP request with malformed JSON body, oversized payload, or unexpected content-type produces a successful mutation.

**G12.** An HTTP request with method override (`X-HTTP-Method-Override`, querystring `_method=DELETE`) reaches mutation when it should not.

**G13.** Path traversal in URL or object_id field reaches the state file.

**G14.** Header injection (CRLF, null byte) in any field smuggles a second request.

### Audit integrity (G15–G16)

**G15.** Audit log can be truncated or rotated mid-run without producing a discontinuity warning.

**G16.** Audit entries can be replayed (same content appended twice) and the discrepancy is undetectable.

### Time-based attacks (G17–G18)

**G17.** Manipulating system time backward between issuance and verification (clock-skew attack) extends a record's validity beyond its `expires_at`.

**G18.** Issued-at-in-the-future records (`issued_at > now`) produce a successful mutation. (V1 did not explicitly test this.)

### FINDING_A20 fix verification (G19–G20)

**G19.** After implementing the predicate registry fix, a packet with `test = "subjective_review"` (prose-shaped identifier not in the registry) must be rejected by the entry guard.

**G20.** After the fix, the legitimate predicate `test = "window_active"` (which IS in the registry) must continue to be accepted, and no v1 test regresses.

---

## Battery design principles (carried from V1)

1. Tests are written to attempt the failure, not to confirm the fix.
2. No test rescues another. Each starts from a clean state and clean ledger.
3. Every test states the failure mode it targets.
4. **No silent fixes.** If a test reveals a real failure, it is recorded here, in `RESULTS_v2.md`, and in test output before any patch is applied.
5. Property-based fuzzing where useful, with explicit trial counts.

---

## Battery contents (planned)

| ID | Target | Method |
|----|--------|--------|
| B01 | G1 | Pre-corrupt state.json with attacker-chosen invariant violation, run gate |
| B02 | G2 | Truncate state.json mid-JSON, run gate, assert it fails closed |
| B03 | G3 | Symlink state.json target outside repo dir, attempt mutation |
| B04 | G3 | object_id contains `../../../etc/passwd`-style traversal |
| B05 | G4 | Pre-tamper audit.jsonl, run gate, confirm new audit entries are still correct |
| B06 | G5 | Delete audit.jsonl between mutations, confirm gate either recreates or fails |
| B07 | G6 | Construct two CommitGate instances (simulating restart), replay nonce in second |
| B08 | G7 | Crash simulation: mutate succeeds, nonce-consume fails. Detect the inconsistency. |
| B09 | G8 | 16 threads, same nonce, count mutations |
| B10 | G9 | 16 threads, distinct valid records targeting same object |
| B11 | G10 | Audit ordering check: all entries timestamped before/after mutation atomically |
| B12 | G11 | HTTP POST with `Content-Type: text/plain`, JSON-shaped body |
| B13 | G11 | HTTP POST with 10MB body |
| B14 | G11 | HTTP POST with body containing nested arrays of depth 1000 |
| B15 | G12 | HTTP GET with `_method=POST` querystring |
| B16 | G13 | Path traversal in URL: `/execute/../state` |
| B17 | G13 | object_id field contains traversal |
| B18 | G14 | CRLF injection in actor_id |
| B19 | G15 | Truncate audit.jsonl mid-run, verify discontinuity flag |
| B20 | G16 | Append duplicate audit entry, verify detection |
| B21 | G17 | Mock `datetime.now()` to roll back, attempt expired record |
| B22 | G18 | issued_at = now + 1 day, expires_at = now + 2 days. Should block. |
| B23 | G19 | After fix: `test = "subjective_review"` blocked |
| B24 | G19 | After fix: `test = "feels_right"` blocked |
| B25 | G19 | After fix: `test = "looks_ok_to_me"` blocked |
| B26 | G20 | After fix: `test = "window_active"` accepted |
| B27 | G20 | After fix: `test = "inventory_below_threshold"` accepted |
| B28 | G20 | All V1 tests still pass after fix |

Total: 28 V2 tests + V1 regression confirmation.

---

## What "passing" means (V2)

The battery **passes** if and only if:
- Every adversarial attempt is correctly blocked or fails closed
- State and audit are unchanged or auditable after every blocked attempt
- All 89 V1 tests continue to pass
- After the FINDING_A20 fix, A20 (which is currently `xfail`) flips to `pass`

The battery **fails** if any single adversarial test produces a real failure mode.

---

## Order of operations (strict)

1. Commit this pre-registration to public repo
2. Implement V2 tests
3. Implement FINDING_A20 fix (predicate registry)
4. Run full suite
5. Document all results, including any failures, in `RESULTS_v2.md`
6. Commit V2 battery + fix + results in a single transparent commit

If a real failure surfaces, it is recorded before any patch is applied to make the test pass.

---

**This document is committed before any V2 test is written or run.**
