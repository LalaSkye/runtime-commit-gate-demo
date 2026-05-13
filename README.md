# runtime-commit-gate-demo

New to this work? Start here: https://github.com/LalaSkye/start-here

## Public disclosure boundary

This repository is a public inspection surface, not full architecture disclosure.

It shows a bounded claim, a runnable evidence object, an inspection path, and the claim limit.

See [`PUBLIC_DISCLOSURE_BOUNDARY.md`](PUBLIC_DISCLOSURE_BOUNDARY.md).

## Invariant

No valid decision record -> no state mutation on the demonstrated path.

## What this repo shows

A minimal path-local execution-boundary demo.

On the demonstrated path:

- invalid or missing authority blocks execution
- replay is blocked
- scope mismatch is blocked
- expired authority is blocked
- valid authority permits the demonstrated action

No policy engine. No AI. No production claim.

## What this does not prove

This repository does not prove adoption, certification, standardisation, production readiness, path-universal deployment coverage, or non-bypassability outside the demonstrated path.

It demonstrates a bounded execution-control surface that can be run, inspected, and tested at its stated scope.

## Current hardening gap

This repository does not currently claim that durable proof is committed before consequence can bind, or that audit durability forms an atomic precondition to mutation.

## Run

```bash
python demo/run_demo.py
```

Expected result classes:

```text
BLOCKED
ALLOWED
```

## Inspection path

Run the demo and tests:

```bash
python demo/run_demo.py
python -m pytest tests/ -v
```

The narrow question this repo answers is:

**Can the demonstrated mutation path proceed without a valid decision record?**

Expected answer:

**No.**

## What this proves

On the demonstrated path:

- missing decision records block execution
- valid decision records allow the demonstrated action
- replay, scope mismatch, expiry, and invalid input are blocked
- the failure mode can be tested locally

## Scope note

Implementation files are present so the demonstrated path can be run and challenged.

This README does not publish an architecture map, component sequence, orchestration model, or protected system design.

## Provenance

See [PROVENANCE.md](PROVENANCE.md).

## Licence

MIT — see [LICENSE](LICENSE).

---

This repository demonstrates a deterministic control boundary using standard engineering techniques. No proprietary frameworks or external implementations are used.
