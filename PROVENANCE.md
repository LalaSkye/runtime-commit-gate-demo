# Provenance

## Authorship

This repository was independently authored by **Ricky Dean Jones**.

- **Organisation:** Os-Trilogy LMT
- **GitHub:** github.com/LalaSkye
- **Date of first commit:** 2026-03-28

## Identity Binding

The author is the sole originator of all architecture, code, specifications,
and documentation in this repository. No external framework, codebase, or
third-party intellectual property was used in the design or implementation
of this system.

## Architectural Lineage

This repository implements a runtime commit boundary — a discrete,
deterministic, fail-closed gate that enforces the invariant:

**No valid decision record -> no state mutation.**

The design lineage traces to the author's prior published work:

| Repository | Created | Relationship |
|---|---|---|
| `LalaSkye/invariant-lock` | 2026-02-16 | Version-locked invariant enforcement |
| `LalaSkye/stop-machine` | 2026-02-16 | Deterministic state controller |
| `LalaSkye/constraint-workshop` | 2026-02-16 | Constraint primitives |
| `LalaSkye/execution-boundary-lab` | 2026-02-18 | Gate interface and contamination cases |
| `LalaSkye/start-here` | 2026-03-25 | Canonical governance demo |

All dates are GitHub-recorded creation timestamps (UTC), immutable and
independently verifiable.

## Intellectual Property Declaration

All content in this repository is original work.

- No code was derived from, copied from, or based on any third-party
  governance framework, architecture, or codebase.
- No licensing agreement, collaboration binding, or IP transfer has been
  entered into with any third party in relation to this work.
- The architectural approach (discrete admissibility gates, fail-closed
  evaluation, proof-carrying decision records) is structurally distinct
  from continuous-dynamics, spectral, or manifold-based governance approaches.

## Copyright

Copyright (c) 2026 Ricky Dean Jones / Os-Trilogy LMT. All rights reserved.

The code in this repository is released under the MIT licence.
The authorship, provenance, and IP declarations in this document are
asserted regardless of licence terms.
