# Contributing

## Principles

- Preserve the invariant: no valid decision record -> no state mutation.
- Prefer small, auditable changes.
- Fail closed on ambiguity.
- No silent fixes: document behaviour changes.

## Before opening a PR

1. Run `python -m pytest tests/ -v`
2. Update docs if semantics changed.
3. Describe threat model or failure mode addressed.
4. Keep scope narrow.

## Good PR examples

- Add tests for a discovered edge case.
- Improve replay resistance.
- Tighten input validation.
- Clarify docs or examples.
