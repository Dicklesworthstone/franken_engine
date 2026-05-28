# ECMA-262 ES2020 — `SHOULD`-clause Coverage

> Closes audit finding **FIND-14** (`bd-ctbqv`).
>
> Sibling docs:
> - Spec pin: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md)
> - Aggregate coverage: [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md)
> - Per-clause traceability: [`docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md)

This document carves the `SHOULD`-clause coverage out of the global
matrix so a reviewer can answer **"which ES2020 `SHOULD` clauses does
FrankenEngine currently exercise?"** without scrolling past 90+ `MUST`
rows.

## Why `SHOULD` is tracked separately

ECMA-262 distinguishes two requirement levels (RFC 2119 style):

- A **`MUST`** clause is part of conformance. Failing a tested `MUST`
  case is a compliance failure; the `0.95` promotion gate codified in
  [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md#compliance-threshold)
  is `MUST`-only.
- A **`SHOULD`** clause names a behaviour the implementation **ought**
  to exhibit. A failing `SHOULD` is a documented deviation, not an
  outright violation. Engines routinely diverge here (Annex B web-compat
  quirks, performance-sensitive choices, error-message wording).

If `SHOULD` cases are buried inside the same scoreboard row as `MUST`
cases, the aggregate score either over-weights `SHOULD`s (making MUST
debt invisible) or buries `SHOULD` debt (making coverage gaps invisible).
The audit's `MUST`-coverage figure (`0.67` against the `0.95`
threshold) intentionally excludes `SHOULD`s; this document is the home
for the residual.

## Budget vs current coverage

| Field | Value |
| --- | ---: |
| Total ES2020 `SHOULD` clauses (audit estimate) | **423** |
| Tagged `SHOULD` test cases in this tree | **10** (raw enum/string scan) |
| Coverage ratio | **≈ 2.4 %** |

The audit puts the ratio at `≈ 3.5 %`. The 1-point gap between the
audit number and the in-tree scan is consistent with the field-name
drift documented under FIND-12 (`bd-cd0px`): the scan looks for
`requirement_level: RequirementLevel::Should` or the string `"SHOULD"`
literal, but the strict_mode and runner harnesses use neither.

There is **no near-term ramp target** for `SHOULD` coverage — it
intentionally sits below `MUST`. The point of this document is to make
the residual countable and to keep `SHOULD` gaps from masquerading as
`MUST` debt.

## Current `SHOULD` cases (by §-section)

| §-section | Harness | Test id | Notes |
| --- | --- | --- | --- |
| §11.8.6 (Template literal lexical) | `template_literal` | `template-literal-unicode-escape` | Unicode-escape `SHOULD` rendering inside template parts. |
| §12.2.9 (TemplateLiteral semantics) | `template_literal` | `template-literal-nested` | Nested template substitution — `SHOULD` rather than `MUST` because the spec leaves the optimiser hands free. |
| §12.3.2.1 (OptionalExpression) | `optional_chaining` | `ES2020-12.3.2.1-symbol-property` | Symbol-keyed optional access — the **only** `SHOULD` outside the iteration / template surfaces. |
| §13.2.6 (for-of) | `iteration_statements` | `for-of-iterator-throw-handling` | Iterator-throw cleanup path is `SHOULD`-tier. |
| §13.2.6 (for-of) | `iteration_statements` | `for-of-array-iterator-simple` | Specialised array iterator fast-path. |
| §13.2.6 (for-of) | `iteration_statements` | `for-of-destructuring-defaults` | Destructuring with defaults — `SHOULD` because default evaluation order is observable but not load-bearing. |
| §13.2.6 (for-of) | `iteration_statements` | `for-of-destructuring-rest` | Destructuring with rest. |
| §13.2.6 (for-of) | `iteration_statements` | *(id unresolved by extractor)* | Likely paired with one of the above — field-name drift (FIND-12). |
| §13.12 (break) | `iteration_statements` | `labeled-break-statement` | Labelled break is `SHOULD` per ES2020 §13.12 production rules. |
| §13.13 (continue) | `iteration_statements` | `labeled-continue-statement` | Labelled continue. |

## High-density `SHOULD` surfaces still untouched

The 10 cases above are concentrated on three §-sections. The audit
flagged the following `SHOULD`-heavy surfaces as currently **dark**:

| Surface | `SHOULD` debt (qualitative) | Tracking |
| --- | --- | --- |
| §12.4 / §12.5 (Postfix / unary expression evaluation order) | Engines `SHOULD` short-circuit per ABNF order. No tests. | none yet |
| §13.7.5 (for-of completion) | Iterator close on abrupt completion is `SHOULD`. No tests. | overlaps with `bd-bg9l1.27` |
| §25.6.5 (Promise chaining order) | Microtask ordering between adjacent `.then` chains is `SHOULD`. Only `MUST` covered. | overlaps with `bd-hjfj1` (FIND-21) |
| Annex B realm extensions | Out of scope per the spec-pin doc; included here only to flag that audit findings outside the §-tree are routinely classified as `SHOULD` upstream. | covered by FIND-4 `bd-w50mz` |

A formal queue for ramping `SHOULD` coverage **is not** opened here —
the audit consensus is to ship `MUST` coverage to 0.95 (FIND-3
`bd-u2n6w`) first, then revisit `SHOULD` density per surface.

## Recording new `SHOULD` cases

Add to the matrix above when:

1. A new test case lands with `requirement_level: RequirementLevel::Should`
   (or the legacy string-tag form `"SHOULD"`).
2. An existing case is downgraded from `MUST` to `SHOULD` because spec
   review confirmed the behavior is implementation-defined — record the
   downgrade reason inline.

The extractor in [`SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md#how-this-matrix-is-generated)
re-counts both forms; pasting its `SHOULD` output here is the canonical
update step until FIND-20 (`bd-13rib`) ships a real generator.

## Cross-references

- Audit epic: [`bd-85qfs`](../../#) — Conformance test harness audit.
- Aggregate `MUST` deficit ramping to 0.95: `bd-u2n6w` (FIND-3).
- Field-name drift confirmation: `bd-cd0px` (FIND-12).
- `strict_mode` empty tags (which also obscures `SHOULD` counts there):
  `bd-s2ubw` (FIND-15).
- Iterator-protocol `SHOULD` surfaces awaiting tests: `bd-bg9l1.27`.
- Promise rejection-path `SHOULD` surfaces: `bd-hjfj1` (FIND-21).
