# ECMA-262 Conformance Target

> Closes audit finding **FIND-1** (`bd-5kg0h`) — the top-level spec-target
> document that pins the ECMA-262 edition FrankenEngine claims to implement.

## Spec pin

| Field | Value |
| --- | --- |
| Specification | ECMA-262 |
| Edition | **11th edition** |
| Profile name | **ES2020** |
| Publication date | June 2020 |
| Canonical URL | https://262.ecma-international.org/11.0/ |
| Authoritative artifact (PDF) | https://262.ecma-international.org/11.0/ECMA-262_11th_edition_june_2020.pdf |

FrankenEngine targets this exact edition. Newer-edition behavior (ES2021+)
that is not also present in ES2020 is **out of scope** unless an explicit
RFC promotes it; an unintended ES2021+-specific behavior is a divergence
to be either backed out or recorded under [Divergences](#divergences).

## Test262 fixture pin

| Field | Value |
| --- | --- |
| Source repo | `tc39/test262` |
| Commit | `d0c1b4555b03dd404873fd6422a4b5da00136500` |
| Pin file | [`crates/franken-engine/tests/test262_conformance_pins.toml`](../crates/franken-engine/tests/test262_conformance_pins.toml) |
| Pin file schema | `franken-engine.test262-pin.v1` |

The pin file is the load-bearing source of truth for harness vendoring.
Bumping the commit is **not** a routine action: it requires updating this
document, recording the change under [Fixture refresh policy](#fixture-refresh-policy),
and a full re-bake of the conformance scorecard.

## Scope

### In scope

- **ES2020 baseline syntax + runtime semantics** for the language proper.
- All harness suites listed below under [Coverage surface](#coverage-surface)
  must keep their per-fixture verdicts aligned with the spec edition above.
- Optional production grammars (`Annex B.3`) **only** where the parser already
  emits them with the `runtime-literal` class — see
  `crates/franken-engine/src/parser.rs:1652` (`es2020_clause: "ECMA-262
  Annex B / runtime literal"`).

### Out of scope

- **ECMA-402** (Internationalization API). The pass-rate report at
  [`docs/test262_compatibility_pass_rate_v1.json`](./test262_compatibility_pass_rate_v1.json)
  explicitly excludes ECMA-402 vectors; this exclusion is intentional and
  permanent for the ES2020 profile.
- **Post-ES2020 proposals.** Includes (but is not limited to): class fields
  beyond what ES2020 specifies, top-level `await` outside the modules
  profile already covered, `WeakRefs` finalizers, error cause, `at()` on
  indexed collections, top-level `String.prototype.replaceAll`, etc.
- **Annex B web-compatibility realm extensions** outside the parser's
  `runtime-literal` class (e.g., `String.prototype.substr` quirks beyond
  the canonical surface, sloppy-mode-only legacy octals beyond the
  numeric-literal grammar that the parser already accepts).
- **Host APIs** the spec leaves to host environments (DOM, Web Workers,
  Node-flavored globals, etc.).

A divergence that lands outside both lists is a bug to fix or a row to
add under [Divergences](#divergences).

## Coverage surface

The harnesses below are the load-bearing per-feature conformance
oracles. Each harness file pins fixtures, applies the verdict comparator,
and feeds the aggregate scorecard in
[`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`](../crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md).

| Harness file (under `crates/franken-engine/tests/`) | Spec area |
| --- | --- |
| `abstract_operations_test262_conformance.rs` | §7 Abstract Operations |
| `arrow_function_test262_conformance.rs` | §14.2 ArrowFunction |
| `async_promise_test262_conformance.rs` | §27.1 / §27.7 Promises + async |
| `destructuring_binding_test262_conformance.rs` | §13.3 / §14.1 Destructuring binding patterns |
| `iteration_statements_test262_conformance.rs` | §13.7 IterationStatement (`for`, `for-of`, `while`, …) |
| `iterator_protocol_test262_conformance.rs` | §7.4 / §27.1 Iterator protocol |
| `optional_chaining_test262_conformance.rs` | §12.3.10 OptionalExpression (ES2020 addition) |
| `strict_mode_test262_conformance.rs` | §10.2.1 / Strict Mode Code |
| `template_literal_test262_conformance.rs` | §12.2.9 TemplateLiteral |
| `test262_conformance_runner_integration.rs` | Runner-level integration coverage |
| `test262_runner_conformance_golden.rs` | Runner output golden (regression pin) |

## Compliance threshold

ECMA-262 compliance is binary at the `MUST`-clause level: every testable
`MUST` clause must have an explicit verdict (`pass`, `fail`, or
documented `divergence`).

- **Promotion threshold:** aggregate `MUST`-clause pass rate **≥ 0.95**.
- **Current baseline-builtins score:** **0.67** (147/1847 tested, 124
  passing; see `CONFORMANCE_HARNESS_MANIFEST.md` row "ECMAScript baseline
  builtins"). Tracked as `bd-u2n6w` (FIND-3) and not closed by this
  document.

Anything below the threshold is documented as *partial compatibility*,
not *conformance*.

## Divergences

Currently **no** documented intentional divergences from the ES2020 spec
edition. As intentional divergences are accepted, they are recorded in a
sibling `DISCREPANCIES.md` (tracked by `bd-w50mz` / FIND-4). Until that
document lands, every divergence MUST be filed as a bug against the
relevant harness.

## Fixture refresh policy

The test262 commit pin (`d0c1b4555b03dd404873fd6422a4b5da00136500`) is
held until one of:

1. The ES2020 profile vendored from `tc39/test262` receives a correctness
   fix that the harnesses materially exercise.
2. The pin is bit-rotted by a coordinated upstream rebase.

Bumping the pin requires:

- Updating both this document and
  `crates/franken-engine/tests/test262_conformance_pins.toml`.
- Re-baking every harness's golden artifacts under one commit so the
  diff is reviewable.
- Re-baselining `CONFORMANCE_HARNESS_MANIFEST.md` row "ECMAScript baseline
  builtins" with the new tested/passing counts.

A full fixture-refresh GUIDE is tracked under `bd-rpimp` (FIND-23).

## Cross-references

- [`crates/franken-engine/tests/test262_conformance_pins.toml`](../crates/franken-engine/tests/test262_conformance_pins.toml) — load-bearing pin file (schema `franken-engine.test262-pin.v1`).
- [`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`](../crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md) — per-harness manifest, current scorecard.
- [`docs/test262_compatibility_pass_rate_v1.json`](./test262_compatibility_pass_rate_v1.json) — machine-readable scorecard snapshot (records the ECMA-402 + post-ES2020 exclusions).

## Audit lineage

- Filed by: `bd-85qfs` (Conformance test harness audit, ScarletJay).
- Concrete finding: `bd-5kg0h` (FIND-1) — closed by this document.
- Sibling: `bd-d9ot3` (FIND-18) — *No top-level conformance-targets
  document defining edition + scope (Annex B, ECMA-402 in/out)* — this
  document also addresses the scope questions there; FIND-18 may be
  closed jointly once a reviewer signs off on the Annex B / ECMA-402
  language above.
