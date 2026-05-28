# ECMA-262 ES2020 — `MUST`-Clause Coverage Remediation Roadmap

> Closes audit finding **FIND-3** (`bd-u2n6w`). Sibling docs:
> [`ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md) (shape-of-current matrix),
> [`SHOULD_COVERAGE.md`](./SHOULD_COVERAGE.md) (paired surface),
> [`SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md) (spec→test map),
> [`CI_SCOREBOARD.md`](./CI_SCOREBOARD.md) (gate scoreboard contract), and
> the manifest scorecard at
> [`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`](../../crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md).

## Why this document exists

The conformance manifest declares a **promotion threshold of `≥ 0.95`**
on aggregate `MUST`-clause pass rate (manifest §"Compliance Scorecard").
The same scorecard row for *ECMAScript baseline builtins* records a
current score of **`0.67`** alongside `Tested = 147`, `Passing = 124`,
`Divergent = 23` against `MUST clauses = 1847`. Two facts follow:

1. The **score itself is opaque.** `124 / 1847 = 0.0671` (passing /
   total) and `124 / 147 = 0.843` (passing / tested) are the natural
   ratios from the column values, and neither is `0.67`. The `0.67`
   figure in the manifest is hand-maintained and not derivable from the
   column inputs; until the compliance-report generator (`bd-13rib`
   FIND-20) lands, no recomputation pipeline exists to surface drift
   between the recorded score and the actual harness output.
2. The **coverage shape is the dominant gap**, not the test pass rate.
   At HEAD only 147 of 1847 MUST clauses (~7.96%) have any tagged
   conformance test in the franken-engine ES2020 harness suite. Closing
   the 0.95 threshold means landing on the order of **`+1623`** new
   `MUST`-tagged cases (1847 × 0.95 − 124 passing today, assuming the
   newly-added cases match the present 124/147 ≈ 84% pass rate).

This roadmap exists so that future agents (and reviewers) can answer
"what does closing FIND-3 actually mean" without re-deriving the gap
from first principles. It is **not** a commitment to ship 1623 tests in
one wave — it is a phased decomposition that names the buckets, names
the tracked beads, and pins the empirical numerator/denominator at the
moment of writing.

## Coverage budget at HEAD (2026-05-28)

`MUST`-tag counts are taken from a `grep` of
`requirement_level: RequirementLevel::Must` (and the legacy `"MUST"`
string-literal form — see FIND-12 `bd-cd0px`) across the
`crates/franken-engine/tests/*_conformance.rs` harness files.

| Harness file (under `crates/franken-engine/tests/`) | Spec area | `MUST` tags at HEAD |
| --- | --- | ---: |
| `iteration_statements_test262_conformance.rs` | §13.7 IterationStatement | 28 |
| `async_promise_test262_conformance.rs` | §25.4 / §27 Promise + AsyncFunction | 22 |
| `arrow_function_test262_conformance.rs` | §14.2 ArrowFunction | 21 |
| `optional_chaining_test262_conformance.rs` | §12.3.10 OptionalExpression | 17 |
| `template_literal_test262_conformance.rs` | §12.2.9 TemplateLiteral | 14 |
| `destructuring_binding_test262_conformance.rs` | §13.3 / §14.1 Destructuring | 12 |
| `abstract_operations_test262_conformance.rs` | §7 Abstract Operations | 12 |
| `module_import_export_grammar_conformance.rs` | §15.2 Modules | 11 |
| `iterator_protocol_test262_conformance.rs` | §7.4 / §27.1 Iterator | 10 |
| `strict_mode_test262_conformance.rs` | §10.2.1 Strict Mode | 0 (FIND-15 `bd-s2ubw`) |
| **Total tagged `MUST` tests at HEAD** | | **147** |

Manifest counts (`MUST clauses = 1847`, `SHOULD clauses = 423`) are
copied from the upstream ECMA-262 ES2020 spec-clause inventory and are
**not** recomputed here. Refreshing the denominator is part of the
compliance-report generator scope (`bd-13rib` FIND-20).

## Threshold semantics — what `≥ 0.95` actually means

The manifest's promotion threshold is a *single* aggregate number, but
the underlying spec surface is wildly uneven (some §-clauses have one
`MUST`, others have dozens). Two interpretations are operationally
distinct, and the manifest does not currently pin which one is binding:

- **Interpretation A — Coverage threshold.** `≥ 0.95` means
  `tagged_must_tests / total_must_clauses ≥ 0.95`. Today: `147 / 1847 =
  0.0796`. Closing the gap requires **+1608** new tagged tests
  (`ceil(1847 × 0.95) − 147 = 1608`).
- **Interpretation B — Pass-rate threshold.** `≥ 0.95` means
  `passing / tagged_must_tests ≥ 0.95`. Today: `124 / 147 = 0.8435`.
  Closing the gap requires resolving **≥ 16** currently-failing tagged
  MUSTs (`ceil(147 × 0.95) − 124 = 16`).

Interpretation B is hollow on its own — a harness can trivially keep its
pass rate above any threshold by refusing to tag risky tests. The
honest reading is "both A and B must hold simultaneously": coverage
must be near-total, and the tagged set must pass. This roadmap treats
the joint reading as the binding gate.

Until the compliance-report generator (`bd-13rib`) materialises a single
authoritative score, **this document is the place that names the joint
gate explicitly**.

## Per-spec-area remediation buckets

Each bucket lists the §-clause range, the current per-harness tagged
count, the existing tracked beads for engine-side gaps, and the rough
phased target the bucket carries.

### §7 — Abstract Operations (12 tagged today)

`abstract_operations_test262_conformance.rs` exercises ToNumber,
ToString, ToObject, ToPrimitive, OrdinaryHasInstance, and friends. §7
enumerates dozens of MUST clauses spread across `7.1.{1..18}` (type
conversion) and `7.2.{1..15}` (test/compare) and `7.3.{1..28}` (object
internals) and `7.4.{1..9}` (iterator/async-iterator). A complete
surface saturation is approximately **`+85`** new tagged tests to cover
every `MUST` clause in §7 (denominator estimate from clause-by-clause
walk of TC39 ES2020 Edition-11 §7).

Tracked engine-side gaps: none open at HEAD beyond the harness-tagging
gap itself.

### §10.2.1 — Strict Mode Code (0 tagged today)

`strict_mode_test262_conformance.rs` has **0 tagged** clauses (FIND-15
`bd-s2ubw` — partially closed: `es2020_section` non-empty assertion
landed; full `requirement_level` tagging follow-up still open). The
strict-mode surface is small in clause count (~12 enumerated MUSTs in
§10.2.1.1 + the appendix B.3.5 modifications) but high-leverage: every
other harness implicitly depends on strict-mode semantics being
correct.

Tracked: `bd-s2ubw`, follow-up filings under `bd-85qfs`.

### §12.2.9 — TemplateLiteral (14 tagged today)

Positive paths only — error-case tests missing (FIND-8 `bd-t2cgg`).
§12.2.9 has ~24 MUST clauses (cooked vs raw, escape-sequence handling,
tagged-template TV/TRV invariants, NoSubstitution vs head/middle/tail).
Closing the gap: `+10` tagged cases on error paths and edge encodings.

Tracked: `bd-t2cgg`.

### §12.3.10 — OptionalExpression (17 tagged today)

Dense for a single-section feature — covers chain semantics, short-
circuit, and `?.` / `?.[ ]` / `?.( )` interleave. The §12.3.10 surface
has ~22 MUST clauses. Closing the gap: `+5` tagged cases on grammar
ambiguity edges and template-literal-after-optional-chain.

Tracked: none open at HEAD beyond the harness-tagging gap.

### §13.3 / §14.1 — Destructuring binding (12 tagged today)

Light vs the §13.3.{1,2,3} grammar surface. Approximate clause count
~36 MUSTs across BindingPattern, AssignmentPattern, and PropertyName
rules. Closing the gap: `+22` tagged cases including rest-element edge
behaviour and computed property destructuring.

Tracked: none open at HEAD beyond the harness-tagging gap.

### §13.7 — IterationStatement (28 tagged today)

Currently the densest harness. **14 frontier-fail cases** are tracked
under `bd-bg9l1.27` (Symbol.iterator, for-of destructuring, labeled
break/continue, let-TDZ, single-line comments). The §13.7 surface has
~46 MUSTs across DoStatement, WhileStatement, ForStatement,
ForInOfStatement, BreakStatement, ContinueStatement. Closing the gap:
`+15` tagged cases AFTER `bd-bg9l1.27` engine work lands the 14
currently-failing MUSTs.

Tracked: `bd-bg9l1.27`.

### §14.2 — ArrowFunction (21 tagged today)

Tracks both grammar and `[[ThisMode]]` / no-`new` semantics. Error-case
tests are missing (FIND-9 `bd-vj6kn`). The §14.2 surface has ~28 MUSTs
across ArrowFormalParameters, AsyncArrowFunction, `[[ThisMode]] =
lexical` propagation, and `[[ConstructorKind]] = base` exclusion.
Closing the gap: `+10` tagged cases including reject-on-new and
async-arrow edge behaviour.

Tracked: `bd-vj6kn`.

### §15.2 — Modules (11 tagged today)

`module_import_export_grammar_conformance.rs` covers the import/export
grammar surface. §15.2 has ~45 MUSTs across ModuleSpecifier resolution,
HostResolveImportedModule contract, NamedExports/StarExports, and
dynamic import. Closing the gap: `+32` tagged cases including the
ModuleEvaluation step ordering and TDZ-across-modules invariants.

Tracked: none open at HEAD beyond the harness-tagging gap.

### §25.4 / §27 — Promise + AsyncFunction (22 tagged today)

Round-trip present; rejection-path error cases missing (FIND-21
`bd-hjfj1`). §27 has ~60 MUSTs across Promise.{resolve, reject, all,
allSettled, race, any}, the executor invariants, and the AsyncFunction
spec. Closing the gap: `+35` tagged cases including
HostPromiseRejectionTracker and the async iteration protocol.

Note: ES2022 `Promise.any` was accepted as ES2020-divergent (DISC-011,
`bd-w50mz.1`); those cases do not count against the ES2020 MUST
denominator.

Tracked: `bd-hjfj1`.

### §7.4 / §27.1 — Iterator protocol (10 tagged today)

Custom `Symbol.iterator` cases incomplete (`bd-bg9l1.27`). §7.4 has
~30 MUSTs across `GetIterator`, `IteratorNext`, `IteratorClose`, and
the async iterator extension in §27.1. Closing the gap: `+19` tagged
cases.

Tracked: `bd-bg9l1.27`.

### Untagged surface — §8, §9, §11, §16–24, §26, §28+ (0 tagged today)

The majority of the 1847 MUST clauses live in spec areas that **have no
dedicated harness file at HEAD**: §8 (Executable Code / Execution
Contexts), §9 (Ordinary / Exotic Objects), §11 (ECMAScript Language /
Lexical Grammar), §16–24 (Global Object, Number/Math/Date, String,
RegExp, Array, Map/Set/WeakMap/WeakSet/ArrayBuffer/DataView/TypedArray,
JSON), §26 (Reflection), and §28+ (Memory Model). Adding harness
scaffolding for each is the bulk of the `+1608` tagged-test surface
named in *Interpretation A* above.

The prerequisite is a unified `ConformanceTest` trait (FIND-7
`bd-glf1i`) so each new harness does not re-roll its own result enum
and runner glue.

## Phased remediation plan

The plan below sequences buckets by **engine readiness** and
**dependency on already-tracked work**. Each phase ships an
incremental coverage jump and an externally-visible scoreboard
re-baseline.

### Phase 0 — Make the score computable (blocking)

Goal: kill the opaque `0.67` figure. After Phase 0 the manifest's
scorecard row is computed at gate time, not hand-edited.

- Land `bd-13rib` (FIND-20) compliance-report generator binary —
  emits a per-spec-area scoreboard from harness output.
- Land `bd-04uo3` / `bd-euwqz` (FIND-13/25) spec-to-test traceability
  matrix wiring so each test contributes to a known §-clause bucket.
- Land `bd-glf1i` (FIND-7) unified `ConformanceTest` trait so new
  harnesses do not perpetuate the per-harness result-enum drift.
- Land `bd-xkbrm` (FIND-5) drift-detector visibility upgrade so
  `EXPECTED_PASS` does not silently mask coverage loss.

Exit gate: the manifest scorecard row is generated from harness output
on every gate run, and the `MUST coverage` and `MUST pass rate` columns
are independently surfaced (no joint score collapse).

### Phase 1 — Close the bd-bg9l1.27 engine gap

Goal: surface §13.7 + §7.4 / §27.1 iterator-protocol engine support to
the level that the currently-tagged MUSTs flip green.

- Land `bd-bg9l1.27` engine work (Symbol.iterator, for-of
  destructuring, labeled break/continue, let-TDZ, single-line
  comments).
- Tag the 14 frontier cases that flip green into the
  `iteration_statements` and `iterator_protocol` harnesses.

Exit gate: 28 + 10 = 38 tagged MUSTs pass without XFAIL; aggregate
`MUST` pass-rate column rises commensurately.

### Phase 2 — Error-path coverage on existing harnesses

Goal: every existing harness has both positive-path and error-path
tagged cases — error cases are where engine bugs hide today.

- Land `bd-t2cgg` (FIND-8) template literal error cases.
- Land `bd-vj6kn` (FIND-9) arrow function error cases.
- Land `bd-hjfj1` (FIND-21) async/promise rejection-path cases.
- Land `bd-s2ubw` strict-mode harness tagging (the §10.2.1 surface
  has zero tagged MUSTs today).
- Land `bd-rqev5` (FIND-10) round-trip oracle on the remaining six
  harnesses (only three carry one at HEAD).

Exit gate: every harness has at least one error-path MUST. `+~35` net
tagged cases. Phase 2 + Phase 1 combined: target `147 → ~200` tagged
MUSTs.

### Phase 3 — Surface saturation on existing spec areas

Goal: bring each existing harness up to the per-area saturation
estimates listed in *Per-spec-area remediation buckets* above
(Abstract Ops +85, TemplateLiteral +10, OptionalChain +5,
Destructuring +22, ArrowFunction +10, Iterator +19, Promise +35,
IterationStatement +15, Modules +32, StrictMode +12).

Estimated total: `~245` net tagged cases. After Phase 3, tagged total
should be `~200 + 245 = ~445` MUSTs, or **24% of the 1847 budget**.

This phase is engine-impact-light (most cases land additional test
coverage on engine surfaces that already work). Pass rate is the
sensitive metric here, not coverage.

### Phase 4 — Add the missing-harness §-clause buckets

Goal: stand up harnesses for §8, §9, §11, §16–24, §26, §28+ such that
the joint A∧B threshold becomes achievable.

This is the largest single bucket in the roadmap, estimated at
`~+1400` tagged cases distributed across `~14` new harness files. It
should not begin until Phase 0 (computable score) and Phase 1 (engine
gaps) have closed, otherwise every new harness drives the pass-rate
score further down without contributing actionable engine signal.

Exit gate: aggregate `MUST` coverage `≥ 0.95` (Interpretation A).

### Phase 5 — Joint-threshold close-out

Goal: assert `MUST_pass_rate ≥ 0.95` simultaneously with
`MUST_coverage ≥ 0.95`. Any XFAIL set at this point must be backed by
a tracked engine bead and a `DISCREPANCIES.md` entry.

Exit gate: FIND-3 (`bd-u2n6w`) closes; ECMAScript baseline builtins row
in the manifest scorecard reads `Conformance` (not `Partial
conformance`).

## Cross-references — beads that contribute to FIND-3 closure

The roadmap above does not file new beads — it sequences the
already-filed ones. The closure of FIND-3 is the join of these
landings:

| Phase | Bead | Status at this doc's writing |
| --- | --- | --- |
| 0 | `bd-13rib` FIND-20 compliance generator | open |
| 0 | `bd-04uo3` / `bd-euwqz` FIND-13/25 traceability | closed |
| 0 | `bd-glf1i` FIND-7 unified `ConformanceTest` trait | open |
| 0 | `bd-xkbrm` FIND-5 drift detector visibility | open |
| 1 | `bd-bg9l1.27` engine iteration-statement gaps | open |
| 2 | `bd-t2cgg` FIND-8 template error cases | open |
| 2 | `bd-vj6kn` FIND-9 arrow error cases | open |
| 2 | `bd-hjfj1` FIND-21 async/promise error cases | in_progress |
| 2 | `bd-s2ubw` FIND-15 strict_mode tagging | partial |
| 2 | `bd-rqev5` FIND-10 round-trip oracle | in_progress |
| 3 | (per-harness saturation — file as Phase 3 lands) | not yet filed |
| 4 | (per-section new-harness beads — file as Phase 4 lands) | not yet filed |
| 5 | this bead `bd-u2n6w` FIND-3 | closes at Phase 5 exit |

## What this roadmap is NOT

- It is **not** an attempt to recompute the manifest's `0.67` figure
  by hand. The figure is opaque-by-construction (no published
  formula) and the right fix is to retire it in favour of generator-
  computed columns (Phase 0).
- It is **not** a permission to add `MUST`-tagged tests faster than
  the engine can ship green semantics. Adding a tagged test that
  XFAILs without a tracked engine bead is a regression of audit
  hygiene (it makes the drift detector noisier without tightening any
  invariant).
- It is **not** a commitment to a calendar date. ECMA-262 is a moving
  standard; the next ES2020 edition errata cycle can shift the
  denominator under us.

## Update protocol

When a phase exit gate fires:
1. Re-run the per-harness `MUST`-tag grep used to populate the
   *Coverage budget at HEAD* table; update the row counts.
2. Cross-check the new total against the compliance-report generator
   output (once `bd-13rib` lands).
3. Cross-link any newly-filed Phase-3 or Phase-4 beads in the
   *Cross-references* table.
4. When **all** rows in the *Cross-references* table close, file the
   matrix-promotion edit (`bd-u2n6w` closes; manifest scorecard row
   updates to `Conformance`).
