# ECMA-262 Intentional Divergences (FrankenEngine)

> **Status:** Initial seed. This document enumerates every intentional FrankenEngine
> divergence from ES2020 ECMA-262. New divergences land here, not in code comments.
>
> **Tracking bead:** bd-w50mz (FIND-4 from the bd-85qfs audit).
> **Upstream target document:** [`crates/franken-engine/ECMA262_CONFORMANCE_TARGETS.md`](../ECMA262_CONFORMANCE_TARGETS.md)

## How to read this file

Each row is a `DISC-NNN` divergence. A divergence is an OBSERVED, INTENTIONAL
gap between FrankenEngine and ES2020 that the project has decided to accept
or defer rather than fix immediately. *Unobserved* gaps go in the audit beads
(bd-85qfs.* family), not here.

| Field | Meaning |
| --- | --- |
| ID | `DISC-NNN`, monotonically increasing |
| Status | `ACCEPTED` (we're keeping the divergence), `INVESTIGATING` (under review), `WILL-FIX` (slated for repair by a tracked bead) |
| ES2020 ref | §-section in ECMA-262 Edition 11 |
| Affected tests | Concrete test case IDs (the `id` field on `Static*TestCase`) that observe this divergence |
| Tracking bead | `bd-*` issue when status is WILL-FIX |
| Review date | Last time this entry was re-evaluated |
| Next review | When it must be re-evaluated again (default: every 90 days for ACCEPTED, 30 days for INVESTIGATING / WILL-FIX) |

When a divergence is closed (the engine is repaired or the spec interpretation
changes), the row stays in this file but flips Status to `RESOLVED` with the
landing commit hash; do not delete rows — preserve the audit trail.

## Discrepancy schema rationale

Each entry includes a `Test verdict expression` field stating *how the affected
test case currently reports*. If a case is silently green (e.g. via an
EXPECTED_PASS exclusion set, or by virtue of not being written at all), this is
itself called out — the goal is to make every divergence visible in machine-readable
test reports, not buried in const sets (see DISC-005 below).

## Active divergences

### DISC-001: Parser rejects `//` line comments in multi-line test sources

- **Status:** WILL-FIX
- **ES2020 ref:** §11.4 (Comments)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-let-tdz`, `break-for-of-early-exit`, `continue-for-of-skip`, `unlabeled-break-continue-error`, `for-of-iterator-throw-handling`
- **Symptom:** The parser's `merge_logical_lines` chokepoint pushes the entire line text into the logical-line buffer *before* the `//` token is detected by the scan loop, so the inline comment survives into `parse_source` and triggers `ParseErrorCode::UnexpectedToken`.
- **Test verdict expression:** Currently invisible — the affected cases are absent from `EXPECTED_PASS` in `tests/iteration_statements_test262_conformance.rs:744`, which means they are silently failing. Cross-reference DISC-005 (the exact-gap drift detector hides this).
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-002: Arrow function `this` semantics may diverge from spec §14.2 in specific class contexts

- **Status:** INVESTIGATING
- **ES2020 ref:** §14.2.16 (Runtime Semantics: Evaluation), §14.2.9 (FunctionDeclarationInstantiation)
- **Affected harnesses:** `tests/arrow_function_test262_conformance.rs`
- **Affected tests:** none confirmed yet — see fix-direction in bd-vj6kn
- **Symptom:** The arrow-function harness has no error-case tests (FIND-9 / bd-vj6kn). Until the negative cases are added, we cannot verify the spec divergence empirically; this DISC entry is a placeholder for the investigation.
- **Tracking bead:** bd-vj6kn (audit), follow-ups TBD
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-003: Custom `Symbol.iterator` protocol not executed end-to-end

- **Status:** WILL-FIX
- **ES2020 ref:** §7.4.1 (GetIterator), §13.7.5.16 (Runtime Semantics: ForIn/OfHeadEvaluation)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/iterator_protocol_test262_conformance.rs`
- **Affected tests:** `for-of-custom-iterator-basic`, `for-of-iterator-return-method`, `for-of-iterator-throw-handling`
- **Symptom:** The interpreter does not invoke a user-defined `[Symbol.iterator]()` method on a for-of right-hand operand; it falls back to a built-in array iteration path.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-004: for-of binding destructuring (nested patterns, defaults, rest) not supported

- **Status:** WILL-FIX
- **ES2020 ref:** §13.7.5.13 (Runtime Semantics: BindingInitialization), §13.3.3 (Destructuring Binding Patterns)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/destructuring_binding_test262_conformance.rs`
- **Affected tests:** the for-of-binding subset where the binding is `[a, b]`, `{x, y}`, `[a = 1, b]`, or `[...rest]`.
- **Symptom:** Parser accepts the syntax, but lowering does not emit destructuring instructions in the for-of head context.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-005: Known iteration-statement gaps are invisible in machine reports (silent EXPECTED_PASS exclusion, not XFAIL)

- **Status:** WILL-FIX
- **ES2020 ref:** N/A (process / observability issue, not a language clause)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** the 14 currently-non-passing cases at `tests/iteration_statements_test262_conformance.rs:734-741`
- **Symptom:** `IterationStatementResult` (line 37) has variants `{ Pass, Fail, ParseError }` only — no `ExpectedFailure { reason }`. The exact-gap drift detector at lines 724-791 keeps the gap set frozen via the `EXPECTED_PASS` const, but the gap inventory itself is invisible to compliance reports.
- **Tracking bead:** bd-xkbrm
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-006: Labeled `break` / `continue` not supported

- **Status:** WILL-FIX
- **ES2020 ref:** §13.13 (Labelled Statements), §13.8.2 (Runtime Semantics: Evaluation — ContinueStatement), §13.9.2 (Runtime Semantics: Evaluation — BreakStatement)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `labeled-break-statement`, `labeled-continue-statement`
- **Symptom:** Parser rejects labelled statement form.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-007: `let`-binding Temporal Dead Zone (TDZ) not enforced

- **Status:** WILL-FIX
- **ES2020 ref:** §13.3.1.4 (Runtime Semantics: Evaluation — LexicalBinding), §8.1.1.1.6 (GetBindingValue)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-let-tdz`, related `let` cases that probe `(x = (x = 1); ...; ...)`
- **Symptom:** Accessing a `let`-bound name before its declaration site does not raise `ReferenceError`; the interpreter treats the binding as already-initialized.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-008: Bare `break` / `continue` outside any loop not rejected as `SyntaxError`

- **Status:** WILL-FIX
- **ES2020 ref:** §13.8.1 (Static Semantics: Early Errors — ContinueStatement), §13.9.1 (Static Semantics: Early Errors — BreakStatement)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `unlabeled-break-continue-error`
- **Symptom:** Parser accepts a top-level bare `break;` or `continue;` instead of raising `SyntaxError`.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-009: Iterator `return()` / `throw()` cleanup methods not invoked on abrupt completion

- **Status:** WILL-FIX
- **ES2020 ref:** §7.4.6 (IteratorClose), §13.7.5.13 (Runtime Semantics: ForIn/OfBodyEvaluation)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/iterator_protocol_test262_conformance.rs`
- **Affected tests:** `for-of-iterator-throw-handling`, `for-of-iterator-return-method`
- **Symptom:** When a for-of body abruptly completes (break / throw / return), the iterator's `return()` method is not invoked, and any error from a throwing iterator next-step is not routed through `IteratorClose`.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-010: `for`-statement per-iteration block-scope isolation (`let`) not enforced

- **Status:** WILL-FIX
- **ES2020 ref:** §13.7.4.7 (Runtime Semantics: LabelledEvaluation — for / let), §13.7.4.8 (CreatePerIterationEnvironment)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-block-scope-isolation`
- **Symptom:** A `for (let i = 0; ...; i++)` loop body closure observes a *single* shared `i` binding rather than a fresh per-iteration `i`. The expected test value `0+1+2 = 3` produced by closures captured per-iteration is currently observed as a different (single-binding) result.
- **Tracking bead:** bd-bg9l1.27
- **Reviewed:** 2026-05-28
- **Next review:** 2026-06-28

### DISC-011: `Promise.any` (§27.2.4.5) MUST-tier cases live inside the ES2020 async-promise harness

- **Status:** ACCEPTED
- **ES2020 ref:** N/A — `Promise.any` was introduced in **ES2021** (§27.2.4.5 in the ES2022 spec text), and the FrankenEngine conformance profile is pinned at ES2020 (see [`ECMA262_CONFORMANCE_TARGETS.md`](../ECMA262_CONFORMANCE_TARGETS.md) §3 *Out of scope — Post-ES2020 proposals*).
- **Affected harnesses:** `tests/async_promise_test262_conformance.rs`
- **Affected tests:** `ES2022-27.2.4.5-promise-any-fulfills-with-first-fulfillment`, `ES2022-27.2.4.5-promise-any-all-rejected-aggregate-errors`
- **Symptom:** Two MUST-tier cases under spec §27.2.4.5 carry an `ES2022-…` id prefix and live alongside the ES2020 cases. They feed the same `AsyncPromiseHarness` report and contribute to the MUST-tier no-regression gate (`must_tier_has_no_unexpected_regressions`), so a failure on either case fails the ES2020 conformance gate even though the case asserts a post-ES2020 feature.
- **Test verdict expression:** Both cases run inside the standard `AsyncPromiseHarness` and report `AsyncPromiseResult::Pass | Fail | Error | Skip` like any other case; the `ES2022-` prefix is the only signal that they are out-of-profile. The harness's coverage assertion (`harness_covers_all_initial_categories`) deliberately requires `AsyncPromiseCategory::PromiseAny`, and the id-prefix assertion at `harness_has_minimum_initial_coverage` permits `ES2020-` *or* `ES2022-` precisely so these cases can coexist with ES2020 cases — those tests are the codified record of this accepted divergence.
- **Rationale for ACCEPTED rather than moved:** the harness scaffolding (`AsyncPromiseHarness`, `AsyncPromiseCategory`, the `_support::test262_common` comparator) is non-trivial and would have to be duplicated or refactored into a sharable parent for option 1 (extract into a sibling `post_es2020_async_promise_test262_conformance.rs`). The MUST-tier gate as currently written treats failures on the two `ES2022-…` cases as ES2020 regressions, which is wrong but inert today because both pass — Promise.any is correctly implemented end-to-end. When the engine adds an ES2021/ES2022 profile per `ECMA262_CONFORMANCE_TARGETS.md`, the cleaner refactor (option 1) becomes the next step.
- **Tracking bead:** bd-w50mz.1
- **Reviewed:** 2026-05-28
- **Next review:** 2026-08-26

## Resolved divergences

*(none yet — first divergences land in this file in the same commit that creates it)*

## Out-of-spec features (intentional non-divergences)

The following items are sometimes mistaken for divergences but are not, because
they fall **outside** the ES2020 scope declared in
[`ECMA262_CONFORMANCE_TARGETS.md`](../ECMA262_CONFORMANCE_TARGETS.md) §3:

- **Top-level `await` in modules** — promoted in ES2022, outside ES2020 pin.
- **`WeakRef`, `FinalizationRegistry`** — promoted in ES2021, outside ES2020 pin.
- **Logical assignment operators** (`&&=`, `||=`, `??=`) — promoted in ES2021.
- **Numeric separators** in literals (`1_000_000`) — promoted in ES2021.
- **`String.prototype.replaceAll`** — promoted in ES2021.
- **Annex B web-host features** (octal numeric escapes, HTML comment syntax) — explicitly out of scope for FrankenEngine's server-side use.
- **ECMA-402 (Intl)** — separate standard, not part of ECMA-262.

These belong in `test262_conformance_waivers.toml` with reason `out-of-scope-for-es2020`,
not in DISC-NNN rows.

## Adding a new divergence

1. Allocate the next `DISC-NNN` ID (current max: DISC-010).
2. Fill in every required field including `Affected tests` (concrete IDs, not "various").
3. If `Status = WILL-FIX`, link a `bd-*` tracking bead.
4. Set `Reviewed` to today and `Next review` to today+30 (WILL-FIX/INVESTIGATING) or today+90 (ACCEPTED).
5. Commit alongside the test change that observes the divergence (if any).
6. Reference DISC-NNN in the affected harness's test verdict when the harness emits XFAIL/ExpectedFailure.

## Schema reference

For each row:

- ID — `DISC-NNN` integer (zero-padded for sort stability)
- Status — `ACCEPTED` | `INVESTIGATING` | `WILL-FIX` | `RESOLVED`
- ES2020 ref — `§N.M.K` ECMA-262 Edition 11 clause
- Affected harnesses — `crates/franken-engine/tests/*.rs` filename(s)
- Affected tests — concrete test case `id` value(s)
- Symptom — one paragraph, observation-grounded
- Test verdict expression — how the affected case currently reports
- Tracking bead — `bd-*` (when WILL-FIX or INVESTIGATING)
- Reviewed / Next review — ISO dates
