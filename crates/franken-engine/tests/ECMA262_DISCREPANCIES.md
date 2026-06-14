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

- **Status:** RESOLVED (2026-05-28, bd-bg9l1.27.1)
- **ES2020 ref:** §11.4 (Comments)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-let-tdz`, `break-for-of-early-exit`, `continue-for-of-skip`, `unlabeled-break-continue-error`, `for-of-iterator-throw-handling`
- **Symptom:** The parser's `merge_logical_lines` chokepoint pushes the entire line text into the logical-line buffer *before* the `//` token is detected by the scan loop, so the inline comment survives into `parse_source` and triggers `ParseErrorCode::UnexpectedToken`.
- **Resolution:** bd-bg9l1.27.1 adds a `strip_comments_to_whitespace` pre-pass in
  `parse_source` (runs before `merge_logical_lines`) that blanks `//` line and
  `/* */` block comment bytes to spaces while preserving newlines and byte
  offsets (so spans stay aligned) and leaving strings / template literals /
  regex literals intact (mirrors the `merge_logical_lines_slash_starts_regex`
  heuristic). The comment text no longer reaches `split_statement_segments`.
  `continue-for-of-skip` now passes and is promoted to `EXPECTED_PASS`. The other
  cases that *also* carried trailing comments still fail, but now for their own
  deeper reasons tracked by separate rows: `for-statement-let-tdz` → DISC-007,
  `unlabeled-break-continue-error` → DISC-008, `for-of-iterator-throw-handling`
  → DISC-009, `break-for-of-early-exit` → DISC-012 (Array methods).
- **Tracking bead:** bd-bg9l1.27.1 (closed)
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

- **Status:** RESOLVED (2026-05-30, bd-bg9l1.27.3)
- **ES2020 ref:** §7.4.1 (GetIterator), §13.7.5.16 (Runtime Semantics: ForIn/OfHeadEvaluation)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/iterator_protocol_test262_conformance.rs`
- **Affected tests:** `for-of-custom-iterator-basic` (RESOLVED), `for-of-iterator-return-method` (RESOLVED, see DISC-009), `for-of-iterator-throw-handling` (still open, DISC-009)
- **Symptom:** The interpreter did not invoke a user-defined `[Symbol.iterator]()` method on a for-of right-hand operand; it fell back to a built-in array iteration path.
- **Resolution:** The root cause was three layers (SilentBass + CrimsonHarbor):
  (1) the parser had no object-method-shorthand branch, so `[Symbol.iterator]() {}`
  / `next() {}` misparsed — fixed in bd-bg9l1.27.3 (commit 394055fd, parser.rs);
  (2/3) custom for-of `@@iterator` dispatch and the iterator's `next()` closure
  state were independently fixed by intervening interpreter work (verified at HEAD:
  dispatch invokes `@@iterator` once and `next()` advances correctly). The sole
  remaining gap was that `Symbol.iterator` resolved to `undefined` — there is no
  global `Symbol` binding in the eval scope. Fixed by recognizing `Symbol.iterator`
  at lowering (mirroring `Math.PI`) as the engine's canonical well-known-iterator
  key string `"@@iterator"` (`lowering_pipeline.rs::symbol_iterator_member`), so a
  user `{ [Symbol.iterator]() {...} }` stores its method under the exact key the
  for-of dispatch (`lookup_symbol_iterator_method` strategy 1) looks up.
- **Tracking bead:** bd-bg9l1.27.3
- **Reviewed:** 2026-05-30
- **Next review:** 2026-06-30

### DISC-004: for-of binding destructuring (nested patterns, defaults, rest) not supported

- **Status:** RESOLVED (2026-05-28, bd-bg9l1.27.1)
- **ES2020 ref:** §13.7.5.13 (Runtime Semantics: BindingInitialization), §13.3.3 (Destructuring Binding Patterns)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/destructuring_binding_test262_conformance.rs`
- **Affected tests:** the for-of-binding subset where the binding is `[a, b]`, `{x, y}`, `[a = 1, b]`, or `[...rest]`.
- **Symptom:** Parser accepts the syntax, but lowering does not emit destructuring instructions in the for-of head context.
- **Resolution:** The original symptom was mis-attributed. Lowering *does* emit
  for-of destructuring instructions; the three `iteration_statements`
  destructuring cases (`for-of-destructuring-defaults`, `-nested`, `-rest`)
  were failing only because their sources carried `//` trailing comments that
  `parse_source` rejected (DISC-001). With the bd-bg9l1.27.1 comment-strip
  pre-pass in place, all three now pass and are promoted to `EXPECTED_PASS`.
  bd-bg9l1.27.2 independently added
  `tests/for_of_destructuring_lowering_conformance.rs` proving the for-of
  destructuring lowering path is correct (commit a0e01b2a).
  (If that harness later surfaces a genuine for-of destructuring lowering gap,
  open a fresh row rather than reopening this one.)
- **Tracking bead:** bd-bg9l1.27.1 (closed); see also bd-bg9l1.27.2
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

- **Status:** RESOLVED (labelled `break` bd-bg9l1.27.4; labelled `continue` bd-t7txt, 2026-05-29)
- **ES2020 ref:** §13.13 (Labelled Statements), §13.8.2 (Runtime Semantics: Evaluation — ContinueStatement), §13.9.2 (Runtime Semantics: Evaluation — BreakStatement)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `labeled-break-statement`, `labeled-continue-statement` (both now `EXPECTED_PASS`)
- **Symptom (resolved):** Parser produced no `LabeledStatement` node and the lowering pipeline rejected any `break`/`continue` with a label operand as `UndefinedLabel`.
- **Resolution:** Added `ast::LabeledStatement` + `Statement::Labeled`; parser parses `label: <stmt>`; the lowering pipeline threads a `LabelContext` binding each label to its statement's break/continue targets (iteration labels carry a continue target, others are break-only); `break`/`continue` resolve labels fail-closed. Final fix (bd-t7txt): the statement splitter now strips leading `label:` prefixes before its block-terminator check, so a labelled compound statement (`label: for(..){..} rest;`) is split at its closing brace instead of the labelled body greedily absorbing `rest` — see DISC-006b.
- **Tracking bead:** bd-bg9l1.27.4 (break); bd-t7txt (continue + splitter fix)
- **Reviewed:** 2026-05-29

### DISC-006b: Labeled `continue` across a loop boundary faults

- **Status:** RESOLVED (bd-t7txt, 2026-05-29)
- **ES2020 ref:** §13.8.2 (Runtime Semantics: Evaluation — ContinueStatement)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `labeled-continue-statement` (now `EXPECTED_PASS`)
- **Symptom (resolved):** A labelled `break`/`continue` followed by another statement faulted at runtime (`RuntimeFault: type error: expected function, got string`), and labelled `continue` directly in a `while` infinite-looped.
- **Actual root cause (NOT operand-stack unwinding — the earlier hypothesis was disproven by an IR dump):** the statement splitter (`split_statement_segments`) only splits after a block-closing `}` when the raw segment starts with a block keyword (`for`/`while`/…). A labelled compound statement starts with `label:`, so `label: for(..){..} rest;` was never split — the labelled body greedily absorbed `rest`, and the inner block parsed as a `Raw` expression, producing garbage IR (string load + infinite jump).
- **Resolution:** `strip_leading_labels()` now removes leading `label:` prefixes before the splitter's block-terminator check, so labelled compound statements split at their closing brace exactly like their unlabelled forms. Fixes labelled break+trailing (repairing DISC-006), labelled continue cross-loop, and labelled continue direct-in-`while`.
- **Tracking bead:** bd-t7txt
- **Reviewed:** 2026-05-29

### DISC-007: `let`-binding Temporal Dead Zone (TDZ) not enforced

- **Status:** WILL-FIX
- **ES2020 ref:** §13.3.1.4 (Runtime Semantics: Evaluation — LexicalBinding), §8.1.1.1.6 (GetBindingValue)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-let-tdz`, related `let` cases that probe `(x = (x = 1); ...; ...)`
- **Symptom:** Accessing a `let`-bound name before its declaration site does not raise `ReferenceError`; the interpreter treats the binding as already-initialized.
- **Partial fix:** Static self-reference rejection landed in 8ed0e8f4 (bd-bg9l1.27.5) — `static_semantics` rejects `for (let x = (x = 1); ...)` and `let x = x;`. It is verified by `static_semantics` unit tests but is **not** enforced on the `HybridRouter::eval` register path, so `eval` still returns `Ok` for the conformance case. **Runtime TDZ enforcement remains the open gap.**
- **Harness note:** `for-statement-let-tdz` is a NEGATIVE *should-throw* case. The is_ok harness (`tests/iteration_statements_test262_conformance.rs`) scores `Pass` iff `eval()==Ok`, so it credits this case a (false) `Pass` precisely because the engine fails to throw. Since bd-um9a3 fixed `++`/`--` (removing the prior incidental budget-exhaustion error), the case began returning `Ok` and would falsely trip the drift detector's "promote" invariant — so it is classified in `HARNESS_BLIND_SHOULD_THROW`, **not** `EXPECTED_PASS`. The gap is tracked here and verified out-of-band.
- **Tracking bead:** bd-bg9l1.27.5 (static) / runtime TDZ open under bd-bg9l1.27
- **Reviewed:** 2026-05-30

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

- **Status:** RESOLVED (2026-05-30, bd-bg9l1.27.3 + bd-bg9l1.27.7)
- **ES2020 ref:** §7.4.6 (IteratorClose), §13.7.5.13 (Runtime Semantics: ForIn/OfBodyEvaluation)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`, `tests/iterator_protocol_test262_conformance.rs`
- **Affected tests:** `for-of-iterator-return-method` (RESOLVED), `for-of-iterator-throw-handling` (RESOLVED)
- **Symptom:** When a for-of body abruptly completes (break / throw / return), the iterator's `return()` method is not invoked, and any error from a throwing iterator next-step is not routed through `IteratorClose`.
- **Resolution:** Two parts. (1) return-on-break: once `Symbol.iterator` resolved
  (DISC-003 / bd-bg9l1.27.3), `for-of-iterator-return-method` passed — the engine
  already invokes `iterator.return()` on a `break` early-exit; it was gated only
  on the custom iterable being dispatched. (2) throw path (bd-bg9l1.27.7): a throw
  from the iterator's `next()` was not catchable because for-of runs `next()` via
  `invoke_inline_method_call`, which isolates `catch_frames` and surfaced an
  uncaught throw as a value-less `UncaughtException` that escaped the loop. Fix:
  `invoke_inline_method_call` now captures the thrown value before its snapshot
  restore and re-arms `pending_exception`; the `ForOfNext` handler re-routes it
  into the in-loop try/catch unwinding (mirroring the `Throw` instruction). The
  conformance case's `throw new Error(...)` additionally required declaring
  function-body builtin capabilities in `required_capabilities` (so `builtin:Error`
  inside `next()` is not capability-denied). Both cases are EXPECTED_PASS.
- **Tracking bead:** bd-bg9l1.27.7
- **Reviewed:** 2026-05-30
- **Next review:** 2026-06-30

### DISC-010: `for`-statement per-iteration block-scope isolation (`let`) — RESOLVED

- **Status:** RESOLVED (2026-05-30, bd-bg9l1.27.8)
- **ES2020 ref:** §13.7.4.7 (Runtime Semantics: LabelledEvaluation — for / let), §13.7.4.8 (CreatePerIterationEnvironment)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `for-statement-block-scope-isolation` (now `EXPECTED_PASS`)
- **Symptom (historical):** A `for (let i = 0; ...; i++)` loop body closure was reported to observe a *single* shared `i` binding rather than a fresh per-iteration `i`.
- **Resolution:** The engine in fact already creates a fresh per-iteration declarative binding — the case's three closures capture distinct `0,1,2` and sum to `3`. The gap was *masked* by bd-um9a3: `++`/`--` were silently dropped, so `for (let i...; i++)` never terminated (instruction-budget exhaustion) and per-iteration semantics never got a chance to be observed. Once bd-um9a3 implemented `++`/`--` write-back (22866f7c), the case passes. No per-iteration-env code change was required; promoted to `EXPECTED_PASS`.
- **Tracking bead:** bd-bg9l1.27.8
- **Reviewed:** 2026-05-30

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

### DISC-012: `Array.prototype` mutators (`push`/`pop`/…) unresolved on member access; receiver (`this`) not threaded

- **Status:** RESOLVED (push; 2026-05-29, commits 5d19cb63 + e8bec5a1) — `pop`/`shift`/… still stubbed
- **Resolution:** `prototype_chain_get` now resolves `push` on array exotic
  objects to a receiver-aware `BuiltinFunction(ArrayPush)` as a fallback (own
  props still win); `dispatch_builtin_function` appends each arg to the `this`
  array at `array_like_length`, updates `length`, keeps `cached_dense_length`
  coherent, and returns the new length. The receiver was already threaded to
  `dispatch_builtin_function` by `CallMethod`; the missing pieces were
  array-method *resolution* (path (a)) and a real `push` body (path (c)).
  `break-for-of-early-exit` → EXPECTED_PASS; regression in
  `tests/array_prototype_push_disc012.rs`. The other mutators
  (`pop`/`shift`/`unshift`/…) keep their receiver-less stub bodies — resolve
  them via the same `array_prototype_method` seam when a case demands it.
- **ES2020 ref:** §22.1.3.18 (Array.prototype.push), §22.1.3.x (length own property)
- **Affected harnesses:** `tests/iteration_statements_test262_conformance.rs`
- **Affected tests:** `break-for-of-early-exit`
- **Symptom (corrected 2026-05-29, verified by runtime repro):** `.length` is NOT
  the blocker — `[1,2,3].length` and `let a=[1,2,3]; a.length` both eval to `3`
  (length is stored as an own property at array-literal creation). The actual
  blocker is `seen.push(value)`, which faults with `type error: expected function,
  got undefined`, for two compounding reasons:
  1. **No prototype-method resolution on member access.** `Ir3Instruction::GetProperty`
     on a `Value::Object` reads only OWN properties
     (`baseline_interpreter.rs` ~10703-10709 and the twin handler ~10918), with no
     `Array.prototype` fallback, so `a.push` resolves to `Undefined`. (Contrast
     `string_property_value` ~8342, which maps `charAt`/etc. to `BuiltinFunction`s.)
  2. **Mutator builtins ignore `this`.** Even when reached, `builtin:ArrayPrototypePush`
     (`baseline_interpreter.rs` ~11702) is a stub — its own comment notes `'this'
     would be passed separately, but for now` it allocates a *throwaway* array and
     returns `args.count`; `pop`/`shift` similarly "assume […] an empty array".
  A real fix needs: (a) resolve known `Array.prototype` method names to bound
  `BuiltinFunction`s in `GetProperty` when `object.is_array` and the own prop is
  absent; (b) thread the receiver (`this`) through the method-call ABI to the
  builtin (strings carry the same latent gap — `string_char_at()` captures no
  receiver); (c) rewrite the ~10 array mutators to operate on `this`. This is a
  method-call-ABI change in `baseline_interpreter.rs`. The `break`-in-for-of
  control flow itself is fine (see the passing `continue-for-of-skip`, which uses
  only `sum +=`).
- **Tracking bead:** bd-bg9l1.27.9 (DISC-012; under bd-bg9l1.27)
- **Reviewed:** 2026-05-29
- **Next review:** 2026-06-28

### DISC-013: Own-property string-key enumeration uses deterministic `BTreeMap` order instead of insertion order

- **Status:** ACCEPTED
- **ES2020 ref:** §9.1.11 (`[[OwnPropertyKeys]]`), plus callers such as
  `Object.keys`, `Object.values`, `Object.entries`, `Reflect.ownKeys`,
  `for...in`, and `JSON.stringify`
- **Affected harnesses:** `tests/youtube_botguard_js_conformance.rs`,
  `tests/object_model_integration.rs`
- **Affected tests:** `ytbg-spike-object-keys-values-order`,
  `ordinary_object_own_property_keys_es2020_order`
- **Symptom:** Ordinary object storage is deterministic, but non-index string
  keys are enumerated in `BTreeMap` lexical order rather than ECMAScript
  insertion order. Integer-index keys still sort numerically before string
  keys. This means `Object.keys({b:2,a:1})` can observe `a,b` from the current
  storage model even though donor order is `b,a`.
- **Test verdict expression:** The BotGuard spike case records donor expectation
  `b,a|2,1`; the object-model integration test currently pins the deterministic
  storage behavior by expecting non-index string keys `a,b` after numeric keys.
  The pin is intentional for the current deterministic lane, not conformance
  evidence.
- **Rationale for ACCEPTED rather than immediate repair:** A donor-equivalent
  fix requires deterministic insertion-order-preserving object storage across
  both `franken-engine` and `franken-core`, plus updates to object statics,
  `for...in`, `Reflect.ownKeys`, JSON serialization, persisted/replay shapes,
  and goldens that froze sorted order. The current docs decision keeps the gap
  enumerable while avoiding a broad storage redesign in a docs-only session.
- **Tracking bead:** bd-qporw
- **Reviewed:** 2026-06-14
- **Next review:** 2026-09-12

## Resolved divergences

- **DISC-001** — `//` comment leak in `merge_logical_lines` — RESOLVED 2026-05-28 (bd-bg9l1.27.1).
- **DISC-004** — for-of binding destructuring — RESOLVED 2026-05-28 (bd-bg9l1.27.1; symptom was the DISC-001 comment leak, not a lowering gap).

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

1. Allocate the next `DISC-NNN` ID (current max: DISC-013).
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
