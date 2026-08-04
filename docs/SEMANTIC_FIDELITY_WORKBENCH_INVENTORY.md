# Semantic Fidelity Workbench Inventory

Status: initial inventory for `bd-mihky.1`.

This document maps the current eval-facing builtin routes, internal reference
routes, external oracle assets, and first semantic-drift vector families for
the `bd-mihky` semantic-fidelity workbench. It is an inventory only; it does
not claim complete ECMAScript conformance.

Operator runbook: `docs/SEMANTIC_FIDELITY_VECTOR_RUNBOOK.md`.
Capstone handoff: `docs/SEMANTIC_FIDELITY_CAPSTONE_HANDOFF.md`.

## Scope

The workbench should compare observable JavaScript behavior across routes that
already exist in this repository:

- Source-string eval route: `QuickJsInspiredNativeEngine::eval`,
  `V8InspiredNativeEngine::eval`, and `HybridRouter::eval` in
  `crates/franken-engine/src/lib.rs`.
- Eval-facing builtin dispatch route: `InterpreterCore::dispatch_builtin_function`
  in `crates/franken-engine/src/baseline_interpreter.rs`.
- Hostcall builtin route: `InterpreterCore::dispatch_builtin_hostcall` and the
  test-only `call_builtin_by_id` mapping in
  `crates/franken-engine/src/baseline_interpreter.rs`.
- Internal stdlib/reference route: `crates/franken-engine/src/stdlib.rs`.
- Generated intrinsic-table route for the current String.prototype family:
  `crates/franken-engine/src/intrinsics_table.rs` plus
  `dispatch_string_intrinsic` in `baseline_interpreter.rs`.
- External oracle route: Node/Bun trace adapters and lockstep oracle tooling
  (`scripts/lockstep_runtime_adapter_node.mjs`,
  `scripts/lockstep_runtime_adapter_bun.mjs`,
  `crates/franken-engine/src/frx_lockstep_oracle.rs`,
  `crates/franken-engine/src/runtime_lockstep_helpers.rs`).

Non-goals for this track:

- Do not import Node, Bun, V8, QuickJS, or any binding-led runtime into core
  execution.
- Do not strengthen claim language from fixture results alone.
- Do not replace E7, YTBG, or `bd-xulus`; this workbench feeds them with
  structured evidence.

## Route Inventory

| Route | Current anchor | Useful for | Notes |
| --- | --- | --- | --- |
| Source eval | `lib.rs` `QuickJsInspiredNativeEngine::eval`, `V8InspiredNativeEngine::eval`, `HybridRouter::eval` | User-visible JS snippets and regression vectors | This is the best public route for semantic-fidelity vectors because it exercises parser/lowering/interpreter together. |
| BuiltinFunctionKind dispatch | `baseline_interpreter.rs` `dispatch_builtin_function` | Eval/member-access Path A for many builtin functions | String.prototype arms mostly delegate to shared `string_*_impl`; Number arms have recent RangeError fixes for `toFixed` and `toString`. |
| Hostcall capability dispatch | `baseline_interpreter.rs` `dispatch_builtin_hostcall`; builtin ID map and `call_builtin_by_id` test helper | IR HostCall and legacy/direct builtin ID coverage | Several static/prototype builtins have separate hostcall implementations. Example: `builtin:StringPrototypeRepeat` still contains older clamp/default semantics and should be tracked separately from eval Path A. |
| String intrinsic table | `intrinsics_table.rs` String.prototype rows; `dispatch_string_intrinsic`; `string_intrinsic_table_parity_tests` | Route-parity reporting for String.prototype methods | Current table rows point to the same `string_*_impl` functions as legacy String.prototype arms and have parity tests. |
| Stdlib/reference | `stdlib.rs` `exec_string_method`, `exec_number_method`, `exec_string_static`, `StdlibError` | Existing internal reference behavior and closed-bug comparison | Uses `StdlibError::{TypeError, RangeError}`. Some limits differ from eval path and should be recorded as route-specific facts, not silently normalized. |
| Lockstep/oracle | `runtime_lockstep_oracle_integration.md`, `frx_lockstep_oracle.rs`, `runtime_lockstep_helpers.rs`, Node/Bun adapters | Optional external oracle evidence | Existing shape compares trace files and classifies divergences. Semantic-fidelity should reuse the artifact style but use smaller vector-level traces. |
| Test262/conformance | `docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`, `tests/*_test262_conformance.rs`, `scripts/run_real_test262_conformance.sh` | Clause metadata and broader coverage context | Current traceability is broader than builtin/error-class fidelity. Use it as context, not as a substitute for route-specific vectors. |

## First Semantic Families

These are the first fixture families for `bd-mihky.4`.

| Family | Current evidence | First vector candidates | Route emphasis |
| --- | --- | --- | --- |
| String repeat RangeError | `string_repeat_impl` now throws RangeError for negative/oversize counts; eval regression tests are in `string_prototype_methods_part2_bd9a8cz1.rs`; stdlib RangeError tests are in `stdlib_enrichment_integration.rs`. | `"x".repeat(-1)`, `"ab".repeat(10000000)`, `String.prototype.repeat.call(null, 1)` | Compare source eval, String intrinsic parity, stdlib reference, and hostcall `builtin:StringPrototypeRepeat` because the hostcall arm still has older clamp/default behavior. |
| String.fromCodePoint RangeError | Hostcall arm now refuses invalid/partial results; regression tests are in `global_static_methods_bd_tvpjk_regression.rs`; stdlib static route throws `StdlibError::RangeError`. | `String.fromCodePoint(65, 0x110000)`, `String.fromCodePoint(-1)`, `String.fromCodePoint(1.5)`, `String.fromCodePoint(undefined)` | Compare source eval, hostcall capability `builtin:StringFromCodePoint`, stdlib static route, and Node oracle. |
| Number error-class fidelity | Eval/hostcall RangeError tests cover invalid `Number.prototype.toString` radix and invalid `toFixed`, `toExponential`, `toPrecision` digits in `baseline_interpreter_integration.rs`. | `(42).toString(1)`, `(42).toString(37)`, `(42).toFixed(-1)`, `(42).toFixed(101)`, `(42).toExponential(-1)`, `(42).toPrecision(0)` | Compare eval/member-access, hostcall builtin IDs, stdlib number route, and Node oracle. Record known stdlib digit-limit differences explicitly. |
| Array length RangeError | `array_prototype_mutators_bd962ev.rs` covers invalid length assignment after the current `bd-xulus` fix. | `let a=[1,2]; a.length=-1`, `a.length=1.5`, `a.length='not-a-length'`, `a.length=4294967296` | Compare source eval first. Hostcall/stdin reference may not have an exact route; mark missing route as unsupported instead of passing. |
| JS catchable error object fidelity | `js_catchable_error_name`, `native_error_to_thrown_value`, and error constructors map TypeError/RangeError/ReferenceError into JS objects. Existing tests include `error_constructor_regression.rs`. | `try { "x".repeat(-1) } catch (e) { e.name }`, `new RangeError("r").name`, `e instanceof RangeError` once supported | Compare eval route and YTBG error-object expectations; link unsupported `instanceof`/prototype gaps to YTBG rather than hiding them. |

## Existing Seed Tests

The first runner should consume or mirror these cases:

- `crates/franken-engine/tests/string_prototype_methods_part2_bd9a8cz1.rs`
  covers `String.prototype.repeat` normal, zero, negative RangeError, and
  oversize RangeError behavior.
- `crates/franken-engine/tests/global_static_methods_bd_tvpjk_regression.rs`
  covers `String.fromCodePoint` valid output and invalid RangeError cases.
- `crates/franken-engine/tests/baseline_interpreter_integration.rs` covers
  `Number.prototype.toString` invalid radix and invalid digit/precision ranges
  for `toFixed`, `toExponential`, and `toPrecision`.
- `crates/franken-engine/tests/array_prototype_mutators_bd962ev.rs` covers
  invalid and valid Array length assignment behavior.
- `crates/franken-engine/tests/stdlib_enrichment_integration.rs` covers stdlib
  String repeat RangeError cases and related stdlib error shape.
- `crates/franken-engine/tests/baseline_interpreter_conformance.rs` snapshots
  baseline builtin dispatch arms and builtin ID mappings.

## Overlap and Ownership

- `bd-xulus`: active/blocked tracking bead for the current error-class fidelity
  vein. The workbench should preserve its candidates and turn fixes into
  reusable vectors.
- `bd-8tsdh`: closed String.prototype.repeat RangeError bug. Use as seed
  evidence, not as a reopened implementation task.
- `bd-cxmtb`: closed Number.prototype error-class fidelity bug. Use its vector
  shape for Number fixture schema requirements.
- `bd-fqlfw.7` / E7: broader conformance frontier. This workbench supplies
  route-aware builtin/error-class evidence to E7 but does not replace E7.
- YTBG (`bd-8enww.*`): error object/catchability and BotGuard probes depend on
  correct TypeError/RangeError/ReferenceError identity. Keep those links in
  failure reports.

## Gaps for the Next Beads

`bd-mihky.2` should define a schema that can represent:

- vector ID, semantic family, and source text or fixture path;
- route under test: `source_eval`, `builtin_function_kind`, `hostcall_builtin`,
  `string_intrinsic_table`, `stdlib_reference`, `node_oracle`, or `bun_oracle`;
- expected outcome: normal value, JS error class, unsupported/analyzed-unknown,
  or degraded external-oracle receipt;
- dispatch target metadata: capability string, builtin ID, `BuiltinFunctionKind`,
  stdlib `BuiltinId`, and source hash;
- deterministic route notes for known divergences such as hostcall-only legacy
  repeat behavior or stdlib digit-limit differences;
- links to existing beads when a vector is a regression or known open gap.

`bd-mihky.3` should produce replayable artifacts with at least:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `vector_results.jsonl`
- `path_parity_report.json`
- `auto_triage_report.json`
- `summary.md`

`bd-mihky.5` should make route disagreement visible even when the public eval
route is green.

`bd-mihky.8` should keep auto-triage advisory only: link existing beads,
suggest new bead text when no owner exists, and distinguish confirmed failures
from degraded or expected-unknown surfaces.

## Validation Notes

This inventory was built with source and documentation inspection only:

- `rg` route discovery across `crates/franken-engine/src`,
  `crates/franken-engine/tests`, `scripts`, and `docs`.
- Targeted `nl -ba ... | sed -n ...` reads for the files named above.
- No Cargo, build, or test command was run for this inventory bead.
