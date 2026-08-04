# Golden File Provenance

## Regeneration Convention (Project-Wide)

All franken-engine golden tests honor a single environment variable:

```bash
UPDATE_GOLDENS=1 cargo test ...
```

Setting `UPDATE_GOLDENS=1` puts every golden-aware test into write mode
(creating or rewriting its golden fixture); leaving it unset puts every
test into compare mode. There is no per-suite alias — older sites that
used `UPDATE_GOLDEN`, `REGENERATE_GOLDEN`, or `BLESS_GOLDEN` have all
been migrated (bd-ub6x8.2).

On a successful match, each helper sweeps any stale sibling `*.actual`
file left behind by a prior failing run (bd-ub6x8.7), so the working
tree stays tidy once the test goes green again.

## Review Process (applies to every fixture below)

1. Run the regen command listed for the suite you touched (each section
   gives the most targeted invocation; `UPDATE_GOLDENS=1 cargo test` at
   the workspace root refreshes everything in one pass).
2. `git diff -- crates/franken-engine/tests/golden/` and verify the
   change is intentional, not a regression.
3. Commit the refreshed fixture together with the source change that
   motivated it.

The `.gitignore` next to this file excludes `*.actual` (transient
mismatch artifacts) but tracks every `*.golden`, `*.json`, `*.txt`, and
`*.hex` fixture.

## Shared Helper Status

`tests/_support/golden_diag.rs` is retained only for shared scrub regexes and
CLI binary resolution used by CLI-style snapshot suites. The old `GoldenDiag`
fixture read/write comparison API was removed in bd-ub6x8.21 after all active
callers moved their comparison path to `insta::assert_snapshot!`.

---

## Subdirectory Fixtures

### `ast_parser_golden_integration__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/ast_parser_golden_integration.rs`. Migrated from
  the shared `golden_diag::GoldenDiag` helper to
  `insta::assert_snapshot!`; the load-bearing fixtures now live at
  `tests/snapshots/ast_parser_golden_integration__*.snap`.
- **Subject under test:** `CanonicalEs2020Parser` serialized `SyntaxTree`
  output plus `ParseError` diagnostics for parser failure cases.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test ast_parser_golden_integration golden_ -- --nocapture`
- **Review:** `cargo insta review` after regeneration; commit accepted
  `.snap` files only after confirming the AST/parse-error diff is intended.
- **Scrubbing:** `canonical_hash` values are normalized to
  `[CANONICAL_HASH]`; span offsets/line/column fields are normalized to
  `[START_OFFSET]`, `[END_OFFSET]`, `[START_LINE]`, `[START_COLUMN]`,
  `[END_LINE]`, and `[END_COLUMN]`.
- **Snapshots (14):** `ast_parser_golden_integration__arrow_functions.snap`,
  `ast_parser_golden_integration__basic_literals.snap`,
  `ast_parser_golden_integration__binary_expressions.snap`,
  `ast_parser_golden_integration__budget_exceeded_error.snap`,
  `ast_parser_golden_integration__class_declaration.snap`,
  `ast_parser_golden_integration__complex_nested_structure.snap`,
  `ast_parser_golden_integration__control_flow.snap`,
  `ast_parser_golden_integration__empty_source_error.snap`,
  `ast_parser_golden_integration__function_declaration.snap`,
  `ast_parser_golden_integration__module_import_export.snap`,
  `ast_parser_golden_integration__object_destructuring.snap`,
  `ast_parser_golden_integration__template_literals.snap`,
  `ast_parser_golden_integration__try_catch_finally.snap`,
  `ast_parser_golden_integration__variable_declarations.snap`.
- **Legacy audit copies retained:** `tests/golden/ast_parser/*.golden` remain
  on disk for historical diff/audit continuity while this suite uses insta as
  the active comparator.

### `benchmark_diagnostic_golden__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/benchmark_diagnostic_golden.rs`. Migrated from the
  shared `golden_diag::GoldenDiag` fixture comparator to
  `insta::assert_snapshot!`; the suite still uses `golden_diag` for shared
  scrub regexes and build-on-demand CLI binary resolution.
- **Subject under test:** scrubbed stdout/stderr/exit-code JSON for
  `franken-benchmark-evidence-export` and `runtime_diagnostics` command
  surfaces.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test benchmark_diagnostic_golden test_ -- --nocapture`
- **Review:** `cargo insta review` after regeneration; commit accepted
  `.snap` files only after confirming CLI output changes are intended.
- **Scrubbing:** timestamps, project paths, temp paths, Cargo target paths,
  timing values, content hashes, and memory addresses are normalized before
  snapshot comparison.
- **Snapshots (5):** `benchmark_diagnostic_golden__benchmark_export_help.snap`,
  `benchmark_diagnostic_golden__benchmark_export_version.snap`,
  `benchmark_diagnostic_golden__runtime_diagnostics_export_no_input.snap`,
  `benchmark_diagnostic_golden__runtime_diagnostics_help.snap`, and
  `benchmark_diagnostic_golden__runtime_diagnostics_no_input.snap`.
- **Legacy audit fixtures retained:** `tests/golden/benchmark_diagnostic/*.json`
  remain on disk until explicit deletion/move approval is given. The legacy
  directory did not contain a `benchmark_export_version.json`; the insta
  snapshot pins the implemented `clap` version output.

### `evidence_ledger_integration__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/evidence_ledger_integration.rs`. Migrated from
  the shared `golden_diag::GoldenDiag` helper to
  `insta::assert_snapshot!`; the load-bearing fixtures now live at
  `tests/snapshots/evidence_ledger_integration__*.snap`.
- **Subject under test:** `EvidenceEntry` JSON serialization including
  signed envelope and dynamic metadata fields.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test evidence_ledger_integration golden_evidence_entry -- --nocapture`
- **Review:** `cargo insta review` after regeneration; commit accepted
  `.snap` files only after confirming the diff is intended.
- **Scrubbing:** UUIDs, timestamps, ed25519 signatures, and
  evidence-entry hashes are normalized via
  `scrub_evidence_dynamic_fields` so the fixture stays stable across
  runs.
- **Snapshots (5):**
  `evidence_ledger_integration__capability_decision_deny.snap`,
  `evidence_ledger_integration__extension_lifecycle_terminate.snap`,
  `evidence_ledger_integration__minimal_contract_evaluation.snap`,
  `evidence_ledger_integration__policy_update.snap`,
  `evidence_ledger_integration__security_action_sandbox.snap`.
- **Legacy audit fixtures retained:** `tests/golden/evidence_ledger/*.golden`
  remain on disk until explicit deletion/move approval is given.

### `golden_fuzz_regression__parser_boundary_*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.5)*

- **Owning test:** `tests/golden_fuzz_regression.rs`. Migrated from the
  local `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!` in
  bd-ub6x8.21 child bead `bd-ub6x8.21.5`; the load-bearing fixtures now live
  at `tests/snapshots/golden_fuzz_regression__parser_boundary_*.snap`.
  Seeded from corpora curated in
  `tests/fuzz_adversarial.rs::run_parser_boundary_golden`.
- **Subject under test:** parser-boundary IR for adversarial/regression
  inputs that previously broke or stressed the parser.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test golden_fuzz_regression`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** SHA256 → `sha256:[HASH]`; raw addresses → `0x[ADDR]`.
- **Fixtures (7):** `parser_boundary_case_00.snap` …
  `parser_boundary_case_04.snap`, `parser_boundary_max_recursion.snap`,
  `parser_boundary_minimal_module.snap`. Legacy
  `tests/golden/fuzz_adversarial/*.json` files are retained for audit history
  until explicit deletion/move approval is given.

### `fuzz_adversarial__{simple_script_success,malformed_syntax_error,module_with_exports}.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/fuzz_adversarial.rs`. Migrated from the
  shared `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!`
  with `Settings::add_filter` scrubbing for parser hashes and generated
  trace/decision IDs.
- **Subject under test:** parser-boundary harness output for a successful
  script parse, malformed syntax diagnostics, and module import/export
  coverage.
- **Regen:**
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_fe5 INSTA_UPDATE=always cargo test -p frankenengine-engine --test fuzz_adversarial golden_parser_boundary -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** SHA256 -> `[HASH]`; trace IDs -> `[TRACE_ID]`;
  parser decision IDs -> `[DECISION_ID]`.
- **Fixtures (3):** `simple_script_success.snap`,
  `malformed_syntax_error.snap`, `module_with_exports.snap`. Legacy
  `tests/golden/parser_boundary/*.json` files are retained for audit history
  until explicit deletion/move approval is given.

### `lowering/` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/golden_lowering.rs` (helper
  `assert_lowering_golden`). Migrated from the shared
  `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!`; the
  load-bearing fixtures now live at
  `tests/snapshots/golden_lowering__*.snap`.
- **Subject under test:** ES2020 source → IR3 lowering output rendered
  by `render_lowered_ir3` (hand-readable text dump; instructions encoded
  via serde_json per bd-ub6x8.9.2).
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test golden_lowering`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** none — IR3 dump is deterministic by construction.
- **Fixtures (6):** `golden_lowering__async_function.snap`,
  `golden_lowering__for_of_destructuring.snap`,
  `golden_lowering__generator_function.snap`,
  `golden_lowering__nullish_coalescing.snap`,
  `golden_lowering__optional_chaining.snap`,
  `golden_lowering__try_catch.snap`. Legacy `tests/golden/lowering/*.txt`
  files are retained for audit history until explicit deletion/move
  approval is given (each snapshot body was verified byte-identical to
  its legacy fixture, modulo the regen-instruction comment header, when
  the snapshots landed).

### `lowering_pipeline__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** in-module `#[cfg(test)]` tests in
  `src/lowering_pipeline.rs` (helper `assert_lowering_pipeline_snapshot`).
  Migrated from the local `UPDATE_GOLDENS`/`tests/golden/ir/*.json`
  comparator to `insta::assert_snapshot!`.
- **Subject under test:** IR0 -> IR1 -> IR2 -> IR3 lowering pipeline output,
  including flow proof artifact, pass witnesses, isomorphism ledger, and
  lowering events for six small IR0 programs.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib lowering_pipeline::tests::golden_ -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** none — the pretty JSON pipeline output is deterministic by
  construction.
- **Fixtures (6):** `lowering_pipeline__arithmetic_expression.snap`,
  `lowering_pipeline__for_loop_statement.snap`,
  `lowering_pipeline__function_declaration.snap`,
  `lowering_pipeline__if_else_statement.snap`,
  `lowering_pipeline__numeric_literal.snap`, and
  `lowering_pipeline__variable_declarations.snap`.
- **Legacy audit fixtures retained:** `tests/golden/ir/*.json` and historical
  `tests/golden/ir/*.actual.json` siblings remain on disk until explicit
  deletion/move approval is given.

### `parser_boundary/`

- **Owning binary:** `crates/franken-engine/src/bin/franken_parser_phase0_report.rs`
  (the `franken_parser_phase0_report` tool that wraps the parser and
  emits the JSON snapshots checked in here).
- **Subject under test:** Phase-0 parser report shapes for golden
  integration coverage in higher-level proof harnesses.
- **Regen:** these fixtures are produced by running the report tool
  against curated inputs; rerun the tool and overwrite if the report
  schema changes intentionally.
- **Fixtures (3):** `malformed_syntax_error.json`,
  `module_with_exports.json`, `simple_script_success.json`.

### `resource_escalation_control_integration__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/resource_escalation_control_integration.rs`.
  Migrated from the shared `golden_diag::GoldenDiag` helper to
  `insta::assert_snapshot!`; the load-bearing fixtures now live at
  `tests/snapshots/resource_escalation_control_integration__*.snap`.
- **Subject under test:** `EscalationLog` JSON for resource-escalation
  decision sequences.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test resource_escalation_control_integration golden_escalation -- --nocapture`
- **Review:** `cargo insta review` after regeneration; commit accepted
  `.snap` files only after confirming the diff is intended.
- **Scrubbing:** dynamic fields (timestamps and content hashes) are
  normalized via `scrub_escalation_dynamic_fields`.
- **Snapshots (5):**
  `resource_escalation_control_integration__complete_sequence.snap`,
  `resource_escalation_control_integration__early_termination.snap`,
  `resource_escalation_control_integration__minimal_single_dimension.snap`,
  `resource_escalation_control_integration__repeated_violations.snap`,
  `resource_escalation_control_integration__shed_decision.snap`.
- **Legacy audit fixtures retained:** `tests/golden/resource_escalation/*.golden`
  remain on disk until explicit deletion/move approval is given.

### `react_compilation_golden__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/react_compilation_golden.rs`. Migrated from the
  shared `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!`; the
  load-bearing fixtures now live at
  `tests/snapshots/react_compilation_golden__*.snap`.
- **Subject under test:** normalized React JSX lowering fixtures covering
  classic and automatic runtime modes, fragments, components, spread props,
  conditional children, arrays, falsy children, raw HTML, and member-expression
  components.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test react_compilation_golden test_ -- --nocapture`
- **Review:** `cargo insta review` after regeneration; commit accepted
  `.snap` files only after confirming the diff is intended.
- **Scrubbing:** source coordinate spans are normalized in
  `normalized_fixture_value` before snapshot comparison.
- **Snapshots (17):** `react_compilation_golden__*.snap`.
- **Legacy audit fixtures retained:** `tests/golden/react_compilation/*.json`
  and existing `.actual` siblings remain on disk until explicit deletion/move
  approval is given.

### `certificate_golden_tests__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.6)*

- **Owning test:** `tests/certificate_golden_tests.rs`. Migrated from the
  shared `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!` in
  bd-ub6x8.21 child bead `bd-ub6x8.21.6`; the load-bearing fixtures now live
  at `tests/snapshots/certificate_golden_tests__*.snap`.
- **Subject under test:** governance / capability certificate
  serialization, including mixed-verdict bundles and timescale
  separation verdicts.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test certificate_golden_tests`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** none — fixtures are constructed from hand-curated
  inputs with deterministic content hashes.
- **Fixtures (10):** `certificate_bundle_mixed_verdicts.golden.json`,
  `certificate_evidence_basic.golden.json`,
  `certificate_evidence_memory.golden.json`,
  `certificate_evidence_network_io.golden.json`,
  `golden_workflow_test.golden.json`,
  `governance_receipt_comprehensive.golden.json`,
  `governance_receipt_denial.golden.json`,
  `timescale_certificate_insufficient.golden.json`,
  `timescale_certificate_marginal.golden.json`,
  `timescale_certificate_sufficient.golden.json`.
- **Migrated from:** `tests/goldens/certificates/` (bd-ub6x8.6.4).
  The legacy `tests/golden/certificates/*.golden.json` files are retained for
  audit history until explicit deletion/move approval is given.

### `policy_theorem_compiler_integration__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/policy_theorem_compiler_integration.rs`
  (helper `assert_policy_compiler_golden`).
- **Subject under test:** policy theorem compiler outputs for valid
  policies, complex constraint sets, and explicit failure
  counterexamples.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test policy_theorem_compiler_integration`,
  followed by `cargo insta review` for interactive blessing.
- **Scrubbing:** none — the policy compiler output is canonically
  serialised.
- **Fixtures (3):** `policy_theorem_compiler_integration__valid_policy_all_passes.snap`,
  `policy_theorem_compiler_integration__complex_constraints_all_passes.snap`,
  `policy_theorem_compiler_integration__failure_counterexamples.snap`.
- **Migrated from:** `tests/golden/policy_theorem_compiler/*.json`; the
  legacy JSON fixtures are retained for audit history until an explicit
  deletion/move approval is given.

### `deterministic_serde_golden__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/deterministic_serde_golden.rs` (helper
  `run_golden`). Migrated from the local `UPDATE_GOLDENS` JSON read/write
  helper to `insta::assert_snapshot!`. Each snapshot is a
  `{"value", "expected_sha256_hex"}`
  pair pinning a `CanonicalValue` shape to the SHA-256 of its canonical
  encoding — load-bearing for every downstream `content_hash`.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test deterministic_serde_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Fixtures:** active snapshots are
  `tests/snapshots/deterministic_serde_golden__01_null.snap` …
  `tests/snapshots/deterministic_serde_golden__20_real_evidence_entry.snap`;
  see the test file for the full corpus table.
- **Legacy audit fixtures retained:** `tests/golden/deterministic_serde/*.json`
  remain on disk until explicit deletion/move approval is given.

---

## Top-Level Fixtures

### `attack_surface_game_model__generate_report_golden_snapshot.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `crates/franken-engine/src/attack_surface_game_model.rs`
  (in-module `#[cfg(test)] mod tests::generate_report_golden_snapshot`).
  Migrated from `tests/golden/attack_surface_game_model_generate_report_expected.json`
  plus the `UPDATE_GOLDENS` read/write branch to `insta::assert_snapshot!`;
  the load-bearing fixture now lives at
  `tests/snapshots/attack_surface_game_model__generate_report_golden_snapshot.snap`.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib attack_surface_game_model::tests::generate_report_golden_snapshot`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/attack_surface_game_model_generate_report_expected.json` remains
  on disk until explicit deletion/move approval is given.

### `benchmark_behavior_equivalence_golden__build_report_golden_snapshot.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.2)*

- **Owning test:** `tests/benchmark_behavior_equivalence_golden.rs`.
  Migrated from `golden_diag::GoldenDiag` to `insta::assert_snapshot!`
  in bd-ub6x8.21 child bead `bd-ub6x8.21.2`. The load-bearing fixture now
  lives at
  `tests/snapshots/benchmark_behavior_equivalence_golden__build_report_golden_snapshot.snap`.
- **Subject under test:** the `build_report` JSON shape for benchmark behavior
  equivalence classifications and owner routing.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test benchmark_behavior_equivalence_golden`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/benchmark_behavior_equivalence_build_report_expected.json`
  file is retained for audit history until an explicit deletion/move approval
  is given.

### `benchmark_runtime_diagnostics_snapshot__benchmark_and_runtime_diagnostics_outputs_match_golden.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/benchmark_runtime_diagnostics_snapshot.rs`.
  Migrated from the local `UPDATE_GOLDENS` read/write branch plus
  `tests/golden/wire_vectors/benchmark_diagnostics_output_v1.json` include to
  `insta::assert_snapshot!`. The load-bearing fixture now lives at
  `tests/snapshots/benchmark_runtime_diagnostics_snapshot__benchmark_and_runtime_diagnostics_outputs_match_golden.snap`.
- **Subject under test:** combined benchmark-evidence bundle report and
  runtime-diagnostics output snapshot for the diagnostics wire surface.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test benchmark_runtime_diagnostics_snapshot`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/wire_vectors/benchmark_diagnostics_output_v1.json` file is
  retained for audit history until an explicit deletion/move approval is given.

### `extension_host_lifecycle_integration__authority_decision_sequence.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/extension_host_lifecycle_integration.rs`.
  Migrated from the embedded include of
  `tests/golden/wire_vectors/extension_host_lifecycle_authority_decisions.json`
  to `insta::assert_snapshot!`.
- **Subject under test:** extension-host lifecycle authority decision ledger
  format for the load/bind/invoke/revoke sequence.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test extension_host_lifecycle_integration authority_decision_sequence_matches_golden_snapshot -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/extension_host_lifecycle_authority_decisions.json`
  remains on disk until explicit deletion/move approval is given.

### `baseline_malformed_dispatch_golden__baseline_malformed_dispatch_fail_closed.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/baseline_malformed_dispatch_golden.rs`. Migrated
  from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/baseline_malformed_dispatch_fail_closed.json`
  to `insta::assert_snapshot!`.
- **Subject under test:** malformed baseline-interpreter dispatch inputs,
  including fail-closed binding-kind and UTF-16 boundary behavior.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test baseline_malformed_dispatch_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/baseline_malformed_dispatch_fail_closed.json`
  remains on disk until explicit deletion/move approval is given.

### `baseline_interpreter_conformance__baseline_dispatch_arm_snapshot.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/baseline_interpreter_conformance.rs`.
  Migrated from the embedded `DISPATCH_ARMS_GOLDEN` include of
  `tests/golden/wire_vectors/baseline_dispatch_arms.txt` to
  `insta::assert_snapshot!`.
- **Subject under test:** baseline-interpreter dispatch arm enumeration,
  including total, unique, and duplicate-count invariants.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test baseline_interpreter_conformance baseline_dispatch_arm_snapshot_matches_golden -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/baseline_dispatch_arms.txt` remains on disk until
  explicit deletion/move approval is given.

### `revocation_enforcement_integration__revocation_check_event_schema.snap`, `revocation_enforcement_integration__revocation_check_event_v1_wire.snap`, `revocation_enforcement_integration__signed_revocation_check_event_v1_wire.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/revocation_enforcement_integration.rs`.
  Migrated from embedded includes of
  `tests/golden/wire_vectors/revocation_check_event_schema.json`,
  `tests/golden/wire_vectors/revocation_check_event_v1_wire.json`, and
  `tests/golden/wire_vectors/signed_revocation_check_event_v1_wire.json`
  to `insta::assert_snapshot!`.
- **Subject under test:** revocation-event schema plus the unsigned and signed
  revocation-check wire representations.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test revocation_enforcement_integration revocation_check_event -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/revocation_check_event_schema.json`,
  `tests/golden/wire_vectors/revocation_check_event_v1_wire.json`, and
  `tests/golden/wire_vectors/signed_revocation_check_event_v1_wire.json`
  remain on disk until explicit deletion/move approval is given.

### `perf_h4_encode_buffer_integration__frankenctl_compile_artifact_unchanged_after_buffer_pool.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/perf_h4_encode_buffer_integration.rs`.
  Migrated from the `BLESS_H4_GOLDEN` read/write branch plus
  `tests/golden/h4_encode/compile_artifact.hash` comparison to
  `insta::assert_snapshot!`. The test still checks within-build repeated
  compile determinism before comparing the compile-hash map to the snapshot.
- **Subject under test:** the deterministic `frankenctl compile` IR hash set
  emitted after the H4 buffered-encoding path.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test perf_h4_encode_buffer_integration frankenctl_compile_artifact_unchanged_after_buffer_pool -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/h4_encode/compile_artifact.hash` remains on disk until
  explicit deletion/move approval is given.

### `benchmark_evidence_bundle_golden__bundle_report_output.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/benchmark_evidence_bundle_golden.rs`.
  Migrated from the shared `golden_diag::GoldenDiag` helper to
  `insta::assert_snapshot!` in bd-ub6x8.21. The load-bearing fixture now
  lives at
  `tests/snapshots/benchmark_evidence_bundle_golden__bundle_report_output.snap`.
- **Subject under test:** the `BundleReport` JSON shape emitted by
  `benchmark_evidence_bundle::generate_report`.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test benchmark_evidence_bundle_golden`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/bundle_report_output.golden` file is retained for audit
  history until an explicit deletion/move approval is given.

### `benchmark_evidence_bundle__*.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning tests:** in-module `#[cfg(test)]` tests in
  `src/benchmark_evidence_bundle.rs` using helper
  `assert_evidence_bundle_golden`.
- **Subject under test:** canonical `EvidenceBundle` JSON serialization for
  minimal, passing, failing, and complex parity evidence-bundle shapes.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib benchmark_evidence_bundle::tests::golden_ -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Review:** the active snapshots live in `tests/snapshots/` via
  `insta::with_settings!({ snapshot_path => "../tests/snapshots" })` even
  though the tests live in a source module.
- **Fixtures (4):** `benchmark_evidence_bundle__minimal_bundle.snap`,
  `benchmark_evidence_bundle__passing_bundle_with_multiple_workloads.snap`,
  `benchmark_evidence_bundle__failing_bundle_with_regression.snap`, and
  `benchmark_evidence_bundle__complex_parity_edge_cases.snap`.
- **Legacy audit fixtures retained:** `tests/golden/evidence_bundle/*.json`
  remain on disk until explicit deletion/move approval is given. Existing
  untracked `.actual.json` siblings are transient historical mismatch outputs,
  not active fixtures.

### `decode_golden_artifacts__{decode_encode_roundtrip,malformed_input_behavior,schema_hash_determinism}.snap` *(moved to `tests/snapshots/` — bd-drdxa)*

- **Owning test:** `tests/decode_golden_artifacts.rs`. Migrated from the
  ad-hoc `assert_golden` helper to `insta::assert_snapshot!` in commit
  `a5a6e3a6` (bd-ub6x8.21 sub-bead `bd-drdxa`). The three fixtures moved
  from `tests/golden/<name>.golden` → `tests/snapshots/decode_golden_artifacts__<name>.snap`
  with the canonical insta YAML header.
- **Subject under test:** canonical decoder behavior under
  malformed/well-formed inputs and schema-hash determinism.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test decode_golden_artifacts`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `UPDATE_GOLDENS=1` regen flow no longer applies to this suite.

### `proof_manifest_golden_artifacts__{test_proof_manifest_deterministic_serialization,test_proof_manifest_no_host_specific_tokens_in_serialization}.snap` *(moved to `tests/snapshots/` — bd-drdxa)*

- **Owning test:** `tests/proof_manifest_golden_artifacts.rs`. Migrated from
  the shared `golden_diag::GoldenDiag` helper to `insta::assert_snapshot!` in
  bd-ub6x8.21 sub-bead `bd-drdxa`, correcting the earlier closeout that
  accidentally documented the decode-golden suite instead.
- **Subject under test:** canonical `ProofManifest` JSON serialization for the
  deterministic proof-artifact manifest used by gate bundles.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts`,
  followed by `cargo insta review` for interactive blessing. The legacy
  proof-manifest JSON fixture is retained for audit history until an explicit
  deletion/move approval is given.

### `seqlock_fastpath_golden__seqlock_fastpath_recovery_surface.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/seqlock_fastpath_golden.rs`. Migrated from the
  embedded `EXPECTED` include of
  `tests/golden/wire_vectors/seqlock_fastpath_recovery_surface.json` to
  `insta::assert_snapshot!`.
- **Subject under test:** deterministic JSON for the seqlock fast-path
  recovery surface, including retry policy, initial/published reads, and
  telemetry counters.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test seqlock_fastpath_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/seqlock_fastpath_recovery_surface.json` remains
  on disk until explicit deletion/move approval is given.

### `semantic_flattening_inventory_golden__semantic_flattening_inventory_hashes.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/semantic_flattening_inventory_golden.rs`.
  Migrated from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/semantic_flattening_inventory_hashes_v1.json`
  to `insta::assert_snapshot!`; the test still decodes the serialized
  JSON and checks per-occurrence hash stability after the snapshot assertion.
- **Subject under test:** semantic-flattening inventory hash table for
  intentional, acceptable-edge, and must-fix translation cases.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test semantic_flattening_inventory_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/semantic_flattening_inventory_hashes_v1.json`
  remains on disk until explicit deletion/move approval is given.

### `test262_runner_conformance_golden__test262_runner_accounting.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/test262_runner_conformance_golden.rs`. Migrated
  from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/test262_runner_accounting_v1.json` to
  `insta::assert_snapshot!`.
- **Subject under test:** test262 conformance-runner accounting wire
  format v1.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test test262_runner_conformance_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/test262_runner_accounting_v1.json` remains on
  disk until explicit deletion/move approval is given.

### `policy_bundle_golden_artifacts__{policy_bundle_default,policy_bundle_minimal,policy_bundle_comprehensive}.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.1)*

- **Owning test:** `tests/policy_bundle_golden_artifacts.rs`. Migrated from
  the local `assert_golden` helper to `insta::assert_snapshot!` in commit
  `96526935` (bd-ub6x8.21 child bead `bd-ub6x8.21.1`). The load-bearing
  fixtures now live at
  `tests/snapshots/policy_bundle_golden_artifacts__<name>.snap` with the
  canonical insta YAML header.
- **Subject under test:** deterministic `PolicyBundle` JSON serialization for
  the default, minimal, and comprehensive policy-bundle shapes.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test policy_bundle_golden_artifacts`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/policy_bundle_*.golden` files are retained for audit history
  until an explicit deletion/move approval is given.

### `golden_pattern__{deterministic_formatting,error_message_formatting}.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning example:** `examples/golden_pattern.rs`. Migrated from the local
  pedagogical `assert_golden` / `UPDATE_GOLDENS` / `.actual` helper to
  `insta::assert_snapshot!`; the load-bearing fixtures now live at
  `tests/snapshots/golden_pattern__*.snap`.
- **Subject under test:** the standalone golden-artifact pattern demo outputs
  for deterministic formatting and error-message formatting. This example does
  not exercise product runtime code.
- **Regen:**
  `INSTA_UPDATE=always cargo run -p frankenengine-engine --example golden_pattern`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixtures retained:** `tests/golden/deterministic_formatting.golden`
  and `tests/golden/error_message_formatting.golden` remain on disk until an
  explicit deletion/move approval is given.

### `evidence_ledger__evidence_entry_signature_unchanged_post_cache.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** in-module `#[cfg(test)]` test
  `src/evidence_ledger.rs::tests::evidence_entry_signature_unchanged_post_cache`.
  Migrated from `tests/golden/evidence_h1_fixed_signature.hex` plus the
  `UPDATE_GOLDENS` read/write branch to `insta::assert_snapshot!`; the
  load-bearing fixture now lives at
  `tests/snapshots/evidence_ledger__evidence_entry_signature_unchanged_post_cache.snap`.
- **Subject under test:** the deterministic Ed25519 signature bytes for the
  fixed H1 evidence entry after signing-key caching.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib evidence_ledger::tests::evidence_entry_signature_unchanged_post_cache`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:** `tests/golden/evidence_h1_fixed_signature.hex`
  remains on disk until explicit deletion/move approval is given.

### Calibration sentinel build report

- **Owning test:** in-module `#[cfg(test)]` test
  `src/calibration_sentinel.rs::tests::golden_build_report_deterministic_output`.
  Migrated from the lazy `tests/golden/build_report_output.golden`
  `UPDATE_GOLDENS` read/write branch to `insta::assert_snapshot!`; the
  load-bearing fixture now lives at
  `tests/snapshots/calibration_sentinel__golden_build_report_deterministic_output.snap`.
- **Subject under test:** deterministic JSON for the mixed-state
  `SentinelReport` returned by `build_report`.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib calibration_sentinel::tests::golden_build_report_deterministic_output`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture:** no committed `tests/golden/build_report_output.golden`
  fixture existed before migration, so there is no legacy file to retain.

### Allocation elision savings report

- **Owning test:** in-module `#[cfg(test)]` test
  `src/allocation_elision_gate.rs::tests::golden_generate_savings_report_deterministic_output`.
  Migrated from the lazy
  `tests/golden/generate_savings_report_output.golden` `UPDATE_GOLDENS`
  read/write branch to `insta::assert_snapshot!`; the load-bearing fixture now
  lives at
  `tests/snapshots/allocation_elision_gate__golden_generate_savings_report_deterministic_output.snap`.
- **Subject under test:** deterministic JSON for the aggregate
  `ElisionSavingsReport` returned by `generate_savings_report`.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --lib allocation_elision_gate::tests::golden_generate_savings_report_deterministic_output`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture:** no committed
  `tests/golden/generate_savings_report_output.golden` fixture existed before
  migration, so there is no legacy file to retain.

---

## Other Golden Roots

Consolidation of the historical `tests/goldens/`, `tests/golden_tests/`,
and `tests/golden_vectors/` sibling roots into this single
`tests/golden/` tree is complete (bd-ub6x8.6 + bd-ub6x8.6.2 +
bd-ub6x8.6.3 + bd-ub6x8.6.4). The migration tombstone (a stub
`PROVENANCE.md` recording the historical paths and where each
subdirectory landed) survives under `tests/goldens/` per the
bd-ub6x8.6.1 RATIONALIZATION decision.

## Toolchain

Generated with:

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Parser: `CanonicalEs2020Parser`
- Mode: `ScalarReference`
