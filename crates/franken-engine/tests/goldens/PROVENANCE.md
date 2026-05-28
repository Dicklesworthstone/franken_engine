# Golden File Provenance — `tests/goldens/` (JSON)

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

This directory is one of three legacy golden roots that pre-date the
canonical-location decision (bd-ub6x8.6); migration into
`tests/golden/<feature>/` is deferred to a follow-up bead. Until that lands,
every fixture below stays here and is read by its owning test through a path
hard-coded relative to `CARGO_MANIFEST_DIR`, not relative to this file.

## Regeneration

All franken-engine golden tests honor the project-wide `UPDATE_GOLDENS=1`
contract (bd-ub6x8.2). Workspace-wide:

```bash
UPDATE_GOLDENS=1 cargo test
```

Per-suite invocations are listed beside each subdirectory below.

The `.actual` siblings produced by failing runs are gitignored by
`crates/franken-engine/tests/.gitignore`; on a successful match each
helper sweeps them (bd-ub6x8.7).

---

## Subdirectory Fixtures

### `ir/`

- **Owning test:** `src/lowering_pipeline.rs` in-module
  `#[cfg(test)] mod tests` (lazy-blessed JSON via the local
  `golden_path` helper at L14043).
- **Subject under test:** ES2020 source → IR3 lowering output rendered as
  structured JSON (distinct from the text-format `tests/golden/lowering/`
  fixtures: those pin the human-readable IR3 dump; these pin the
  serialized IR shape).
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib lowering_pipeline`
- **Fixtures (6):** `arithmetic_expression.json`, `for_loop_statement.json`,
  `function_declaration.json`, `if_else_statement.json`,
  `numeric_literal.json`, `variable_declarations.json`.
- **Scrubbing:** none — IR shape is deterministic by construction.

### `evidence/`

- **Owning test:** `src/benchmark_evidence_bundle.rs` in-module
  `#[cfg(test)] mod tests` (the `evidence_golden_path` helper at L1905
  reads `tests/goldens/evidence/<test>.json`).
- **Subject under test:** `BenchmarkEvidenceBundle` serialization for
  several composed bundle shapes.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib benchmark_evidence_bundle`
- **Fixtures (4):** `minimal_bundle.json`,
  `passing_bundle_with_multiple_workloads.json`,
  `failing_bundle_with_regression.json`,
  `complex_parity_edge_cases.json`.
- **Scrubbing:** dynamic timestamp / id fields normalized by the in-test
  helpers; see the module's `tests` block for the exact rules.

### `certificates/`

- **Owning test:** `tests/certificate_golden_tests.rs` (local
  `assert_golden` helper at L28; reads
  `tests/goldens/certificates/<test>.golden.json`).
- **Subject under test:** governance / capability certificate
  serialization, including mixed-verdict bundles.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test certificate_golden_tests`
- **Fixtures (7):** `certificate_bundle_mixed_verdicts.golden.json`,
  `certificate_evidence_basic.golden.json`,
  `certificate_evidence_memory.golden.json`,
  `certificate_evidence_network_io.golden.json`,
  `golden_workflow_test.golden.json`,
  `governance_receipt_comprehensive.golden.json`,
  `governance_receipt_denial.golden.json`,
  `timescale_certificate_insufficient.golden.json`.

### `react_compilation/`

- **Owning test:** `tests/react_compilation_golden.rs`
  (`test_react_compilation_golden` + helpers at L199–202).
- **Generator binary:** `src/bin/generate_react_goldens.rs` writes a
  refreshed set into this directory on demand
  (`cargo run -p frankenengine-engine --bin generate_react_goldens`).
- **Subject under test:** JSX → ES module compilation output for the
  classic and automatic runtimes.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test react_compilation_golden`
- **Fixtures:** paired `.json` / `.actual` per case
  (`component_with_props_automatic`, `component_with_props_classic`,
  `conditional_and_automatic`, `conditional_ternary_automatic`, and the
  other generator-emitted shapes — see
  `src/bin/generate_react_goldens.rs` for the full enumeration).

### `policy_theorem_compiler/`

- **Owning test:** `tests/policy_theorem_compiler_integration.rs`
  (`assert_policy_compiler_golden` helper at L129 and the
  `should_update_policy_goldens` gate at L118).
- **Subject under test:** policy theorem compiler outputs for valid
  policies, complex constraint sets, and explicit failure
  counterexamples.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test policy_theorem_compiler_integration`
- **Fixtures (3):** `valid_policy_all_passes.json`,
  `complex_constraints_all_passes.json`,
  `failure_counterexamples.json`.

### `benchmark_diagnostic/`

- **Owning test:** `tests/benchmark_diagnostic_golden.rs` (delegates to
  `GoldenDiag` via `tests/golden_diag.rs`; the `assert_golden_match`
  call site is the canonical write path).
- **Subject under test:** runtime-diagnostics CLI output for the
  benchmark-export and runtime-diagnostics surfaces.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test benchmark_diagnostic_golden`
- **Fixtures (4):** `benchmark_export_help.json`,
  `runtime_diagnostics_export_no_input.json`,
  `runtime_diagnostics_help.json`,
  `runtime_diagnostics_no_input.json`.

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `UPDATE_GOLDENS=1` for blessing; default compare mode otherwise.
