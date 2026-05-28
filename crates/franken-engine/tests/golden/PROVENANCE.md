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

---

## Subdirectory Fixtures

### `ast_parser/`

- **Owning test:** `tests/ast_parser_golden_integration.rs`
  (helpers `assert_ast_golden` / `assert_parse_error_golden`)
- **Subject under test:** `CanonicalEs2020Parser` → `ParseEvent` IR
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test ast_parser_golden_integration`
- **Scrubbing:** UUIDs → `[UUID]`, timestamps → `[TIMESTAMP]`,
  addresses → `0x[ADDR]`, SHA256 → `sha256:[HASH]`
- **Fixtures (14):** `arrow_functions.golden`, `basic_literals.golden`,
  `binary_expressions.golden`, `budget_exceeded_error.golden`,
  `class_declaration.golden`, `complex_nested_structure.golden`,
  `control_flow.golden`, `empty_source_error.golden`,
  `function_declaration.golden`, `module_import_export.golden`,
  `object_destructuring.golden`, `template_literals.golden`,
  `try_catch_finally.golden`, `variable_declarations.golden`

### `evidence_ledger/`

- **Owning test:** `tests/evidence_ledger_integration.rs`
  (helper `assert_evidence_golden`)
- **Subject under test:** `EvidenceEntry` JSON serialization including
  signed envelope and dynamic metadata fields
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test evidence_ledger_integration`
- **Scrubbing:** UUIDs, timestamps, ed25519 signatures, and
  evidence-entry hashes are normalized via
  `scrub_evidence_dynamic_fields` so the fixture stays stable across
  runs.
- **Fixtures (5):** `capability_decision_deny.golden`,
  `extension_lifecycle_terminate.golden`,
  `minimal_contract_evaluation.golden`, `policy_update.golden`,
  `security_action_sandbox.golden`

### `fuzz_adversarial/`

- **Owning test:** `tests/golden_fuzz_regression.rs` (helper
  `assert_golden`), seeded from corpora curated in
  `tests/fuzz_adversarial.rs::run_parser_boundary_golden`.
- **Subject under test:** parser-boundary IR for adversarial/regression
  inputs that previously broke or stressed the parser.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test golden_fuzz_regression`
- **Scrubbing:** SHA256 → `sha256:[HASH]`; raw addresses → `0x[ADDR]`.
- **Fixtures (7):** `parser_boundary_case_00.json` …
  `parser_boundary_case_04.json`, `parser_boundary_max_recursion.json`,
  `parser_boundary_minimal_module.json`.

### `lowering/`

- **Owning test:** `tests/golden_lowering.rs` (helper
  `assert_lowering_golden`).
- **Subject under test:** ES2020 source → IR3 lowering output rendered
  by `render_lowered_ir3`. Fixtures intentionally use the `.txt`
  extension because the IR3 dump is a hand-readable text format, not
  JSON.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test golden_lowering`
- **Scrubbing:** none — IR3 dump is deterministic by construction.
- **Fixtures (6):** `async_function.txt`, `for_of_destructuring.txt`,
  `generator_function.txt`, `nullish_coalescing.txt`,
  `optional_chaining.txt`, `try_catch.txt`.

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

### `resource_escalation/`

- **Owning test:** `tests/resource_escalation_control_integration.rs`
  (helper `assert_escalation_golden`).
- **Subject under test:** `EscalationLog` JSON for resource-escalation
  decision sequences.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test resource_escalation_control_integration`
- **Scrubbing:** dynamic fields (timestamps, decision IDs) are
  normalized via `scrub_escalation_dynamic_fields`.
- **Fixtures (5):** `complete_sequence.golden`,
  `early_termination.golden`, `minimal_single_dimension.golden`,
  `repeated_violations.golden`, `shed_decision.golden`.

### `deterministic_serde/` (created on first bless)

- **Owning test:** `tests/deterministic_serde_golden.rs` (helper
  `run_golden`). Each fixture is a `{"value", "expected_sha256_hex"}`
  pair pinning a `CanonicalValue` shape to the SHA-256 of its canonical
  encoding — load-bearing for every downstream `content_hash`.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test deterministic_serde_golden`
- **Fixtures:** the corpus is hand-authored (`01_null.json` …
  `20_real_evidence_entry.json`); see the test file for the full table.
  The subdirectory is created automatically the first time a fixture is
  blessed.

---

## Top-Level Fixtures

### `attack_surface_game_model_generate_report_expected.json`

- **Owning test:** `crates/franken-engine/src/attack_surface_game_model.rs`
  (in-module `#[cfg(test)] mod tests::generate_report_golden`).
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib attack_surface_game_model::tests::generate_report_golden`

### `benchmark_behavior_equivalence_build_report_expected.json`

- **Owning test:** `tests/benchmark_behavior_equivalence_golden.rs`
  (helper `assert_golden_json` over `build_report`).
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test benchmark_behavior_equivalence_golden`

### `decode_encode_roundtrip.golden`, `malformed_input_behavior.golden`, `schema_hash_determinism.golden`

- **Owning test:** `tests/decode_golden_artifacts.rs` (helper
  `assert_golden`).
- **Subject under test:** canonical decoder behavior under
  malformed/well-formed inputs and schema-hash determinism.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test decode_golden_artifacts`

### `deterministic_formatting.golden`, `error_message_formatting.golden`

- **Owning test:** `tests/simple_golden_demo.rs` (helper
  `assert_golden`). Reference / template suite for the golden pattern.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test simple_golden_demo`

### Lazily-blessed top-level fixtures (not yet on disk)

The following fixtures are owned by `#[cfg(test)]` blocks in `src/`
modules and are only materialised once a developer runs the regen flow:

- `build_report_output.golden` —
  `src/calibration_sentinel.rs::tests::golden_build_report_deterministic_output`,
  regen: `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib calibration_sentinel::tests::golden_build_report_deterministic_output`
- `generate_savings_report_output.golden` —
  `src/allocation_elision_gate.rs::tests::golden_generate_savings_report_deterministic_output`,
  regen: `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib allocation_elision_gate::tests::golden_generate_savings_report_deterministic_output`
- `evidence_h1_fixed_signature.hex` —
  `src/evidence_ledger.rs::tests::evidence_entry_signature_unchanged_post_cache`,
  regen: `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --lib evidence_ledger::tests::evidence_entry_signature_unchanged_post_cache`
- `bundle_report_output.golden` —
  `tests/benchmark_evidence_bundle_golden.rs::golden_bundle_report_deterministic_output`,
  regen: `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test benchmark_evidence_bundle_golden`

If any of these files is missing when its owning test runs without
`UPDATE_GOLDENS`, the test panics with a "golden file missing" message
that points at the same regen command.

---

## Other Golden Roots

For historical reasons three additional golden directories exist
outside this tree:

- `crates/franken-engine/tests/goldens/` — react/JSX compilation, CLI
  output, and IR fixtures (multi-helper, see bd-ub6x8.6 for the planned
  consolidation).
- `crates/franken-engine/tests/golden_tests/` — proof-manifest
  fixtures, currently inlined via `concat!()` rather than read from
  disk (bd-ub6x8.5).
- `crates/franken-engine/tests/golden_vectors/` — vector-format
  fixtures used by the certificate suites.

Consolidation into a single `golden/` root is tracked in bd-ub6x8.6.
Until that lands, the helpers in each suite locate their fixtures
relative to `CARGO_MANIFEST_DIR`, not relative to this file.

## Toolchain

Generated with:

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Parser: `CanonicalEs2020Parser`
- Mode: `ScalarReference`
