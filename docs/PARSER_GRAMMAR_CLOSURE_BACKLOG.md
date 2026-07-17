# Parser Grammar Closure Backlog (PSRP-01.1)

This document defines the canonical, machine-checkable backlog for scalar-reference grammar closure tracking.

## Source Artifacts

- Backlog catalog: `crates/franken-engine/tests/fixtures/parser_grammar_closure_backlog.json`
- Deterministic normative fixture catalog: `crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json`
- Deterministic adversarial fixture catalog: `crates/franken-engine/tests/fixtures/parser_phase0_adversarial_fixtures.json`
- Reducer promotion policy: `crates/franken-engine/tests/fixtures/parser_reducer_promotion_policy.json`
- Backlog verification tests: `crates/franken-engine/tests/parser_grammar_closure_backlog.rs`
- Corpus/promotion verification tests: `crates/franken-engine/tests/parser_corpus_promotion_policy.rs`
- Matrix source of truth: `crates/franken-engine/src/parser.rs` (`GrammarCompletenessMatrix::scalar_reference_es2020`)

## Coverage Contract

- Target family count: **20/20** (exactly the matrix family set)
- Promotion policy must remain compatible with:
  - canonical AST schema: `franken-engine.parser-ast.schema.v4`
  - diagnostics schema/taxonomy:
    - `franken-engine.parser-diagnostics.schema.v1`
    - `franken-engine.parser-diagnostics.taxonomy.v1`
- Each family must include:
  - deterministic fixture bindings (`fixture_ids`)
  - at least one replay command (family-scoped)
  - unit/property/e2e linkage fields
  - evidence path expectations

## Verification Commands

All CPU-intensive Rust commands must run through `rch`.

```bash
# Verify backlog-matrix alignment + fixture/replay integrity
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_phase0_gate \
  cargo test -p frankenengine-engine --test parser_grammar_closure_backlog

# Verify normative/adversarial corpus + reducer promotion policy contract
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_reducer_promotion \
  cargo test -p frankenengine-engine --test parser_corpus_promotion_policy

# Replay only one grammar family deterministically
PARSER_GRAMMAR_FAMILY=statement.control_flow rch exec -- \
  env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_phase0_gate \
  cargo test -p frankenengine-engine --test parser_grammar_closure_backlog \
  parser_grammar_closure_backlog_fixtures_are_replayable_by_family -- --nocapture

# End-to-end parser phase0 gate (includes backlog test lane)
./scripts/run_parser_phase0_gate.sh ci

# End-to-end reducer promotion gate + deterministic replay lane
./scripts/run_parser_reducer_promotion_gate.sh ci
./scripts/e2e/parser_reducer_promotion_replay.sh
```

## Evidence Expectations

- `artifacts/parser_phase0_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_phase0_gate/<timestamp>/events.jsonl`
- `artifacts/parser_phase0/golden_checksums.txt`
- `artifacts/parser_reducer_promotion/<timestamp>/run_manifest.json`
- `artifacts/parser_reducer_promotion/<timestamp>/events.jsonl`

Backlog closure evidence is valid only when deterministic fixture hashes, backlog verification tests,
normative/adversarial promotion-policy tests, and phase0/promotion gate artifacts all pass.
