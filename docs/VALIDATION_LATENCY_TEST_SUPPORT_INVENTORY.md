# Validation-Latency Test Support Inventory

Bead: `bd-0z9h9.1`

This document records the evidence behind the current fast-validation blocker:
source-local library unit tests in `frankenengine-engine` still pull the
support-heavy integration test crate into the Cargo test graph.

## Summary

`crates/franken-engine/Cargo.toml` declares `frankenengine-test-support` as a
dev-dependency:

```toml
[dev-dependencies]
frankenengine-test-support = { path = "../franken-engine-test-support" }
```

`crates/franken-engine-test-support/Cargo.toml` depends back on the product
crate:

```toml
[dependencies]
frankenengine-engine = { path = "../franken-engine" }
```

That topology preserves integration-test access to deterministic control-plane
helpers, but it also means a focused command such as `cargo test -p
frankenengine-engine --lib <one source-local test>` can still compile
`frankenengine-test-support`. On fresh `rch` targets this defeats the expected
cheap unit-test validation path.

## Reproduction Evidence

The motivating blocker came from `bd-b2mnm`, which added a source-local unit
test for `shadow_decision_composer` and then attempted focused `rch` proof.

Attempt 1:

```bash
timeout 900 rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo test -p frankenengine-engine shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release -- --exact --nocapture
```

Result: exited `124` with no compiler diagnostic after reaching
`Compiling frankenengine-test-support v0.1.0`.

Attempt 2:

```bash
timeout 900 rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo test -p frankenengine-engine --lib shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release -- --exact --nocapture
```

Result: exited `124` with no compiler diagnostic after again reaching
`Compiling frankenengine-test-support v0.1.0`.

The second command proves that `--lib` alone is not enough to avoid the
support crate in the current package topology.

## Direct Support Consumers

Current source inspection found no `frankenengine_test_support` imports under
`crates/franken-engine/src`, `src/bin`, `benches`, or `examples`.

The support crate is imported by 24 unique integration-test files under
`crates/franken-engine/tests`:

- `cancellation_lifecycle_integration.rs`
- `control_plane_adapter.rs`
- `control_plane_integration.rs`
- `cx_threading_edge_cases.rs`
- `cx_threading_enrichment_integration.rs`
- `cx_threading_integration.rs`
- `evidence_emission_enrichment_integration.rs`
- `evidence_emission_integration.rs`
- `execution_cell_integration.rs`
- `extension_host_lifecycle_integration.rs`
- `frankenlab_extension_lifecycle_enrichment_integration.rs`
- `frankenlab_extension_lifecycle_integration.rs`
- `frankenlab_release_gate_enrichment_integration.rs`
- `frankenlab_release_gate_integration.rs`
- `migration_compatibility_enrichment_integration.rs`
- `migration_compatibility_integration.rs`
- `obligation_integration_enrichment_integration.rs`
- `obligation_integration_integration.rs`
- `release_gate_edge_cases.rs`
- `release_gate_enrichment_integration.rs`
- `release_gate_integration.rs`
- `safe_mode_fallback_enrichment_integration.rs`
- `safety_decision_router_enrichment_integration.rs`
- `safety_decision_router_integration.rs`

This matches the long-term support-crate model documented in
`docs/CONTROL_PLANE_TEST_SUPPORT_MODEL_V1.md`: production code should not expose
mock helpers, and integration tests should import them from a dedicated support
crate. The unresolved issue is validation latency, not mock leakage.

## Smallest Known Problem Graph

The smallest observed graph is:

1. `frankenengine-engine` library test target.
2. `frankenengine-engine` dev-dependency set.
3. `frankenengine-test-support`.
4. `frankenengine-test-support` dependency back to `frankenengine-engine`.

That graph is enough for a one-test `--lib` command to compile the support
crate on a fresh `rch` target.

## Follow-On Requirements

`bd-0z9h9.2` should keep all support-dependent integration coverage but move
that coverage behind a Cargo topology where `frankenengine-engine` library
unit-test validation no longer compiles `frankenengine-test-support`.

`bd-0z9h9.3` should add a cheap `rch` smoke gate that fails closed if a
source-local library unit-test command compiles `frankenengine-test-support`.

`bd-0z9h9.4` should return to `bd-b2mnm` and close it only after the focused
shadow-decision lock regression reaches a real test result under `rch`.

## Inspection Commands

These source-only commands produced the inventory above:

```bash
rg -n "frankenengine_test_support" crates/franken-engine/tests
rg -n "frankenengine_test_support" crates/franken-engine/src crates/franken-engine/src/bin crates/franken-engine/benches crates/franken-engine/examples
nl -ba crates/franken-engine/Cargo.toml | sed -n '96,108p'
nl -ba crates/franken-engine-test-support/Cargo.toml | sed -n '1,20p'
```
