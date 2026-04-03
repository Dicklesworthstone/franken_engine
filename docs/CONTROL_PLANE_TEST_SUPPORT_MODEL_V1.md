# Control-Plane Test Support Model V1

Bead: `bd-2muur.3.1`

This document chooses the long-term exposure model for control-plane mock helpers and inventories the current consumers that the follow-on refactor bead must migrate.

## Problem

`crates/franken-engine/src/control_plane/mod.rs` currently exports `pub mod mocks`, which means production-default code can import test scaffolding directly from the shipped crate surface. That is an architectural leak even when the live runtime no longer depends on those helpers in production code paths.

The replacement model has to satisfy two constraints at the same time:

1. Production-default imports of mock helpers must become impossible.
2. Existing unit and integration tests must keep a supported, explicit path to the same deterministic helpers.

## Decision

The chosen model is a dedicated dev-only workspace crate:

- Add a new workspace crate named `frankenengine-test-support`.
- Move the current `control_plane::mocks` helpers into that crate under a stable module such as `frankenengine_test_support::control_plane`.
- Remove `pub mod mocks` from `frankenengine_engine::control_plane`.
- Update integration tests to import mock helpers from `frankenengine_test_support`, not from `frankenengine_engine`.
- Keep in-crate `#[cfg(test)]` modules on the same helper implementations via either direct imports from `frankenengine_test_support` or a crate-local `#[cfg(test)]` re-export alias that never reaches production builds.

This is the preferred model for `bd-2muur.3.2` because it keeps the production crate surface clean while preserving normal `cargo test` ergonomics for both unit and integration tests.

## Why This Model

This model wins on the constraints that matter here:

- `#[cfg(test)]` alone is insufficient because integration tests compile the library as a dependency and cannot see `#[cfg(test)]`-only exports.
- A feature-gated test-support surface inside `frankenengine_engine` would keep production cleaner than the current state, but it still leaves the mock API inside the product crate and pushes test execution toward feature management instead of a clearly separate support boundary.
- A dedicated test-support crate preserves explicitness, keeps the product surface honest, and gives guardrails and inventories a crisp rule: any production import from `frankenengine_engine::control_plane::mocks` is a defect.

## Migration Shape

`bd-2muur.3.2` should implement the refactor with this target shape:

```rust
use frankenengine_test_support::control_plane::{
    MockBudget,
    MockCx,
    MockDecisionContract,
    MockEvidenceEmitter,
    MockFailureMode,
    decision_id_from_seed,
    policy_id_from_seed,
    schema_version_from_seed,
    trace_id_from_seed,
};
```

`bd-2muur.3.2` should not re-export that crate back through `frankenengine_engine`, because that would recreate the production-default leak under a new name.

## Current Direct Consumers

These files currently depend on the live mock helper surface and must migrate to the dedicated test-support crate.

### In-Crate `#[cfg(test)]` Modules Under `src/`

- `crates/franken-engine/src/cancellation_lifecycle.rs`
- `crates/franken-engine/src/control_plane/mod.rs`
- `crates/franken-engine/src/cx_threading.rs`
- `crates/franken-engine/src/evidence_emission.rs`
- `crates/franken-engine/src/evidence_replay_checker.rs`
- `crates/franken-engine/src/execution_cell.rs`
- `crates/franken-engine/src/extension_host_lifecycle.rs`
- `crates/franken-engine/src/frankenlab_extension_lifecycle.rs`
- `crates/franken-engine/src/frankenlab_release_gate.rs`
- `crates/franken-engine/src/migration_compatibility.rs`
- `crates/franken-engine/src/obligation_integration.rs`
- `crates/franken-engine/src/release_gate.rs`
- `crates/franken-engine/src/safe_mode_fallback.rs`
- `crates/franken-engine/src/safety_decision_router.rs`

### Integration Tests Under `tests/`

- `crates/franken-engine/tests/cancellation_lifecycle_integration.rs`
- `crates/franken-engine/tests/control_plane_adapter.rs`
- `crates/franken-engine/tests/control_plane_integration.rs`
- `crates/franken-engine/tests/cx_threading_edge_cases.rs`
- `crates/franken-engine/tests/cx_threading_enrichment_integration.rs`
- `crates/franken-engine/tests/cx_threading_integration.rs`
- `crates/franken-engine/tests/evidence_emission_enrichment_integration.rs`
- `crates/franken-engine/tests/evidence_emission_integration.rs`
- `crates/franken-engine/tests/execution_cell_integration.rs`
- `crates/franken-engine/tests/extension_host_lifecycle_integration.rs`
- `crates/franken-engine/tests/frankenlab_extension_lifecycle_enrichment_integration.rs`
- `crates/franken-engine/tests/frankenlab_extension_lifecycle_integration.rs`
- `crates/franken-engine/tests/frankenlab_release_gate_enrichment_integration.rs`
- `crates/franken-engine/tests/frankenlab_release_gate_integration.rs`
- `crates/franken-engine/tests/migration_compatibility_enrichment_integration.rs`
- `crates/franken-engine/tests/migration_compatibility_integration.rs`
- `crates/franken-engine/tests/obligation_integration_enrichment_integration.rs`
- `crates/franken-engine/tests/obligation_integration_integration.rs`
- `crates/franken-engine/tests/release_gate_edge_cases.rs`
- `crates/franken-engine/tests/release_gate_enrichment_integration.rs`
- `crates/franken-engine/tests/release_gate_integration.rs`
- `crates/franken-engine/tests/safe_mode_fallback_enrichment_integration.rs`
- `crates/franken-engine/tests/safety_decision_router_enrichment_integration.rs`
- `crates/franken-engine/tests/safety_decision_router_integration.rs`

## Non-Consumer References That Must Stay Intentional

These files mention mock symbols as scanner definitions, fixture text, or negative assertions. They are part of the guardrail and inventory machinery, not ordinary runtime consumers, so `bd-2muur.3.2` should review them separately instead of bulk-rewriting them.

- `crates/franken-engine/src/control_plane_mock_inventory.rs`
- `crates/franken-engine/src/mock_seam_guardrail.rs`
- `crates/franken-engine/src/frankenlab_harness_migration.rs`
- `crates/franken-engine/src/orchestration_context_contract.rs`
- `crates/franken-engine/tests/ambient_mock_guard.rs`
- `crates/franken-engine/tests/control_plane_mock_inventory_enrichment_integration.rs`
- `crates/franken-engine/tests/control_plane_mock_inventory_integration.rs`
- `crates/franken-engine/tests/execution_orchestrator_integration.rs`
- `crates/franken-engine/tests/frankenlab_release_gate_promotion_integration.rs`
- `crates/franken-engine/tests/mock_seam_guardrail_enrichment_integration.rs`
- `crates/franken-engine/tests/mock_seam_guardrail_integration.rs`

## Follow-On Requirements

`bd-2muur.3.2` should:

- create the dedicated `frankenengine-test-support` crate
- migrate every direct consumer listed above
- remove `pub mod mocks` from `frankenengine_engine::control_plane`
- preserve deterministic helper behavior and public test helper names where practical

`bd-2muur.3.3` should:

- update `mock_seam_guardrail` and `control_plane_mock_inventory` expectations to fail closed on any renewed production-default exposure
- keep fixture-text tests explicit so bad examples still exercise the scanners

`bd-2muur.5.*` should:

- regenerate the inventory after the refactor instead of preserving the pre-refactor architectural assumption that `pub mod mocks` is still live

## Verification Notes

The consumer inventory above was derived from repo-local source inspection using targeted `rg` searches over `crates/franken-engine/src` and `crates/franken-engine/tests`, then manually split into direct consumers versus guardrail or fixture references.
