# Cross-Repo Integration Suite (`bd-1mgd`)

Deterministic aggregation lane for FrankenEngine's sibling-boundary contracts.

## Scope

This suite collects the executable cross-repo checks that already exist across
the repository and runs them as one `rch`-backed operator lane. The goal is to
fail closed on schema drift, boundary regressions, and degraded-mode blind spots
at the seams with:

- `/dp/asupersync`
- `/dp/frankentui`
- `/dp/frankensqlite`
- `/dp/fastapi_rust`
- `sqlmodel_rust` boundary inventory carried on top of `frankensqlite`

## Covered Boundaries

- `asupersync`: contract-matrix tests plus bundle generation via
  `scripts/e2e/run_asupersync_contract_matrix.sh`
- `frankentui`: adapter contract and enrichment integration tests
- `frankensqlite`: storage-adapter contract and enrichment integration tests
- `fastapi_rust`: service-endpoint integration tests for health, control,
  evidence export, and replay control
- `sqlmodel_rust`: boundary-rule verification plus shared inventory coverage

Shared inventory and schema-drift protection comes from the
`cross_repo_contract_*` test targets, which pin the shared envelope/field/error
contracts across the sibling set.

## Suite Composition

`./scripts/run_cross_repo_integration_suite.sh` runs targeted steps for:

- `cross_repo_integration_suite`
- `cross_repo_contract_integration`
- `cross_repo_contract_enrichment_integration`
- `cross_repo_contract_edge_cases`
- `asupersync_contract_matrix_integration`
- `asupersync_contract_matrix_enrichment_integration`
- `frankentui_adapter_integration`
- `frankentui_adapter_enrichment_integration`
- `storage_adapter_integration`
- `storage_adapter_enrichment_integration`
- `service_endpoint_template_integration`
- `sibling_integration_benchmark_gate_integration`
- `sqlmodel_rust_boundary`

The suite also emits an `asupersync_contract_matrix` bundle under the run
directory so sibling operators can validate the generated matrix artifacts
without re-discovering the command shape.

## Degraded-Mode and Drift Expectations

The suite is intended to make these classes of failures explicit:

- sibling unavailable or version-drifted -> fail with stable diagnostics
- structured-log field drift -> fail on missing `trace_id`, `decision_id`,
  `policy_id`, `component`, `event`, `outcome`, `error_code`
- schema mismatch -> fail with machine-readable boundary attribution
- contract inventory regression -> fail if a boundary target or suite contract
  disappears from the documented inventory

`sibling_integration_benchmark_gate_integration` is included so the suite covers
the repo's existing cross-sibling overhead guardrail in addition to schema/API
shape checks.

## Machine-Readable Contract

The operator-readable contract lives in:

- `docs/cross_repo_integration_suite_v1.json`

That JSON file lists boundary ids, expected test targets, replay command, suite
script, reproducibility artifacts, and operator verification commands.

## RCH-Only Operator Commands

```bash
./scripts/run_cross_repo_integration_suite.sh ci
```

Replay wrapper:

```bash
./scripts/e2e/cross_repo_integration_suite_replay.sh
```

Modes:

- `check`
- `test`
- `clippy`
- `ci` (`check` + `test` + `clippy`)

All CPU-intensive Rust work is offloaded through `rch`.

## Reproducibility Artifacts

Each suite run writes:

- `artifacts/cross_repo_integration_suite/<timestamp>/run_manifest.json`
- `artifacts/cross_repo_integration_suite/<timestamp>/events.jsonl`
- `artifacts/cross_repo_integration_suite/<timestamp>/commands.txt`
- `artifacts/cross_repo_integration_suite/<timestamp>/asupersync_contract_matrix/`

`run_manifest.json` carries the exact command list, trace/decision/policy ids,
selected sibling roots, failure attribution, and replay commands.
