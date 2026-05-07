# SWARM_BENCHMARK_WORKLOAD_CATALOG

`bd-ep64o` defines the V1 source contract for the SWARM-BENCH-I benchmark
workload catalog.

This catalog exists because the repo already ships multiple benchmark and
measurement surfaces, but operators still have to remember which workload
answers which performance question. The catalog is the stable inventory layer
that later normalizers, scorers, and operator-status handoffs can consume
without guessing which benchmark script or artifact contract is relevant.

Machine-readable contract:
[`docs/swarm_benchmark_workload_catalog_contract_v1.json`](./swarm_benchmark_workload_catalog_contract_v1.json)

Smoke gate:
`./scripts/e2e/swarm_benchmark_workload_catalog_contract_smoke.sh`

This surface is advisory only and proof only. It does not query live `br`,
Agent Mail, RCH, git, or workers. It does not mutate beads, release
reservations, send mail, run Cargo, run RCH, change queue policy, or replace
`scripts/swarm_operator_status_report.sh`.

## Catalog Row Contract

Every workload row must define these fields:

- `workload_id`
- `benchmark_class`
- `purpose`
- `intent_tags`
- `symptom_tags`
- `required_inputs`
- `artifact_paths`
- `measurement_source`
- `benchmark_entrypoint`
- `replay_entrypoint`
- `resource_profile`
- `cold_warm_expectation`
- `rch_policy`
- `mutation_policy`
- `result_schema`
- `operator_questions`
- `owning_bead_id`
- `upstream_workload_ids`
- `downstream_workload_ids`
- `failure_reason_codes`
- `validation_commands`

Missing scripts, docs, contracts, or benchmark entrypoints must not be silently
accepted. Future consumers must classify missing required sources as
`fail_closed` with stable reason codes. Optional replay entrypoints may degrade
only when the row explicitly models the missing replay surface and downstream
consumers can still produce truthful advisory output.

## Initial Workload Classes

The V1 catalog starts with these workload classes so future swarm-performance
work can route against known benchmark surfaces instead of creating duplicate
performance control planes:

| Class | Representative workload | Primary entry point |
| --- | --- | --- |
| denominator throughput | `benchmark_denominator_suite` | `scripts/run_benchmark_denominator_suite.sh` |
| extension-heavy benchmark spec | `extension_heavy_benchmark_spec` | `scripts/run_extension_heavy_benchmark_spec_suite.sh` |
| PLAS benchmark bundle | `plas_benchmark_bundle` | `scripts/run_plas_benchmark_bundle_suite.sh` |
| parser baseline artifact generation | `parser_phase0_artifact_contract` | `scripts/run_parser_phase0_artifact_contract.sh` |
| cross-repo benchmark guard | `sibling_integration_benchmark_gate` | `scripts/run_sibling_integration_benchmark_gate_suite.sh` |
| blocked FrankenEngine throughput measurement | `frankenengine_throughput_baseline_status` | `scripts/benchmarks/throughput_baselines.sh` |

## RCH Policy

Catalog rows may mention heavy benchmark validation only as advisory command
evidence. Any heavy Cargo example must start with
`rch exec -- env CARGO_TARGET_DIR=` or be routed through an existing repo-local
benchmark suite script that already enforces that wrapper. Bare `cargo check`,
`cargo clippy`, `cargo test`, `cargo bench`, or `cargo run` examples are
catalog drift and must fail closed unless the row explicitly models local
fallback contamination as blocked evidence.

The catalog producer itself does not execute Cargo or RCH. Its validation is
limited to JSON shape checks, markdown whitespace checks, and shell smoke checks
for the contract.

## Operator Status Boundary

The catalog may name the operator questions a workload answers, but
`scripts/swarm_operator_status_report.sh` remains the only predictive dashboard
producer. Later beads may hand benchmark catalog and scorer artifacts to that
producer; this contract does not create another dashboard or claim automatic
benchmark execution, automatic tuning, or queue mutation.

## Required Fail-Closed Reasons

- `FE-SWARM-BENCH-MISSING-BENCHMARK`
- `FE-SWARM-BENCH-MISSING-DOC`
- `FE-SWARM-BENCH-MISSING-CONTRACT`
- `FE-SWARM-BENCH-MALFORMED-CONTRACT`
- `FE-SWARM-BENCH-DUPLICATE-WORKLOAD`
- `FE-SWARM-BENCH-UNSAFE-MUTATION`
- `FE-SWARM-BENCH-BARE-HEAVY-CARGO`
- `FE-SWARM-BENCH-BLOCKED-MEASUREMENT`
- `FE-SWARM-BENCH-STALE-SOURCE`

## Validation

For this contract-only bead:

```bash
jq empty docs/swarm_benchmark_workload_catalog_contract_v1.json
jq -e '.required_workload_fields | index("workload_id") and index("validation_commands")' docs/swarm_benchmark_workload_catalog_contract_v1.json
jq -e '.source_inventory | length >= 6' docs/swarm_benchmark_workload_catalog_contract_v1.json
bash scripts/e2e/swarm_benchmark_workload_catalog_contract_smoke.sh check
git diff --check -- docs/SWARM_BENCHMARK_WORKLOAD_CATALOG.md docs/swarm_benchmark_workload_catalog_contract_v1.json scripts/e2e/swarm_benchmark_workload_catalog_contract_smoke.sh
```
