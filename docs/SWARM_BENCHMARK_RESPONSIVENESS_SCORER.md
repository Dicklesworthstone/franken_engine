# SWARM_BENCHMARK_RESPONSIVENESS_SCORER

`bd-cppm0` defines the fixture-fed responsiveness and utilization scorer for
SWARM-BENCH-I.

The scorer consumes the normalized benchmark workload catalog plus the
normalized benchmark bundle and optionally layers in resource-envelope,
topology/locality, and proof-cache locality evidence. It does not execute
benchmarks, mutate queue state, run Cargo, run RCH, or send Agent Mail.

## Inputs

Required:

- `--normalized-workload-catalog-json FILE`
- `--normalized-benchmark-bundle-json FILE`

Optional:

- `--resource-envelope-json FILE`
- `--topology-locality-json FILE`
- `--proof-cache-locality-plan-json FILE`

## Output

The scorer emits `swarm_benchmark_responsiveness_advisory.json` plus
`events.jsonl`, `commands.txt`, and `report.md`.

The advisory includes:

- ranked bottleneck classes
- `throughput_gap_band`
- `utilization_pressure_band`
- `cold_warm_cache_recommendation`
- `remote_proof_confidence_state`
- exact advisory commands to gather or refresh evidence

## Decision Policy

- `pass`: benchmark rows are observed and optional pressure signals do not
  indicate proof, topology, or resource friction
- `degraded`: benchmark evidence is truthful but at least one blocked,
  recovered-stall, topology, proof-cache, or resource bottleneck remains
- `fail_closed`: required benchmark evidence is missing or malformed, observed
  results conflict with blocked-state claims, local fallback contamination is
  present, or the scorer would need to recommend bare heavy Cargo

## Banded Outputs

`throughput_gap_band`:

- `narrow`
- `moderate`
- `blocked_measurement`
- `contaminated`

`utilization_pressure_band`:

- `relaxed`
- `elevated`
- `saturated`
- `unknown`

`cold_warm_cache_recommendation`:

- `prefer_warm_reuse`
- `refresh_cold_target`
- `investigate_topology_locality`
- `insufficient_cache_evidence`

`remote_proof_confidence_state`:

- `confirmed`
- `degraded`
- `contaminated`

## Bottleneck Classes

The scorer may rank:

- `blocked_runtime_measurement`
- `proof_cache_rebuild_pressure`
- `topology_locality_mismatch`
- `resource_saturation`
- `remote_validation_contamination`

## Fail-Closed Rules

The scorer must fail closed when:

- the normalized workload catalog or normalized benchmark bundle is missing or
  malformed
- a normalized benchmark row claims `observed` while the bundle decision or row
  findings still preserve blocked-state truth
- a benchmark bundle finding preserves local fallback contamination
- a generated recommendation would require bare heavy Cargo instead of a script
  wrapper or already-approved safe command form

The scorer treats bare heavy Cargo as forbidden recommendation output. If a
candidate command matches `cargo check`, `cargo test`, `cargo clippy`,
`cargo run`, or `cargo bench` without an `rch exec -- env CARGO_TARGET_DIR=`
wrapper, the advisory becomes `fail_closed`.

## Validation

```bash
bash -n scripts/swarm_benchmark_responsiveness_scorer.sh
bash -n scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh
shellcheck -x scripts/swarm_benchmark_responsiveness_scorer.sh scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh
jq empty scripts/testdata/swarm_benchmark_responsiveness_scorer/cases.json
bash scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh check
bash scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh selftest
git diff --check -- docs/SWARM_BENCHMARK_RESPONSIVENESS_SCORER.md scripts/swarm_benchmark_responsiveness_scorer.sh scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh scripts/testdata/swarm_benchmark_responsiveness_scorer/cases.json
```
