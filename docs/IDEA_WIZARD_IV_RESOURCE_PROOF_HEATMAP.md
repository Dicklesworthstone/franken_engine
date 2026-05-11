# IDEA-WIZARD-IV Resource Proof Heatmap

`bd-my2jw` adds an advisory heatmap integrator for high-core validation hosts.
It consumes preserved RCH, target-dir, proof-cache, archive-pressure, pressure,
resource-envelope, and validation-impact evidence and emits one scheduling
packet for the saturation control plane.

The integrator reuses existing surfaces instead of probing workers directly:

| Existing surface | Reused evidence |
| --- | --- |
| `swarm_resource_envelope_normalizer` | host, memory, disk, RCH, target-dir, and coordination pressure vocabulary |
| `swarm_rch_target_dir_heatmap` | target-dir heat, warm-cache class, and local-fallback contamination rules |
| `swarm_proof_cache_locality_optimizer` | proof-cache residency and reuse/cold-cache advice |
| `remote_proof_archive_pressure_scoreboard` | archive pressure and retention/defer guidance |
| `idea_wizard_iv_validation_impact_planner` | recommended proof commands and expected cost class |

## Inputs

Required:

- `--rch-status-json FILE`

Optional:

- `--queue-depth-json FILE`
- `--target-dir-heatmap-json FILE`
- `--proof-cache-locality-json FILE`
- `--pressure-metrics-json FILE`
- `--validation-impact-plan-json FILE`
- `--archive-pressure-json FILE`
- `--resource-envelope-json FILE`

Missing optional metrics are degraded evidence, not success. Local fallback
contamination fails closed because it invalidates remote-only proof scheduling.

## Artifacts

Each run emits:

- `resource_proof_heatmap.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `report.md`

The heatmap includes `schema_version`, `source_revision`, `decision`,
`classification`, `worker_pressure`, `cache_heat`, `memory_headroom_class`,
`scheduling_advice`, `degraded_reasons`, `fail_closed_reasons`,
`source_surface_refs`, `mutation_policy`, `rch_policy`, and `artifact_paths`.

## Mutation Boundary

The script is proof-only and advisory-only. It does not run Cargo, run RCH,
delete target directories, mutate remote workers, claim slots, change queue
policy, or repair any upstream surface. It may emit RCH-wrapped commands as
operator guidance only.

## Validation

```bash
bash -n scripts/idea_wizard_iv_resource_proof_heatmap.sh
bash -n scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh
bash scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh check
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP.md scripts/idea_wizard_iv_resource_proof_heatmap.sh scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
