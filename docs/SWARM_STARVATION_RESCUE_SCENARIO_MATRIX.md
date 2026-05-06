# SWARM_STARVATION_RESCUE_SCENARIO_MATRIX

`scripts/swarm_starvation_rescue_scenario_matrix.sh` replays fixture-fed
starvation-rescue scenarios through
`scripts/swarm_starvation_rescue_input_normalizer.sh` and emits a scrubbed
matrix report suitable for checked-in golden comparison.

The matrix exists to keep SWARM-CTRL-X scenario coverage deterministic before
the downstream planner/advisory layers are implemented.

## Inputs

Required:

- `--output-dir`

Optional:

- `--matrix-json`
- `--source-revision`

Default fixture:

- `scripts/testdata/swarm_starvation_rescue/scenario_matrix.json`

## Artifacts

- `swarm_starvation_rescue_scenario_matrix_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Covered Scenario Classes

- `healthy`
- `brownout`
- `ownership_contradiction`
- `salvage_pinned`
- `stale_telemetry`
- `local_fallback`

## Validation

```bash
bash -n scripts/swarm_starvation_rescue_scenario_matrix.sh
bash -n scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh
jq empty scripts/testdata/swarm_starvation_rescue/scenario_matrix.json
jq empty docs/swarm_starvation_rescue_scenario_matrix_contract_v1.json
bash scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh check
UPDATE_GOLDENS=1 bash scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh selftest
bash scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh selftest
git diff --check -- scripts/swarm_starvation_rescue_scenario_matrix.sh scripts/e2e/swarm_starvation_rescue_scenario_matrix_smoke.sh scripts/testdata/swarm_starvation_rescue/scenario_matrix.json scripts/testdata/goldens/swarm_starvation_rescue_scenario_matrix.golden docs/SWARM_STARVATION_RESCUE_SCENARIO_MATRIX.md docs/swarm_starvation_rescue_scenario_matrix_contract_v1.json
```
