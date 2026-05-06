# SWARM_STARVATION_RESCUE_INPUT_NORMALIZER

`scripts/swarm_starvation_rescue_input_normalizer.sh` converts the existing
starvation, stale-lock, salvage, admission, capacity, and high-core SLO
artifacts into one deterministic rescue-input surface for downstream
SWARM-CTRL-X planning.

It is replay-only. The script does not query live services, mutate `br`, touch
reservations, run cargo, or change worker state.

## Inputs

Required:

- `--brownout-report-json`
- `--stale-lock-recommendations-json`
- `--lease-exchange-salvage-simulation-json`
- `--admission-budget-plan-json`
- `--capacity-forecast-json`
- `--slo-threshold-receipt-json`

Optional:

- `--source-revision`
- `--now-epoch-seconds`
- `--stale-after-seconds`
- `--output-dir`

## Artifacts

- `swarm_starvation_rescue_input.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Fail-Closed Rules

- Missing or invalid required inputs fail closed.
- Stale replayable timestamps fail closed.
- Contradictory ownership from the lease/salvage simulation fails closed.
- The capacity forecast must stay `decision=pass`.
- The SLO threshold receipt must stay `decision=pass`.
- Capacity inputs that mention `local_fallback` while still reporting `pass`
  are rejected as dishonest predictive truth.

## Notes

- Brownout and admission-plan decisions are preserved as rescue signals rather
  than treated as blockers on their own.
- Some upstream artifacts do not yet publish replayable timestamps. Those inputs
  are normalized, but the report calls them out as timestampless rather than
  inventing freshness claims.

## Validation

```bash
bash -n scripts/swarm_starvation_rescue_input_normalizer.sh
bash -n scripts/e2e/swarm_starvation_rescue_input_normalizer_smoke.sh
shellcheck -x scripts/swarm_starvation_rescue_input_normalizer.sh scripts/e2e/swarm_starvation_rescue_input_normalizer_smoke.sh
jq empty docs/swarm_starvation_rescue_input_contract_v1.json
bash scripts/e2e/swarm_starvation_rescue_input_normalizer_smoke.sh check
bash scripts/e2e/swarm_starvation_rescue_input_normalizer_smoke.sh selftest
git diff --check -- scripts/swarm_starvation_rescue_input_normalizer.sh scripts/e2e/swarm_starvation_rescue_input_normalizer_smoke.sh docs/SWARM_STARVATION_RESCUE_INPUT_NORMALIZER.md docs/swarm_starvation_rescue_input_contract_v1.json
```
