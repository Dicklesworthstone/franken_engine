# Swarm Warm Target Prefetch ROI Advisory

`scripts/swarm_warm_target_prefetch_roi_advisory.sh` composes predictive swarm
admission evidence with proof-cache reuse, warm-target ROI, archive pressure,
and replay-trace cost signals to recommend whether any bounded prefetch is
worth doing.

The advisory is fixture-fed and report-only. It does not execute Cargo, fetch
artifacts, or mutate warm target directories. It exists to answer a narrower
question than the underlying ledgers: when do the existing cache, archive, and
warm-target surfaces justify prewarming or archive prefetch, and when should
operators explicitly not do that?

## Purpose

The advisory reuses existing surfaces rather than introducing a second cache or
archive policy dialect:

- `scripts/proof_reuse_cache_planner.sh`
- `scripts/warm_target_roi_eviction_ledger.sh`
- `scripts/sticky_worker_warm_target_lease_planner.sh` through the ROI ledger
- `scripts/remote_proof_archive_pressure_scoreboard.sh`
- `scripts/proof_economy_replay_trace_normalizer.sh`
- `scripts/swarm_admission_budget_planner.sh`
- `scripts/swarm_capacity_forecaster.sh`

It publishes deterministic guidance that:

- recommends hot-cache reuse when ROI is already strong and the cache is valid
- recommends archive-backed refresh only when stale cache plus high ROI justify
  bounded prefetch
- blocks prefetch under disk pressure, low ROI, missing archive truth, or
  salvage-pinned evidence
- uses replay-trace command costs to avoid treating trivial proof work as worth
  warming

## Inputs

Required:

- `--capacity-forecast-json`
- `--admission-budget-plan-json`
- `--proof-cache-plan-json`
- `--warm-target-roi-ledger-json`
- `--archive-pressure-scoreboard-json`
- `--replay-trace-json`

The advisory relies on the shipped meanings of:

- `proof_cache_decision`
- `warm_target_roi_ledger.decision`
- `archive_pressure_scoreboard.advisory`
- replay-trace `command_rows[].estimated_cpu_slots`

## Output

The advisory writes:

- `swarm_warm_target_prefetch_roi_advisory.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The main advisory artifact publishes:

- `advisory`
- `recommended_action`
- `reason`
- `forecast_summary`
- `budget_summary`
- `proof_cache_summary`
- `warm_target_summary`
- `archive_pressure_summary`
- `validation_cost_summary`
- `recommended_prefetches`
- `policy_findings`

## Advisory Outcomes

- `reuse_hot_cache`
  - bounded hot-cache reuse is already justified
- `prefetch_archive`
  - stale cache plus high ROI justify archive-backed refresh
- `defer`
  - prefetch is not safe or not worth it under current pressure or ROI
- `fail_closed`
  - cache or archive truth is too weak to make an honest prefetch recommendation

## Truth Constraints

- The advisory must remain report-only.
- Salvage-pinned or orphan-reconciliation evidence must block prefetch rather
  than being treated as evictable or refreshable.
- Missing archive truth must fail closed rather than guessing a prefetch path.
- Low-cost replay traces must not claim that warming is justified when the
  reuse ledger already says otherwise.

## Validation

```bash
bash -n scripts/swarm_warm_target_prefetch_roi_advisory.sh
bash -n scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh
shellcheck -x scripts/swarm_warm_target_prefetch_roi_advisory.sh scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh
jq empty docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json
./scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh check
./scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh selftest
```
