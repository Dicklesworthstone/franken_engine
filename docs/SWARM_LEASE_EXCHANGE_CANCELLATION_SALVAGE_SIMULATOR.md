# Swarm Lease Exchange And Cancellation Salvage Simulator

`scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh` publishes a
deterministic counterfactual report for blocked or degraded proof work. It
combines stale-lock ownership evidence, admission-budget decisions, lease-plan
pressure, and archive-salvage posture into ranked dry-run recommendations.

The simulator is fixture-fed only. It must not query live `br`, mutate Agent
Mail reservations, kill processes, or release live workers. Its purpose is to
show what a lease exchange or cancellation-to-salvage promotion would relieve
without performing the action.

## Purpose

The simulator sits after:

- `scripts/stale_lock_stalled_bead_recommender.sh`
- `scripts/swarm_admission_budget_planner.sh`
- `scripts/swarm_resource_lease_planner.sh`
- `scripts/remote_proof_gc_guard.sh`
- `scripts/remote_proof_archive_pressure_scoreboard.sh`

It turns those point-in-time artifacts into a report that:

- ranks lease-exchange candidates when stale ownership is reclaimable
- models cancellation-to-salvage promotion for degraded proof work
- preserves archive and salvage truth when evidence is still pinned
- fails closed when ownership evidence is missing or contradictory
- leaves a replay-friendly `commands.txt` proving that no mutation commands ran

## Inputs

Required:

- `--stale-lock-recommendations-json`
- `--admission-budget-plan-json`
- `--resource-lease-plan-json`
- `--gc-guard-report-json`
- `--archive-pressure-scoreboard-json`

Optional Agent Mail compatibility inputs:

- `--reservation-snapshot-json`
- `--agent-profiles-json`

The stale-lock artifact remains the primary ownership source. Optional Agent
Mail snapshots are only used to confirm or contradict that ownership signal.

## Output

The simulator writes:

- `lease_exchange_cancellation_salvage_simulation.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The main simulation artifact publishes:

- global `decision`: `advisory`, `manual_review_required`, or `fail_closed`
- one ranked recommendation row per admission request
- explicit ownership status: `stale_reclaimable`, `active_owner`,
  `contact_first`, `manual_confirmation_required`, `missing`, or
  `contradictory`
- score components for bottleneck relief, fairness impact, artifact
  preservation, and coordination risk
- counterfactual next-step summaries for lease exchange, salvage promotion, or
  preserve-only outcomes

## Truth Constraints

- The simulator must remain report-only and replayable.
- Missing or contradictory ownership evidence must force `fail_closed`.
- Manual-confirmation evidence may downgrade the report to
  `manual_review_required`, but it must not widen into auto-exchange.
- Salvage-pinned archive evidence must prefer preserve-only outcomes over any
  simulated pressure relief.
- `commands.txt` must only record the simulator invocation; it must not imply
  `br update`, reservation release, or process-kill behavior.

## Validation

```bash
bash -n scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh
bash -n scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh
shellcheck -x scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh
jq empty docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json
./scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh check
./scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh selftest
```
