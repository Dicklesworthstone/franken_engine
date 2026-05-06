# Swarm Admission Budget Planner

`scripts/swarm_admission_budget_planner.sh` converts predictive capacity
forecasts into bounded dry-run admission budgets for swarm validation work.

The planner is fixture-fed only. It does not query live `br`, Agent Mail, or
`rch`, execute Cargo, or mutate workers. It consumes the predictive forecast as
the primary envelope and can optionally tighten decisions with:

- `franken-engine.swarm-validation-plan.v1`
- `franken-engine.swarm-resource-decision.v1`
- `franken-engine.swarm-resource-lease-plan.v1`

## Purpose

The planner sits between the predictive forecaster and any future operator
dashboard or admission wrapper. Its job is to publish deterministic, replayable
budgets that:

- protect P1 and P2 proof obligations under pressure
- throttle P3 and speculative work first
- bound per-agent admission so one worker cannot monopolize the queue
- downgrade heavy work to `admit_narrow` when forecasted risk is non-normal
- enter deterministic safe mode when the forecast itself is unavailable

This planner is not a replacement for `br` / `bv` priority ordering. It only
turns already-ranked work into bounded admission recommendations.

## Inputs

Required:

- `--capacity-forecast-json`
- `--admission-requests-json`

Optional compatibility inputs:

- `--validation-plan-json`
- `--resource-decision-json`
- `--resource-lease-plan-json`

The request-set fixture uses
`franken-engine.swarm-admission-request-set.v1` with bounded rows such as:

- `agent_id`
- `bead_id`
- `bead_priority`
- `requested_command`
- `heavy_rust`
- `proof_obligation`
- `speculative`
- `docs_only`
- `planned_write_paths`
- `requires_ownership_confirmation`

## Output

The planner writes:

- `swarm_admission_budget_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The main plan artifact publishes:

- global `decision`: `admit`, `admit_narrow`, or `defer`
- `budget_profile`: `normal`, `degraded`, `high_pressure`, or `safe_mode`
- per-priority budgets for `P1`, `P2`, and `P3`
- per-agent admitted-request budgets
- one recommendation row per request with explicit reasons

## Budget Profiles

### `normal`

- P1 and protected P2 proof obligations are admitted.
- P3 or speculative work is narrowed first.
- Per-agent fairness still caps admitted requests.

### `degraded`

- P1 stays admitted.
- Protected P2 requests are narrowed.
- P3 and speculative work are deferred.

### `high_pressure`

- Protected work survives only as `admit_narrow`.
- Non-protected heavy or speculative work is deferred.
- Focused heavy admissions are sharply capped.

### `safe_mode`

- Entered when the predictive forecast is present but not `pass`.
- Protected work receives deterministic `admit_narrow`.
- Speculative work is deferred.
- This is the required fallback when forecast evidence is unavailable.

## Truth Constraints

- The planner must remain fixture-fed and replayable.
- Missing optional compatibility inputs may degrade reasoning, but they must not
  trigger live queries.
- Missing or malformed required inputs are hard failures.
- Safe mode must preserve protected P1/P2 proof work without widening into
  speculative or ownership-conflicting commands.
- The planner must not claim beads, change reservations, mutate workers, or run
  the recommended commands.

## Validation

```bash
bash -n scripts/swarm_admission_budget_planner.sh
bash -n scripts/e2e/swarm_admission_budget_planner_smoke.sh
shellcheck -x scripts/swarm_admission_budget_planner.sh scripts/e2e/swarm_admission_budget_planner_smoke.sh
jq empty docs/swarm_admission_budget_planner_contract_v1.json
./scripts/e2e/swarm_admission_budget_planner_smoke.sh check
./scripts/e2e/swarm_admission_budget_planner_smoke.sh selftest
```
