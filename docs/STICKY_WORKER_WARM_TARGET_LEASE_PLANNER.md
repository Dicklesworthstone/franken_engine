# Sticky Worker Warm Target Lease Planner

`scripts/sticky_worker_warm_target_lease_planner.sh` is a deterministic shell
gate for planning repeated remote proof suites that should stay on one worker
and reuse one warm `CARGO_TARGET_DIR` across `check`, `test`, and `clippy`.

It is planning-only:

- it does not query live `rch`
- it does not execute Cargo
- it does not mutate reservations or bead state

## Contract

Output schema: `franken-engine.sticky-worker-warm-target-lease-plan.v1`

Required inputs:

- `--agent-id`
- `--bead-id`
- `--suite-manifest-json`
- `--rch-workers-json`

Optional inputs:

- `--sticky-worker-state-json`
- `--reservation-snapshot-json`
- `--local-fallback-markers-json`

Artifacts:

- `sticky_worker_warm_target_plan.json`
- `sticky_worker_warm_target_summary.md`
- `commands.txt`
- `events.jsonl`

## Decision Surface

The planner emits one of four decisions:

- `admit_sticky`
  The preferred worker is idle or available, and the warm target-dir is not
  held by another agent.
- `admit_fallback_worker`
  The preferred worker is unavailable, but another idle worker exists, so the
  suite is rerouted to one fallback worker with one fresh target-dir.
- `defer_conflicting_target_dir`
  The preferred warm target-dir is still held by another agent. The planner
  does not silently steal or reuse it.
- `fail_closed`
  A preserved local-fallback marker shows that the suite previously degraded to
  local execution. The planner rejects reuse until that evidence is cleared.

## Operator Flow

Operators should pass preserved suite manifests and snapshots rather than live
service queries. The suite commands should remain
`rch exec -- env CARGO_TARGET_DIR=...` wrapped so worker assignment is
explicit.

Example:

```bash
./scripts/sticky_worker_warm_target_lease_planner.sh \
  --agent-id CyanOak \
  --bead-id bd-lviqm \
  --suite-manifest-json /tmp/suite-manifest.json \
  --sticky-worker-state-json /tmp/sticky-worker-state.json \
  --rch-workers-json /tmp/rch-workers.json \
  --reservation-snapshot-json /tmp/agent-mail-reservations.json \
  --local-fallback-markers-json /tmp/rch-local-fallback-markers.json
```

## Validation

```bash
bash -n scripts/sticky_worker_warm_target_lease_planner.sh
bash -n scripts/e2e/sticky_worker_warm_target_lease_planner_smoke.sh
bash scripts/e2e/sticky_worker_warm_target_lease_planner_smoke.sh check
bash scripts/e2e/sticky_worker_warm_target_lease_planner_smoke.sh selftest
```
