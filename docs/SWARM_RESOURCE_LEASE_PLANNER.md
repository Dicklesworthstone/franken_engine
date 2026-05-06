# Swarm Resource Lease Planner

`scripts/swarm_resource_lease_planner.sh` is a deterministic shell/JSON gate
for requesting resource leases before agents start validation work in large
swarm sessions. It is fixture-driven: callers pass snapshots from `br`, Agent
Mail reservations, rch worker state, and dirty worktree state. The script does
not query live services, execute Cargo, reserve files, or mutate bead state.

## Contract

Output schema: `franken-engine.swarm-resource-lease-plan.v1`

The lease plan includes:

- `agent_id`
- `bead_id`
- `requested_command`
- `estimated_cpu_slots`
- `estimated_memory_class`
- `target_dir`
- `lease_decision`
- `lease_ttl_seconds`
- `reason`
- `safe_alternatives`

Artifacts:

- `resource_lease_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Operator Flow

Agents should request a lease before starting heavy validation:

```bash
./scripts/swarm_resource_lease_planner.sh \
  --agent-id ScarletOwl \
  --bead-id bd-x82vp \
  --requested-command "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_x82vp cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts" \
  --estimated-cpu-slots 4 \
  --estimated-memory-class large \
  --target-dir /tmp/rch_target_franken_engine_bd_x82vp \
  --reservation-snapshot-json /tmp/agent-mail-reservations.json \
  --br-snapshot-json /tmp/br-in-progress.json \
  --rch-workers-json /tmp/rch-workers.json \
  --dirty-files-json /tmp/git-dirty-files.json
```

The planner admits light shell work directly, admits focused rch work when an
idle worker and target directory are available, denies over-budget fanout,
defers target-dir conflicts and all-workers-busy states, and emits degraded
`admit_narrow` plans when required snapshots are missing. Heavy Cargo commands
must stay `rch exec -- env CARGO_TARGET_DIR=...` wrapped; observed local rch
fallback fails closed.

## Validation

```bash
bash -n scripts/swarm_resource_lease_planner.sh
bash -n scripts/e2e/swarm_resource_lease_planner_smoke.sh
./scripts/e2e/swarm_resource_lease_planner_smoke.sh check
./scripts/e2e/swarm_resource_lease_planner_smoke.sh selftest
```
