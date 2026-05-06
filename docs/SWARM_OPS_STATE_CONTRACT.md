# SWARM_OPS_STATE_CONTRACT

The SWARM-OPS-P0 state contract defines the advisory evidence bundle that later
swarm operations lanes consume before making resource, queue, reservation, or
proof-cache recommendations.

Machine-readable contract:
`docs/swarm_ops_state_contract_v1.json`.

Smoke gate:
`scripts/e2e/swarm_ops_state_contract_smoke.sh`.

Fixture cases:
`scripts/testdata/swarm_ops_state_contract/cases.json`.

## Source Inventory

The state bundle is assembled from existing coordination and proof surfaces:

- `br ready --json`, `br list --status=in_progress --json`, and
  `br sync --status --json` for queue readiness, live claims, JSONL freshness,
  and DB/export truth.
- `bv --recipe actionable --robot-plan` for ranked advisory work tracks.
- Agent Mail agent, inbox, contact, and reservation snapshots for ownership and
  file-reservation evidence.
- `rch status --workers --jobs --json`, `rch queue --json`, and worker health
  reports for remote execution state, degraded worker state, and stall evidence.
- `git status --short` and scoped `git diff --check -- <paths>` for dirty
  workspace evidence and unowned write-surface contamination.
- Existing proof-cache and locality artifacts, including the SWARM-SCALE-II
  topology placement outputs once they exist, for warm target reuse decisions.

The bundle records evidence. It is not an autonomous operator.

## Bundle Semantics

The canonical output schema is
`franken-engine.swarm-ops-state-bundle.v1`. A complete bundle must include:

- `swarm_ops_state_bundle.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The state bundle must sort source rows before hashing and must carry explicit
source commands, capture timestamps, source revision, freshness state, trust
state, and artifact paths. Optional missing evidence remains visible as
`degraded`. Missing required coordination evidence, stale DB/JSONL truth,
contradictory capacity inputs, or dirty unowned write paths must block or fail
closed.

## Trust And Freshness

Every component reports both a freshness state and a trust state:

- `fresh` means captured inside the accepted freshness window.
- `stale` means the source exists but exceeds the accepted window or conflicts
  with `br sync --status`.
- `missing` means the source is absent.
- `trusted` means the source is coherent with the other required surfaces.
- `degraded` means advisory output may continue only with visible loss of
  optional evidence.
- `blocked` means operator action is required before recommendations are safe.
- `fail_closed` means the bundle cannot support an advisory claim.

## Proof Categories

The smoke fixtures lock four first-class cases:

- `healthy`: all required sources are fresh and coherent.
- `stale_jsonl`: live `br` DB state is newer than `.beads/issues.jsonl`.
- `mail_missing`: Agent Mail is unavailable or missing required snapshots.
- `rch_degraded`: RCH worker or queue evidence is degraded but not contradictory.

Later producer beads may add stricter cases, but they must keep these four
semantics stable.

## Event Keys

Every emitted `events.jsonl` row must include these stable keys:

- `trace_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `evidence_path`

The smoke gate verifies those keys in `selftest` mode.

## Fail-Closed Classes

Later producers must keep these classes explicit:

- `stale_br_jsonl`
- `missing_agent_mail_snapshot`
- `degraded_rch_worker_state`
- `worker_stall_without_bundle`
- `dirty_unowned_files`
- `contradictory_capacity_inputs`
- `missing_required_source`
- `unsafe_live_mutation_claim`

## Mutation Boundary

The SWARM-OPS state contract is fixture-fed, proof-only, and advisory-only. It
never:

- does not update, close, reopen, or reassign beads
- does not release file reservations
- does not send Agent Mail
- does not query live Agent Mail during smoke validation
- does not run Cargo or RCH
- does not mutate remote workers
- does not change active queue policy
- does not repair target directories
- does not write outside the requested output directory

## Validation

```bash
jq empty docs/swarm_ops_state_contract_v1.json scripts/testdata/swarm_ops_state_contract/cases.json
bash -n scripts/e2e/swarm_ops_state_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_ops_state_contract_smoke.sh
bash scripts/e2e/swarm_ops_state_contract_smoke.sh check
bash scripts/e2e/swarm_ops_state_contract_smoke.sh run /tmp/swarm-ops-state-contract
bash scripts/e2e/swarm_ops_state_contract_smoke.sh selftest
git diff --check -- docs/SWARM_OPS_STATE_CONTRACT.md docs/swarm_ops_state_contract_v1.json scripts/e2e/swarm_ops_state_contract_smoke.sh scripts/testdata/swarm_ops_state_contract
```
