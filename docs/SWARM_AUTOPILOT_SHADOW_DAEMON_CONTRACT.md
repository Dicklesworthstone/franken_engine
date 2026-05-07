# SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT

`docs/swarm_autopilot_shadow_daemon_contract_v1.json` defines the
contract-only surface for a continuous shadow daemon that observes swarm state
and emits advisory operator evidence without mutating live systems.

This contract opens the `bd-djejh` track and feeds these follow-on beads:

- `bd-djejh.2` frankensqlite-backed shadow evidence journal
- `bd-djejh.3` one-shot source watchers
- `bd-djejh.4` advisory decision composer
- `bd-djejh.5` replay and drift verifier
- `bd-djejh.6` no-mock lifecycle drill
- `bd-djejh.7` frankentui and optional fastapi_rust handoff
- `bd-djejh.8` adoption and mutation-policy gates

The daemon is advisory only. It may produce commands that a human or agent can
run separately, but it must not execute br, Agent Mail, rch, git, worker, or
queue mutations.

## Required Sources

The shadow daemon consumes normalized one-shot snapshots from:

- `br_queue_snapshot_json`
- `bv_robot_plan_json`
- `agent_mail_snapshot_json`
- `rch_status_snapshot_json`
- `git_state_snapshot_json`
- `artifact_bundle_snapshot_json`

Optional operator overrides may add context, but they cannot authorize mutation
inside the daemon. Missing optional overrides never upgrade a degraded decision
to confirmed.

Every source snapshot must include:

- source id
- source kind
- content hash
- collection timestamp
- freshness window
- freshness and degradation flags
- raw payload path or stable inline payload hash
- error codes when degraded, blocked, or contaminated

## Derived Artifacts

The contract defines these derived artifact families:

- source snapshots
- journal events
- shadow status reports
- recommendation bundles
- truth-gate reports

The implementation track must persist journal events through `/dp/frankensqlite`
integration points. It must not create an ad hoc local SQLite framework. TUI
handoff belongs to `/dp/frankentui`; any service/API surface belongs to
`/dp/fastapi_rust` when needed.

## Truth States

- `confirmed`: required snapshots are fresh, non-contradictory, and complete
- `degraded`: required snapshots are present but one or more sources report a
  degraded/read-only/offline state that still has enough evidence for advisory
  output
- `blocked`: missing, stale, malformed, or contradictory required snapshots
  prevent truthful recommendation
- `contaminated`: local fallback or mutation contamination is present and must
  fail closed

## Fail-Closed Rules

- Missing required snapshots fail closed.
- Stale required snapshots fail closed.
- Malformed snapshot payloads fail closed.
- Contradictory bead ownership fails closed.
- Unsupported mutation claims fail closed.
- Local rch fallback contamination fails closed.
- Dirty shared worktree ambiguity degrades or blocks according to source
  freshness.
- Recommendations must cite source event ids, content hashes, timestamps, and
  degradation state.

Operator wording is fixed as advisory only, proof only, no daemon mutation, no
bead mutation, no Agent Mail mutation, no rch execution, no git mutation, no
worker mutation, and no queue mutation.

## Fixture Cases

The smoke harness proves these contract cases:

- `healthy_advisory_output`
- `stale_source_refusal`
- `unsupported_mutation_claim`
- `degraded_agent_mail_rch_sources`

## Validation

```bash
jq empty docs/swarm_autopilot_shadow_daemon_contract_v1.json scripts/testdata/swarm_autopilot_shadow_daemon_contract/cases.json
bash -n scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh
bash scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh check
bash scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md docs/swarm_autopilot_shadow_daemon_contract_v1.json scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh scripts/testdata/swarm_autopilot_shadow_daemon_contract/cases.json
```
