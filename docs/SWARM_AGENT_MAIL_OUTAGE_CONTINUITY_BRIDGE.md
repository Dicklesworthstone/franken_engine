# SWARM Agent Mail Outage Continuity Bridge

`bd-dl3q2` adds a fixture-fed bridge for sessions where Agent Mail is red,
corrupt, or unavailable but `br`, git, and RCH evidence still work. The bridge
turns preserved health/bootstrap snapshots and `br` ownership state into a
deterministic continuity report.

Machine-readable contract:
[`docs/agent_mail_outage_continuity_bridge_contract_v1.json`](./agent_mail_outage_continuity_bridge_contract_v1.json).

Implementation:
`scripts/swarm_agent_mail_outage_continuity_bridge.sh`.

## Boundary

The bridge is advisory-only and proof-only. It never sends Agent Mail, queries
live Agent Mail during validation, repairs the Agent Mail database, releases
reservations, changes contact policy, claims or closes beads, mutates git, runs
Cargo, starts `rch exec`, changes queue policy, or mutates workers.

When Agent Mail health is missing, red, corrupt, or bootstrap fails, the bridge
emits a visible `degraded` reason and falls back to `br` soft-lock evidence:

- current `br` assignee
- current bead status
- current in-progress snapshot
- optional dirty-path and reservation snapshots

The soft lock records risk. It does not prove that Agent Mail reservations or
acknowledgements exist.

## Inputs

Required:

- `--br-in-progress-json`: preserved `br list --status=in_progress --json`

Optional:

- `--mail-health-json`: captured Agent Mail `health_check`
- `--mail-bootstrap-json`: captured `macro_start_session` or registration result
- `--agent-profiles-json`: captured `list_agents` output
- `--git-status-json`: dirty-path snapshot
- `--file-reservations-json`: captured file-reservation snapshot

All inputs are files. The bridge does not call MCP tools or repair commands.

## Outputs

- `mail_outage_continuity_bridge.json`
- `soft_lock_receipts.jsonl`
- `events.jsonl`
- `commands.txt`
- `report.md`

The JSON report includes `mail_health_state`, `mail_bootstrap_state`,
`degraded_reasons`, `blocked_reasons`, `soft_lock_receipts`,
`recommended_actions`, and a non-mutating `mutation_policy`.

## Decisions

- `healthy`: supplied mail evidence is healthy and no degraded reason is found.
- `degraded`: mail is red, corrupt, missing, or bootstrap failed, but `br`
  in-progress evidence exists for soft-lock continuity.
- `blocked`: mail is unavailable and no `br` in-progress snapshot exists.

## Validation

```bash
jq empty docs/agent_mail_outage_continuity_bridge_contract_v1.json scripts/testdata/swarm_agent_mail_outage_continuity_bridge/cases.json
bash -n scripts/swarm_agent_mail_outage_continuity_bridge.sh scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh
bash scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh check
bash scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh selftest
git diff --check -- docs/SWARM_AGENT_MAIL_OUTAGE_CONTINUITY_BRIDGE.md docs/agent_mail_outage_continuity_bridge_contract_v1.json scripts/swarm_agent_mail_outage_continuity_bridge.sh scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh scripts/testdata/swarm_agent_mail_outage_continuity_bridge/cases.json
```
