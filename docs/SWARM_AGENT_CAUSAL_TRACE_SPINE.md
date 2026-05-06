# SWARM_AGENT_CAUSAL_TRACE_SPINE

The swarm agent causal trace spine is the SWARM-CTRL-XVI evidence contract for
linking live-agent coordination artifacts into one replayable handoff record.

The initial surface is fixture-fed and advisory-only. It helps an operator
answer which agent claimed a bead, which paths were reserved, what Agent Mail
coordination happened, which RCH or validation proof artifacts were produced,
which commit closed the bead, and where the handoff degraded. It does not query
live services or mutate `br`, Agent Mail, file reservations, remote workers, or
queue policy.

Machine-readable contract:
`docs/swarm_agent_causal_trace_spine_contract_v1.json`.

## Source Inventory

The trace spine accepts preserved snapshots from existing operator workflows:

- `br issue snapshot`: `br show <bead-id> --json`
- `br ready/list snapshot`: `br ready --json` or `br list --json`
- `br sync status`: `br sync --status --json`
- `bv plan`: `bv --recipe actionable --robot-plan`
- `Agent Mail profiles`: `list_agents` output
- `Agent Mail messages`: inbox/thread search output for the bead thread
- `file reservations`: active reservation snapshot
- `git status`: scoped dirty/staged path snapshot
- `git commits`: closeout commit mapping or `git log -- <paths>` evidence
- `RCH validation`: policy gate, run manifest, or command transcript artifacts
- `operator status`: optional `scripts/swarm_operator_status_report.sh` output

Missing optional snapshots must be visible degraded evidence. Missing required
identity fields, contradictory ownership, local RCH fallback in a remote proof,
or a closed bead without closeout evidence must fail closed.

## Event Spine

Downstream producers should normalize every source into stable event rows with:

- `event_id`
- `event_type`
- `bead_id`
- `agent_name`
- `thread_id`
- `source_revision`
- `source_path`
- `artifact_path`
- `content_hash`
- `observed_at`
- `decision`
- `degraded_reasons`
- `fail_closed_reasons`

The graph layer then links events with typed causal edges such as:

- `agent_introduced`
- `bead_claimed`
- `reservation_covers_path`
- `message_acknowledged`
- `validation_proves_closeout`
- `commit_closes_bead`
- `operator_status_summarizes_trace`

## Mutation Boundary

The trace spine is proof-only. It never:

- updates or reopens beads
- clears assignees
- releases file reservations
- sends Agent Mail
- starts RCH or Cargo commands
- changes live queue policy
- mutates remote workers
- rewrites historical closeout evidence

Operator remediation remains manual or agent-executed outside this artifact, and
must be reported through the normal bead and Agent Mail workflow.

## Fail-Closed Classes

The first implementation track must preserve these anomaly classes:

- `missing_claim_message`
- `missing_reservation_for_dirty_path`
- `reservation_without_matching_bead_scope`
- `local_rch_fallback_contaminates_remote_proof`
- `closed_bead_missing_commit`
- `closed_bead_missing_validation_evidence`
- `ack_required_message_unacknowledged`
- `stale_owner_recent_activity_conflict`

## Planned Producers

SWARM-CTRL-XVI child beads define the producer chain:

- `scripts/swarm_agent_causal_trace_normalizer.sh`
- `scripts/swarm_agent_causal_trace_graph.sh`
- `scripts/swarm_operator_status_report.sh`
- `scripts/e2e/swarm_agent_causal_trace_no_mock_drill.sh`
- `scripts/e2e/swarm_agent_causal_trace_runbook_truth_gate.sh`

## Validation

```bash
jq empty docs/swarm_agent_causal_trace_spine_contract_v1.json
git diff --check -- docs/SWARM_AGENT_CAUSAL_TRACE_SPINE.md docs/swarm_agent_causal_trace_spine_contract_v1.json
```
