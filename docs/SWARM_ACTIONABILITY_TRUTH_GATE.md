# SWARM_ACTIONABILITY_TRUTH_GATE

`scripts/swarm_actionability_truth_gate.sh` implements the actionability report
described by `docs/SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT.md`.

The gate is advisory only and proof only.
It must not claim, reopen, close, or reassign beads.
It must not release reservations, send Agent Mail, mutate git, run Cargo, run
RCH, mutate remote workers, or change live queue policy.

## Inputs

The script accepts preserved snapshots for:

- `br_ready_json`
- `br_open_json`
- `br_in_progress_json`
- `br_blocked_json`
- `bv_robot_plan_json`
- `git_status_snapshot_json`
- `source_freshness_json`
- optional `agent_mail_snapshot_json`

It also supports `--collect-live` for lightweight local collection of the `br`,
`bv`, and `git` sources when preserved files are not supplied.

## Decisions

- `safe_to_claim`: a bead is ready in `br`, present as actionable in `bv`, and
  has no ownership, reservation, freshness, or dirty-overlap conflicts.
- `defer`: the candidate is known but currently owned, reserved, or dirtied by
  an overlapping surface.
- `fail_closed`: tracker freshness is stale, `bv` promotes a blocked bead, or
  `br` and `bv` disagree about claimability.
- `observe_only`: no safe candidate exists, but the report remains useful for
  operator diagnostics.

## Adoption Workflow

- Run `scripts/swarm_actionability_truth_gate.sh` before any claim or reassignment driven by `bv --recipe actionable --robot-plan`.
- A `safe_to_claim` result is advisory only. Operators must still rerun
  `br show <id>` and `br list --status=in_progress --json` immediately before
  `br update --assignee`.
- `defer` means do not claim. Leave ownership and reservations unchanged, then
  move to a non-overlapping bead or wait for the conflicting evidence to clear.
- `fail_closed` means do not claim. Preserve the emitted bundle, and if fresh
  `br` plus `bv` evidence still reproduces the blocked-versus-actionable
  divergence, update the upstream follow-up bead `bd-5oef0` instead of masking
  the planner bug.
- `observe_only` is diagnostics only and never authorizes a claim.

The gate does not file or update upstream follow-up beads by itself. It only
preserves the evidence bundle needed for an operator to attach or refresh that
external-tool follow-up manually.

## Reason Codes

- `FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE`
- `FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE`
- `FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE`
- `FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE`
- `FE-SWARM-ACTIONABILITY-ACTIVE-RESERVATION`
- `FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP`
- `FE-SWARM-ACTIONABILITY-MISSING-SOURCE`
- `FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE`

## Outputs

The script writes:

- `actionability_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`actionability_report.json` includes the final decision, candidate reports,
reason codes, source freshness, remediation commands, and the advisory-only
mutation policy.
