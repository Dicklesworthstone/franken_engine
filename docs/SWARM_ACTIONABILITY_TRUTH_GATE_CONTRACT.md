# SWARM_ACTIONABILITY_TRUTH_GATE_CONTRACT

`bd-1tsvb` defines the V1 contract for a lightweight actionability truth gate.
The gate exists because agents need one deterministic pre-claim answer when
`br ready` and `bv --recipe actionable --robot-plan` disagree, or when ownership
and dirty-worktree evidence make a candidate unsafe.

The gate is advisory only and proof only.
It must not claim, reopen, close, or reassign beads.
It must not release reservations, send Agent Mail, mutate git, run Cargo, run RCH,
mutate remote workers, or change live queue policy.

## Required Inputs

- `br_ready_json`: output equivalent to `br ready --json`
- `br_open_json`: open bead list with status, priority, dependencies, and labels
- `br_in_progress_json`: in-progress bead list with assignee and update time
- `br_blocked_json`: blocked bead list with status and blocker metadata
- `bv_robot_plan_json`: output equivalent to `bv --recipe actionable --robot-plan`
- `agent_mail_snapshot_json`: agent activity and file reservation snapshot
- `git_status_snapshot_json`: branch, ahead/behind, and dirty path summary
- `source_freshness_json`: freshness and source collection metadata

## Decisions

- `safe_to_claim`: candidate is present in `br_ready_json`, open, unassigned,
  not blocked, not in progress, has no active conflicting reservation, and has no
  dirty-file overlap.
- `defer`: candidate is plausibly valid but currently owned, reserved, stale, or
  blocked by temporary source ambiguity.
- `fail_closed`: sources contradict each other, a blocked or in-progress bead is
  advertised as actionable, source freshness is untrusted, or a mutation claim is
  detected.
- `observe_only`: no safe claim exists, but the report still provides diagnostic
  state for operators.

## Required Fail-Closed Reasons

- `FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE`
- `FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE`
- `FE-SWARM-ACTIONABILITY-BR-BV-DIVERGENCE`
- `FE-SWARM-ACTIONABILITY-STALE-EXPORTED-STATE`
- `FE-SWARM-ACTIONABILITY-ACTIVE-RESERVATION`
- `FE-SWARM-ACTIONABILITY-DIRTY-OVERLAP`
- `FE-SWARM-ACTIONABILITY-MISSING-SOURCE`
- `FE-SWARM-ACTIONABILITY-MALFORMED-SOURCE`
- `FE-SWARM-ACTIONABILITY-UNSUPPORTED-MUTATION`

## Required Outputs

The implementation bead must emit an actionability report with:

- schema version
- source revision
- decision
- candidate summary
- candidate reports with source ids and evidence paths
- fail-closed reasons
- advisory remediation commands
- source freshness summary
- mutation policy

The contract smoke gate proves this contract is stable before implementation.
It checks exact source IDs, decision vocabulary, fail-closed reason coverage,
required fixture scenarios, and advisory-only mutation policy.

## Required Operator Workflow

- Run `scripts/swarm_actionability_truth_gate.sh` before any claim or reassignment driven by `bv --recipe actionable --robot-plan`.
- Treat safe_to_claim as advisory only. Operators must still rerun `br show <id>` and `br list --status=in_progress --json` immediately before `br update --assignee`.
- Treat `defer` as do-not-claim guidance. Ownership and reservations stay
  unchanged until the conflicting evidence clears.
- Treat `fail_closed` as do-not-claim guidance. The emitted bundle must be
  preserved for diagnostics, and fresh blocked-versus-actionable divergence
  evidence must be attached to the upstream follow-up bead `bd-5oef0` instead
  of being masked locally.
- Treat `observe_only` as diagnostics only. It never authorizes a claim.

## Required Mutation-Policy Scanner

The contract smoke must scan the observe-only actionability runners and reject
direct calls to:

- `br update`, `br close`, `br reopen`, `br create`, and `br claim`
- Agent Mail mutation APIs
- git mutation commands
- heavy Cargo commands
- `rch exec`

This scanner exists to prove the actionability adoption surface remains
observe-only even as future workflow automation and replay harnesses evolve.
