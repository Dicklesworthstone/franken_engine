# SWARM_EXECUTION_QUEUE_CONTRACT

SWARM-CTRL-XII turns the existing Rust `SwarmControlLoop` model into a
replayable operator queue lane. The lane is advisory evidence only: it ranks
what a large agent swarm should start, defer, or review next, but it never
updates beads, reassigns ownership, releases reservations, sends Agent Mail, or
mutates remote workers.

## Purpose

The project already emits admission budgets, proof-queue brownout reports,
stale-lock recommendations, salvage receipts, checkpoint restore plans, and
operator status reports. This contract defines the missing bridge between those
surfaces and `crates/franken-engine/src/swarm_control_loop.rs`.

The bridge normalizes fixed snapshots into `TaskNode`-like rows and
cross-cutting health signals, runs the control-loop queue computation, and emits
deterministic artifacts that explain:

- which beads are ready now,
- which beads are ready next but blocked by stale ownership or proof pressure,
- which beads are deferred by conservative risk-budget mode,
- which bottlenecks should be contacted first, and
- which proof or coordination signal caused the fallback action.

## Required Inputs

The input normalizer must accept fixture or captured snapshots equivalent to:

- `br ready --json`
- `br list --json`
- `bv --recipe actionable --robot-plan`
- Agent Mail agent profiles and recent message timestamps
- file reservation summaries
- stale-lock recommender output
- proof-transport or brownout/admission evidence

Missing optional evidence is degraded evidence, not success. Malformed required
`br` or `bv` shapes fail closed.

## Normalized Task Fields

Every normalized task row must include:

- `task_id`
- `title`
- `status`
- `priority`
- `assignee`
- `depends_on`
- `dependents`
- `completed`
- `open_blocker_count`
- `owner_freshness`
- `reservation_pressure`
- `proof_transport`
- `scores.impact_millionths`
- `scores.confidence_millionths`
- `scores.reuse_millionths`
- `scores.effort_millionths`
- `scores.friction_millionths`
- `fallback_trigger`
- `first_action`

`first_action` is mandatory even for deferred tasks so the operator sees a next
step instead of a silent rank.

## Output Artifacts

Complete runs must emit:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `normalized_input.json`
- `execution_queue_artifact.json`
- `risk_budget_receipt.json`
- `bottleneck_report.json`
- `operator_summary.md`

The queue artifact must preserve `SwarmControlLoop` semantics: wave ordering,
EV/relevance scoring, bounded queue depth, risk-budget conservative mode,
rationale deltas, and bottleneck severity.

## Fail-Closed Rules

- Empty graphs fail closed.
- Unknown dependencies fail closed.
- Cycles fail closed.
- Missing required artifact paths fail closed.
- Queue entries without `first_action` fail closed.
- Any local-rch fallback promoted as successful proof health fails closed.
- Any contract, fixture, docs, or runbook claim that this lane mutates live
  beads, reservations, Agent Mail, or workers fails closed.

## Fixture Set

The seed fixtures live under `scripts/testdata/swarm_execution_queue/`:

- `healthy_input.json`
- `stale_owner_input.json`
- `proof_brownout_input.json`
- `blocked_parent_input.json`

These are input fixtures only. Later SWARM-CTRL-XII beads add the normalizer,
runner, goldens, conformance gate, operator report integration, and no-mock
drill.

## Validation

```bash
jq empty docs/swarm_execution_queue_contract_v1.json
jq empty scripts/testdata/swarm_execution_queue/healthy_input.json
jq empty scripts/testdata/swarm_execution_queue/stale_owner_input.json
jq empty scripts/testdata/swarm_execution_queue/proof_brownout_input.json
jq empty scripts/testdata/swarm_execution_queue/blocked_parent_input.json
bash -n scripts/e2e/swarm_execution_queue_contract_smoke.sh
bash scripts/e2e/swarm_execution_queue_contract_smoke.sh check
bash scripts/e2e/swarm_execution_queue_contract_smoke.sh selftest
git diff --check -- docs/SWARM_EXECUTION_QUEUE_CONTRACT.md docs/swarm_execution_queue_contract_v1.json scripts/e2e/swarm_execution_queue_contract_smoke.sh scripts/testdata/swarm_execution_queue
```
