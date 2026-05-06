# SWARM_EXECUTION_QUEUE_OPERATOR_RUNBOOK

This runbook describes the SWARM-CTRL-XII execution queue lane. The lane is
advisory-only: it produces replayable evidence for an operator, but it does not
change bead state, reassign owners, release reservations, send messages, run
remote workers, or warm targets.

## Capture

Capture queue inputs as explicit snapshots:

```bash
br ready --json > br_ready.json
br list --json > br_list.json
bv --recipe actionable --robot-plan > bv_plan.json
```

Add optional snapshots when available: Agent Mail activity, file reservations,
stale-lock recommendations, and proof-transport health. Missing optional
evidence must be treated as degraded, not healthy.

## Normalize

Run the fixture-fed normalizer:

```bash
./scripts/swarm_execution_queue_input_normalizer.sh \
  --br-ready-json br_ready.json \
  --br-list-json br_list.json \
  --bv-actionable-plan-json bv_plan.json \
  --agent-mail-activity-json agent_mail.json \
  --file-reservations-json reservations.json \
  --stale-lock-recommendations-json stale.json \
  --proof-transport-health-json proof.json \
  --output-dir artifacts/swarm_execution_queue/input
```

The primary artifact is `normalized_input.json`. If the normalizer reports
`fail_closed`, quote its `fail_closed_reasons` and stop the queue lane until the
unsafe graph or proof evidence is repaired.

## Run Queue

Replay normalized input through the Rust queue runner:

```bash
franken_swarm_execution_queue \
  --normalized-input-json artifacts/swarm_execution_queue/input/normalized_input.json \
  --output-dir artifacts/swarm_execution_queue/run \
  --queue-depth 8 \
  --epoch 7 \
  --timestamp-ns 777
```

Required runner artifacts:

- `run_manifest.json`
- `execution_queue_artifact.json`
- `risk_budget_receipt.json`
- `bottleneck_report.json`
- `operator_summary.md`

Use the conformance gate to verify checked-in queue behavior:

```bash
bash scripts/e2e/swarm_execution_queue_conformance_gate.sh check
```

## Interpret

Treat `risk_budget_receipt.json` as the source of conservative-mode truth. When
`conservative_mode` is `true`, prefer narrow script or docs gates and defer
broad validation.

Use `execution_queue_artifact.json` for top starts and deferred rows. Every row
must carry a `first_action`; if it does not, the lane is not actionable.

Use `bottleneck_report.json` to decide who or what to inspect first. A stale
owner or reservation conflict is a coordination prompt, not permission to change
ownership.

If checkpoint restore evidence is blocked or manual-review, the
`execution_queue_advisory.restore_dependency_state` field in
`status.json` must remain visible and queue advice must stay secondary to
restore remediation.

## Publish Status

Compose runner artifacts into the operator report:

```bash
./scripts/swarm_operator_status_report.sh \
  --execution-queue-artifact-json artifacts/swarm_execution_queue/run/execution_queue_artifact.json \
  --execution-queue-risk-budget-json artifacts/swarm_execution_queue/run/risk_budget_receipt.json \
  --execution-queue-bottleneck-report-json artifacts/swarm_execution_queue/run/bottleneck_report.json \
  --execution-queue-run-manifest-json artifacts/swarm_execution_queue/run/run_manifest.json \
  --output-dir artifacts/swarm_execution_queue/status
```

Quote `status.json`, `report.md`, `normalized_input.json`,
`execution_queue_artifact.json`, `risk_budget_receipt.json`,
`bottleneck_report.json`, and `run_manifest.json` in parent closeouts.

## Local Fallback

Any local rch fallback marker is unsafe proof evidence for this lane. Re-run the
proof remotely or narrow to script-only validation before publishing a healthy
queue state.
