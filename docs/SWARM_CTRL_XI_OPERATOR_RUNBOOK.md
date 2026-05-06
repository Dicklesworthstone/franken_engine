# SWARM-CTRL-XI Operator Runbook

This runbook composes the shipped SWARM-CTRL-XI checkpoint capture and restore
surfaces into one deterministic, no-mock drill over the checked-in healthy
fixture bundle at `scripts/testdata/swarm_checkpoint_lifecycle_drill/healthy`.
The drill reuses:

- `scripts/swarm_checkpoint_bundle_packer.sh`
- `scripts/swarm_checkpoint_restore_planner.sh`
- `scripts/swarm_checkpoint_restore_conformance_gate.sh`
- `scripts/swarm_operator_status_report.sh`
- `scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh`
- `scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh`

This drill is proof-only. `scripts/swarm_operator_status_report.sh` remains the only predictive dashboard producer in `franken_engine`.

## Output Bundle

`run` and `selftest` emit a deterministic bundle under the selected output dir:

- `swarm_checkpoint_lifecycle_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `capture/checkpoint_bundle.json`
- `capture/run_manifest.json`
- `capture/summary.md`
- `simulated-disconnect-restart/checkpoint_bundle.json`
- `simulated-disconnect-restart/run_manifest.json`
- `restore-plan/swarm_checkpoint_restore_plan.json`
- `conformance/swarm_checkpoint_restore_conformance_report.json`
- `operator-status/status.json`
- `operator-status/report.md`

## Operator Flow

1. Validate the runbook truth gate first:

```bash
./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh selftest
```

2. Validate the composed drill:

```bash
./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh check
./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh run
./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh selftest
```

3. Review the emitted bundle:

```bash
cat /tmp/franken-engine-swarm-checkpoint-lifecycle-no-mock-drill/*/swarm_checkpoint_lifecycle_no_mock_drill_report.json
cat /tmp/franken-engine-swarm-checkpoint-lifecycle-no-mock-drill/*/report.md
cat /tmp/franken-engine-swarm-checkpoint-lifecycle-no-mock-drill/*/operator-status/status.json
cat /tmp/franken-engine-swarm-checkpoint-lifecycle-no-mock-drill/*/operator-status/report.md
```

Heavy proof examples stay in this form:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_ctrl_xi cargo test -p frankenengine-engine --test module_compatibility_matrix_integration -- --nocapture
```

## Workflow Truth Claims

- The composed drill reuses the checked-in checkpoint lifecycle fixtures and the real control-plane scripts only; it does not mutate live bead, reservation, worker, or queue state.
- The simulated disconnect/restart step only replays the saved checkpoint bundle copy under `simulated-disconnect-restart/checkpoint_bundle.json`; there is no automatic reopen or silent ownership transfer.
- Stale checkpoint age, local fallback truth, contradictory ownership/contact-first evidence, or salvage manual review must keep restore fail-closed or advisory; they never auto-promote resume.
- Because the no-mock drill omits unrelated resource-lease, proof-cache, QoS batch, and staged-contamination artifacts, `operator-status/status.json` may stay degraded; checkpoint restore truth lives in `summary.checkpoint_restore_*` and `predictive_dashboard.checkpoint_restore.*`.
- The operator status report remains the only predictive dashboard producer in franken_engine.

## What The Drill Must Prove

The combined report is truthful only when it shows:

- one checkpoint bundle capture rooted in `capture/checkpoint_bundle.json`
- one simulated disconnect/restart replay rooted in `simulated-disconnect-restart/checkpoint_bundle.json`
- one restore planner receipt at `restore-plan/swarm_checkpoint_restore_plan.json`
- one conformance receipt at `conformance/swarm_checkpoint_restore_conformance_report.json`
- one operator-status checkpoint handoff rooted in `operator-status/status.json`
- one operator-status markdown handoff rooted in `operator-status/report.md`

The drill must keep these behaviors explicit:

- stale checkpoint age cannot be reworded into an automatic reopen
- local fallback remains fail-closed restore truth, not a successful remote replay
- contradictory ownership or contact-first evidence stays manual review
- salvage pressure stays advisory; there is no silent ownership transfer

## Interpreting Outputs

Review these fields first in `swarm_checkpoint_lifecycle_no_mock_drill_report.json`:

- `summary.checkpoint_id`
- `summary.capture_decision`
- `summary.restore_plan_decision`
- `summary.restore_top_action`
- `summary.conformance_decision`
- `summary.operator_checkpoint_restore_plan_decision`
- `summary.operator_checkpoint_restore_escalation_band`
- `summary.operator_checkpoint_restore_top_action`
- `assertions.bundle_copy_reused_for_restore`
- `assertions.checkpoint_ids_match`
- `assertions.conformance_tracks_plan`
- `assertions.operator_status_integrates_checkpoint_restore`

The bundle is only trustworthy when every assertion is `true` and the child
artifact paths point at:

- `swarm_checkpoint_lifecycle_no_mock_drill_report.json`
- `capture/checkpoint_bundle.json`
- `capture/run_manifest.json`
- `simulated-disconnect-restart/checkpoint_bundle.json`
- `restore-plan/swarm_checkpoint_restore_plan.json`
- `conformance/swarm_checkpoint_restore_conformance_report.json`
- `operator-status/status.json`
- `operator-status/report.md`

If `operator-status/status.json` remains degraded, treat
`summary.checkpoint_restore_plan_decision`,
`summary.checkpoint_restore_escalation_band`,
`summary.checkpoint_restore_top_action`, and
`predictive_dashboard.checkpoint_restore.*` as the checkpoint-specific handoff
truth. The no-mock drill intentionally leaves unrelated resource-lease,
proof-cache, QoS batch, and staged-contamination inputs absent so the overall
dashboard can remain advisory while the checkpoint handoff itself still proves
truthful integration.

## Truth Gate

Run the truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples
- missing references to `swarm_checkpoint_lifecycle_no_mock_drill_report.json`
- missing references to `capture/checkpoint_bundle.json`
- missing references to `capture/run_manifest.json`
- missing references to `simulated-disconnect-restart/checkpoint_bundle.json`
- missing references to `restore-plan/swarm_checkpoint_restore_plan.json`
- missing references to `conformance/swarm_checkpoint_restore_conformance_report.json`
- missing references to `operator-status/status.json`
- missing references to `operator-status/report.md`
- claims that the drill performs automatic reopen, silent ownership transfer, or live worker mutation
- claims that the drill is a second predictive dashboard producer
- stale claims that fail-closed checkpoint age, local fallback truth, contradictory ownership, or salvage manual review can be ignored
