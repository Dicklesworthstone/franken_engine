# SWARM-CTRL-X Operator Runbook

This runbook composes the shipped SWARM-CTRL-X starvation-rescue surfaces into
one deterministic, no-mock drill over the checked-in scenario matrix. The
drill reuses:

- `scripts/swarm_starvation_rescue_input_normalizer.sh`
- `scripts/swarm_starvation_rescue_scenario_matrix.sh`
- `scripts/swarm_starvation_rescue_planner.sh`
- `scripts/swarm_starvation_rescue_conformance_gate.sh`
- `scripts/swarm_operator_status_report.sh`
- `scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh`
- `scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh`

This drill is proof-only. `scripts/swarm_operator_status_report.sh` remains the
only predictive dashboard producer in `franken_engine`.

## Output Bundle

`run` and `selftest` emit a deterministic bundle under the selected output dir:

- `swarm_starvation_rescue_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `selected-case/swarm_starvation_rescue_input.json`
- `scenario-matrix/swarm_starvation_rescue_scenario_matrix_report.json`
- `scenario-matrix/case_summaries/*.json`
- `plan/swarm_starvation_rescue_plan.json`
- `conformance/swarm_starvation_rescue_conformance_report.json`
- `operator-status/status.json`
- `operator-status/report.md`

## Operator Flow

1. Validate the runbook truth gate first:

```bash
./scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh selftest
```

2. Validate the composed drill:

```bash
./scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh check
./scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh run
./scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh selftest
```

3. Review the emitted bundle:

```bash
cat /tmp/franken-engine-swarm-starvation-rescue-no-mock-drill/*/swarm_starvation_rescue_no_mock_drill_report.json
cat /tmp/franken-engine-swarm-starvation-rescue-no-mock-drill/*/report.md
cat /tmp/franken-engine-swarm-starvation-rescue-no-mock-drill/*/operator-status/status.json
cat /tmp/franken-engine-swarm-starvation-rescue-no-mock-drill/*/operator-status/report.md
```

## Workflow Truth Claims

- The composed drill reuses the checked-in starvation-rescue scenario matrix and extracted case fixtures only; it does not mutate live bead, reservation, worker, or queue state.
- The scenario matrix remains policy-only and the selected case must round-trip through the normalizer before the planner or conformance gate is trusted.
- Contradictory ownership, stale required inputs, or admitted local fallback truth must stay fail-closed instead of reopening claims.
- The planner and conformance gate are advisory and honesty surfaces only; they never perform automatic ownership transfer or queue mutation.
- The operator status report remains the only predictive dashboard producer in franken_engine.

## What The Drill Must Prove

The combined report is truthful only when it shows:

- one full scenario-matrix replay with zero drift from expected case outcomes
- one selected case round-tripped through `selected-case/swarm_starvation_rescue_input.json`
- one planner receipt at `plan/swarm_starvation_rescue_plan.json`
- one honesty receipt at `conformance/swarm_starvation_rescue_conformance_report.json`
- one operator-status handoff rooted in `operator-status/status.json` and
  `operator-status/report.md`
- one scenario summary inventory under `scenario-matrix/case_summaries/*.json`

The drill must keep these behaviors explicit:

- contradictory ownership or stale evidence cannot be reworded into an
  automatic reopen
- local fallback remains fail-closed rescue truth, not a successful remote proof
- brownout rescue stays advisory or degraded until pressure cools
- manual-review or salvage-pinned pressure stays manual; there is no automatic
  ownership transfer

## Interpreting Outputs

Review these fields first in `swarm_starvation_rescue_no_mock_drill_report.json`:

- `summary.selected_case_id`
- `summary.selected_scenario_class`
- `summary.selected_case_decision`
- `summary.plan_decision`
- `summary.conformance_decision`
- `summary.operator_status_escalation_band`
- `summary.operator_status_top_action`
- `assertions.matrix_matches_expected`
- `assertions.selected_case_round_trips`
- `assertions.planner_tracks_selected_case`
- `assertions.conformance_passes`
- `assertions.operator_status_integrates_handoff`
- `assertions.operator_status_has_recommended_ordering`

The bundle is only trustworthy when every assertion is `true` and the child
artifact paths point at:

- `swarm_starvation_rescue_no_mock_drill_report.json`
- `selected-case/swarm_starvation_rescue_input.json`
- `scenario-matrix/swarm_starvation_rescue_scenario_matrix_report.json`
- `scenario-matrix/case_summaries/*.json`
- `plan/swarm_starvation_rescue_plan.json`
- `conformance/swarm_starvation_rescue_conformance_report.json`
- `operator-status/status.json`
- `operator-status/report.md`

## Truth Gate

Run the truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples
- missing references to `swarm_starvation_rescue_no_mock_drill_report.json`
- missing references to `selected-case/swarm_starvation_rescue_input.json`
- missing references to `scenario-matrix/swarm_starvation_rescue_scenario_matrix_report.json`
- missing references to `scenario-matrix/case_summaries/*.json`
- missing references to `plan/swarm_starvation_rescue_plan.json`
- missing references to `conformance/swarm_starvation_rescue_conformance_report.json`
- missing references to `operator-status/status.json`
- missing references to `operator-status/report.md`
- claims that the drill mutates live worker state, reopens beads automatically, or performs automatic ownership transfer
- claims that the drill is a second predictive dashboard producer
- stale claims that contradictory ownership can be ignored or that local
  fallback rejection is optional
