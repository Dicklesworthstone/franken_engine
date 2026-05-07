# SWARM_AUTOPILOT_FORENSIC_DIFF_NO_MOCK_DRILL

`bd-00ofm.6` composes the shipped forensic diff control-plane artifacts into one
no-mock drill. Fixture mode runs the real shipped forensic producer scripts:
`swarm_autopilot_cohort_diff_comparator.sh`,
`swarm_autopilot_replay_recipe_composer.sh`,
`swarm_autopilot_forensic_hypothesis_scorer.sh`, and
`swarm_autopilot_operator_status_bundle.sh`.

Replay mode verifies a pinned complete forensic bundle without rerunning producers.
Live mode accepts preserved warehouse/cohort/replay artifacts and routes them
through the same producer chain. The drill does not run Cargo or RCH work directly.

Required root artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `warehouse.json`
- `reference_anomaly_cohorts.json`
- `comparison_anomaly_cohorts.json`
- `reference_replay_index.json`
- `comparison_replay_index.json`
- `cohort_diff_receipts.json`
- `fingerprint_delta_plan.json`
- `replay_recipe_bundle.json`
- `replay_recipe_index.json`
- `forensic_hypothesis_summary.json`
- `forensic_hypothesis_evidence.json`
- `operator_status_bundle.json`
- `truth_gate_report.json`

The fixture suite covers healthy forensic comparison, blocked locality
contradiction replay, contaminated replay refusal fail closed, low-evidence
degraded hypotheses, and stale-reference fail-closed behavior.

Truth gates fail closed on stale references, contradictory cohort identity,
missing replay paths, local fallback contamination, unsupported mutation claims,
or any heavy Cargo/RCH command in the drill command log.

Validation:

```bash
jq empty docs/swarm_autopilot_forensic_diff_no_mock_drill_contract_v1.json scripts/testdata/swarm_autopilot_forensic_diff_no_mock_drill/cases.json
bash -n scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh
shellcheck -x scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh
bash scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh check
bash scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill_smoke.sh selftest
```
