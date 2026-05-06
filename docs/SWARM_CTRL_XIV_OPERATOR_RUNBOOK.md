# SWARM-CTRL-XIV Operator Runbook

SWARM-CTRL-XIV composes the final execution-queue tuning lifecycle into
advisory-only evidence. It packages queue tuning evidence, evaluates promotion
guard eligibility, compares rollback and canary evidence, and publishes one
operator-status handoff. It does not change the active queue, does not apply
retuning automatically, and does not claim beads, send Agent Mail, release
reservations, or mutate remote workers.

manual approval remains required before any active policy change. The lifecycle
can say that a candidate is eligible for canary review or that rollback is
recommended, but it does not perform live queue mutation.

scripts/swarm_operator_status_report.sh remains the only predictive dashboard producer in franken_engine. The lifecycle drill feeds that script; it is not a second predictive dashboard producer.

## Inputs

Start from real checked-in scripts and explicit evidence artifacts:

- `scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh`
- `scripts/swarm_execution_queue_tuning_promotion_guard.sh`
- `scripts/swarm_execution_queue_tuning_rollback_comparator.sh`
- `scripts/swarm_operator_status_report.sh`
- queue fidelity score receipt
- queue drift ledger
- counterfactual backtest report
- tuning plan
- policy frontier
- current policy state

If evidence is missing, stale, contradictory, or locally fabricated, stop and
quote the fail-closed reason. In this lane, reject local fallback proof evidence
instead of promoting it into tuning confidence.

## Bundle Policy Evidence

Run the bundle packer through the no-mock drill or directly with explicit input
paths. Preserve:

- `tuning-policy-bundle/tuning_policy_bundle.json`
- `tuning-policy-bundle/policy_frontier_export.json`
- `tuning-policy-bundle/evidence_hashes.json`

The bundle is review evidence only. It links the fidelity receipt, drift ledger,
counterfactual backtest report, tuning plan, frontier, operator-status seed,
prior policy bundle id, prior frontier path, rollback comparator path, and
canary verdict ledger path.

## Guard Promotion

Run the promotion guard against a candidate bundle and a current policy state.
Preserve:

- `promotion-guard/promotion_guard_receipt.json`
- `promotion-guard/manual_approval_rollout_plan.json`

Treat `eligible_canary` as permission to prepare a manual approval packet, not
permission to retune the active queue. Treat stale evidence as fail-closed and
stop before the rollback comparator or operator-status handoff.

## Compare Rollback And Canary Evidence

Run the rollback comparator only after the guard accepts fresh, consistent
evidence. Preserve:

- `rollback-comparator/rollback_comparator_receipt.json`
- `rollback-comparator/canary_verdict_ledger.json`

When the comparator reports `worse_than_current` or the canary ledger reports
`rollback_required`, surface that state to operator status and leave the actual
rollback to a separate manual approval path.

## Publish Status

Publish one operator-status handoff and preserve:

- `operator-status/status.json`
- `operator-status/report.md`

The `predictive_dashboard.queue_tuning_promotion` section must include the
bundle id, readiness, recommendation, promotion guard receipt, manual approval
rollout plan, rollback comparator receipt, canary verdict ledger, mutation
policy, and source paths. It composes with queue fidelity, checkpoint restore,
proof economy, and execution queue sections instead of overriding them.

## No-Mock Drill

Run the composed lifecycle drill:

```bash
./scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh check
./scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh run
./scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh selftest
```

The drill covers `eligible_canary`, `stale_evidence_reject`, and
`rollback_required`. Preserve the run directory printed by the script. It
contains:

- `swarm_execution_queue_tuning_lifecycle_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `eligible_canary/tuning-policy-bundle/tuning_policy_bundle.json`
- `eligible_canary/tuning-policy-bundle/policy_frontier_export.json`
- `eligible_canary/promotion-guard/promotion_guard_receipt.json`
- `eligible_canary/promotion-guard/manual_approval_rollout_plan.json`
- `eligible_canary/rollback-comparator/rollback_comparator_receipt.json`
- `eligible_canary/rollback-comparator/canary_verdict_ledger.json`
- `eligible_canary/operator-status/status.json`
- `eligible_canary/operator-status/report.md`
- `stale_evidence_reject/promotion-guard/promotion_guard_receipt.json`
- `stale_evidence_reject/promotion-guard/manual_approval_rollout_plan.json`
- `rollback_required/rollback-comparator/rollback_comparator_receipt.json`
- `rollback_required/rollback-comparator/canary_verdict_ledger.json`
- `rollback_required/operator-status/status.json`
- `rollback_required/operator-status/report.md`

The report must show:

- `assertions.includes_eligible_canary == true`
- `assertions.includes_stale_evidence_reject == true`
- `assertions.includes_rollback_required == true`
- `assertions.stale_evidence_stops_before_comparator == true`
- `assertions.rollback_required_surfaces_to_operator_status == true`
- `mutation_policy.changes_active_queue == false`
- `mutation_policy.applies_live_retuning == false`

## Truth Gate

Run the runbook truth gate:

```bash
./scripts/e2e/swarm_ctrl_xiv_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_xiv_runbook_truth_gate.sh selftest
```

The gate checks `docs/swarm_ctrl_xiv_runbook_truth_contract_v1.json`, required
artifact references, required commands, required workflow claims, script syntax,
shellcheck, and rch policy compliance. It rejects bare heavy Cargo examples,
missing lifecycle artifacts, claims that manual approval may be skipped, claims
that the drill is a second dashboard producer, and claims that fallback proof
may be used for promotion confidence.

If a Rust proof surface changes, wrap the proof with rch and an explicit target
directory:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_ctrl_xiv cargo test -p frankenengine-engine --test module_compatibility_matrix_integration -- --nocapture
```

Script-only changes can use the truth gate, drill selftest, `bash -n`,
`shellcheck -x`, `jq empty`, and `scripts/rch_policy_compliance_gate.sh` without
running a full workspace build.
