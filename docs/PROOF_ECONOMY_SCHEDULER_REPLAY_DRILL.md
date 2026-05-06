# Proof Economy Scheduler Replay Drill

`scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh` composes the
SWARM-CTRL-VII proof-economy replay lab over one fixture without live worker
calls. It emits
`franken-engine.proof-economy-scheduler-replay-drill-report.v1`.

The drill runs:

- `proof_economy_replay_trace_normalizer.sh`
- `proof_economy_policy_evaluator.sh`
- `proof_economy_counterfactual_replay_runner.sh`
- `proof_queue_brownout_starvation_detector.sh`
- `proof_economy_operator_what_if_report.sh`
- `proof_economy_scheduler_replay_truth_gate.sh`

The fixture includes at least 20 agents, mixed P1/P2/P3 beads, Agent Mail style
reservations, proof-cache receipts, and rch-wrapped resource signals.

## Artifacts

The drill emits:

- `scheduler_replay_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The truth gate rejects bare heavy Cargo examples, missing artifact references,
and missing brownout or fair-share dashboard fields.

## Validation

```bash
bash -n scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh
bash -n scripts/e2e/proof_economy_scheduler_replay_truth_gate.sh
bash scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh check
bash scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh selftest
```
