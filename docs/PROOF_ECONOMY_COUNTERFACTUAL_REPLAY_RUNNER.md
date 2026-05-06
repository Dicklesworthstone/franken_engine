# Proof Economy Counterfactual Replay Runner

`scripts/proof_economy_counterfactual_replay_runner.sh` applies multiple
fixture-only proof-economy policies to the same normalized
`franken-engine.proof-economy-replay-trace.v1` trace and emits
`franken-engine.proof-economy-counterfactual-replay-report.v1`.

The runner composes the shipped policy evaluator. It does not query live `rch`,
mutate workers, or execute proof commands.

## Usage

```bash
./scripts/proof_economy_counterfactual_replay_runner.sh \
  --replay-trace-json /tmp/proof-economy/replay_trace.normalized.json \
  --output-dir /tmp/proof-economy-counterfactual
```

The default policy matrix includes:

- `baseline`: reproduces fixture command order.
- `fair_share`: caps per-agent heavy proof fanout while preserving P1 SLOs.
- `high_pressure`: defers broad P3 heavy proof work under pressure.

## Artifacts

Each run emits:

- `counterfactual_replay_report.json`
- `policy_scorecards.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report includes per-policy scheduled order, deferred order, slot-share
deltas from baseline, changed command explanations, deferred command reasons,
and unchanged command explanations.

## Validation

```bash
bash -n scripts/proof_economy_counterfactual_replay_runner.sh
bash -n scripts/e2e/proof_economy_counterfactual_replay_runner_smoke.sh
bash scripts/e2e/proof_economy_counterfactual_replay_runner_smoke.sh check
bash scripts/e2e/proof_economy_counterfactual_replay_runner_smoke.sh selftest
```
