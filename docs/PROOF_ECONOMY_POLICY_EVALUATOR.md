# Proof Economy Policy Evaluator

`scripts/proof_economy_policy_evaluator.sh` evaluates fair-share scheduler
policy decisions over a normalized
`franken-engine.proof-economy-replay-trace.v1` fixture.

The evaluator is a replay-lab surface. It does not query live `rch`, mutate
workers, or run proof commands. Heavy command examples are accepted only when
they are already `rch exec -- env CARGO_TARGET_DIR=` wrapped in the replay
trace.

## Usage

```bash
./scripts/proof_economy_policy_evaluator.sh \
  --replay-trace-json /tmp/proof-economy/replay_trace.normalized.json \
  --pressure-mode high \
  --max-heavy-per-agent 1 \
  --output-dir /tmp/proof-economy-policy
```

## Decision Rules

The evaluator emits `franken-engine.proof-economy-policy-scorecard.v1` with:

- `policy_decision`
- `p1_slo_risk`
- `fair_share_score_millionths`
- `decisions[]`
- `per_agent[]`
- `findings[]`
- `artifact_paths`

Policy behavior:

- P1 commands are protected as `admit_preempt`.
- Heavy commands that are not `rch exec -- env CARGO_TARGET_DIR=` wrapped are
  fail-closed.
- Per-agent heavy proof fanout above `--max-heavy-per-agent` is deferred with
  `agent fairness throttle`.
- `--pressure-mode high` defers P3 heavy proof work with
  `pressure-aware deferral`.
- Warm target reuse is credited only when the trace contains matching
  reservation ownership evidence for the command's agent or bead.

## Artifacts

Each run emits:

- `policy_scorecard.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
bash -n scripts/proof_economy_policy_evaluator.sh
bash -n scripts/e2e/proof_economy_policy_evaluator_smoke.sh
bash scripts/e2e/proof_economy_policy_evaluator_smoke.sh check
bash scripts/e2e/proof_economy_policy_evaluator_smoke.sh selftest
```
