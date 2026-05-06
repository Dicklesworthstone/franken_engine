# SWARM_EXECUTION_QUEUE_FIDELITY_SCORER

`scripts/swarm_execution_queue_fidelity_scorer.sh` scores SWARM-CTRL-XIII
hindsight output against the original SWARM-CTRL-XII queue advice. It is
advisory-only. It emits a deterministic fidelity receipt and drift ledger, but
it does not update beads, reopen work, rewrite historical outcomes, send Agent
Mail, run Cargo, mutate workers, or change the active queue.

Machine-readable contract:
`docs/swarm_execution_queue_fidelity_scorer_contract_v1.json`.

## Inputs

Required artifacts:

- `--hindsight-report-json FILE`
- `--hindsight-input-json FILE`
- `--evidence-ledger-json FILE`
- `--counterfactual-candidates-json FILE`

The scorer expects artifacts produced by
`scripts/swarm_execution_queue_hindsight_normalizer.sh`. Upstream hindsight
fail-closed reports remain fail-closed here; the scorer must not convert
contradictory owner, reservation, timestamp, or proof evidence into a usable
score.

## Artifacts

Each run emits:

- `fidelity_score_receipt.json`
- `drift_ledger.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The receipt contains aggregate fidelity, confidence band, component scores for
start order, defer correctness, proof-health prediction, owner-friction
prediction, and conservative-mode appropriateness. The drift ledger preserves
per-task mismatch class, row score, confidence band, source row, and remediation
text.

## Mismatch Classes

- `exact_match`
- `conservative_but_correct`
- `over_conservative`
- `stale_owner_miss`
- `proof_brownout_miss`
- `missing_outcome`
- `ranking_drift`
- `timing_drift`
- `contradictory_evidence`
- `unclassified_drift`

`contradictory_evidence` fails closed. Other mismatch classes degrade the score
and provide remediation for replay or policy tuning.

## Validation

```bash
bash -n scripts/swarm_execution_queue_fidelity_scorer.sh
bash -n scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh
shellcheck -x scripts/swarm_execution_queue_fidelity_scorer.sh scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh
jq empty docs/swarm_execution_queue_fidelity_scorer_contract_v1.json scripts/testdata/swarm_execution_queue/fidelity_scorer_fixtures.json
bash scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_fidelity_scorer.sh scripts/e2e/swarm_execution_queue_fidelity_scorer_smoke.sh docs/SWARM_EXECUTION_QUEUE_FIDELITY_SCORER.md docs/swarm_execution_queue_fidelity_scorer_contract_v1.json scripts/testdata/swarm_execution_queue/fidelity_scorer_fixtures.json
```
