# SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_SCORER

`scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh` evaluates a
recorded execution queue policy adoption after its observation window. It
compares the adopted policy receipt and snapshot bundle against post-adoption
fidelity evidence, emits a sustained-gain receipt, and writes a deterministic
post-adoption drift ledger for expiry, supersession, and operator-status follow
up beads.

Machine-readable contract:
`docs/swarm_execution_queue_policy_sustained_gain_scorer_contract_v1.json`.

## Inputs

Required inputs:

- `--adoption-receipt-json FILE`
- `--adoption-snapshot-bundle-json FILE`
- `--post-adoption-fidelity-score-receipt-json FILE`
- `--post-adoption-drift-ledger-json FILE`
- `--evidence-ownership-json FILE`

The adoption receipt supplies the expected observation window, minimum sample
count, monitored metrics, adopted candidate, and supersession context. The
snapshot supplies the pre-adoption current-policy baseline and candidate
promise. The post-adoption fidelity receipt and drift ledger supply observed
benefit or regression evidence. The ownership artifact proves that all evidence
is owned, fresh, and unambiguous.

## Artifacts

Each run emits:

- `sustained_gain_receipt.json`
- `post_adoption_drift_ledger.json`
- `evidence_hashes.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The scorer is deterministic for fixed inputs, source revision, and generated
timestamp. It preserves all source paths and sha256 hashes in the emitted
evidence ledger.

## Verdicts

The scorer emits one of:

- `sustained_gain`: observed fidelity is above the sustained floor and required
  evidence is complete.
- `regression_detected`: observed fidelity falls below the pre-adoption current
  policy baseline or rollback-triggering drift is present.
- `inconclusive_drift`: evidence is complete but observed fidelity does not yet
  sustain enough of the promised gain.
- `fail_closed`: required observation evidence is incomplete, stale,
  contradictory, or ambiguously owned.

The sustained floor is derived from the adoption snapshot baseline plus half of
the promised candidate delta. Later beads can tune the policy, but this scorer
keeps the threshold deterministic and auditable.

## Boundaries

This is a scoring artifact only. It never changes active queue settings and
never applies live retuning. It never mutates `br`, never sends Agent Mail,
never mutates remote workers, and never rewrites historical outcomes. It does
not mutate the adopted policy receipt. It only records whether evidence supports
sustained gain, regression, or inconclusive drift.

The scorer must fail closed on incomplete observation windows, insufficient
sample counts, ambiguous evidence ownership, stale or rejected ownership rows,
missing monitored metrics, automatic retuning claims, sustained-gain claims in
inputs, and fail closed on local fallback proof claims.

## Validation

```bash
bash -n scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh
bash -n scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh
shellcheck -x scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh
jq empty docs/swarm_execution_queue_policy_sustained_gain_scorer_contract_v1.json
bash scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh scripts/e2e/swarm_execution_queue_policy_sustained_gain_scorer_smoke.sh docs/SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_SCORER.md docs/swarm_execution_queue_policy_sustained_gain_scorer_contract_v1.json
```
