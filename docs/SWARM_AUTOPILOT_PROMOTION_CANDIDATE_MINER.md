# SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER

`scripts/swarm_autopilot_promotion_candidate_miner.sh` mines promotion-review
candidates from evidence warehouse rows and hindsight chaos outcomes.

Machine-readable contract:
`docs/swarm_autopilot_promotion_candidate_miner_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh`.

The promotion candidate miner is advisory only and proof only.

## Inputs

Required:

- `--evidence-warehouse-json FILE`
- `--hindsight-chaos-scenarios-json FILE`

Optional:

- `--minimum-evidence-count N`
- `--source-revision REV`
- `--output-dir DIR`

## Outputs

Each run emits:

- `swarm_autopilot_promotion_candidates.json`
- `swarm_autopilot_promotion_candidate_receipts.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each candidate preserves confidence band, required evidence count, observed evidence count, contradictory outcome reasons, and exact source artifact paths.

## Promotion Rules

Promotion candidates require repeated healthy warehouse evidence and replayable hindsight scenarios.

Stable non-promotion recommendations remain explicit non-promotion receipts.

Insufficient evidence degrades instead of suggesting promotion.

Contradictory hindsight blocks promotion truth.

Contaminated evidence cannot support promotion candidates.

The miner never promotes automatically.

## Fail-Closed Rules

- Stale hindsight inputs fail closed.
- Contradictory hindsight blocks fail closed.
- Contamination refusal fails closed.
- Schema drift in warehouse or hindsight material fails closed.

The miner never mutates beads, releases reservations, sends Agent Mail, runs
Cargo, runs RCH, mutates workers, changes live queue policy, or promotes
candidates automatically. It only emits candidate and receipt artifacts under
its output directory.

## Proof Cases

The checked-in fixtures cover:

- `promotable_repeated_success`
- `insufficient_evidence_degradation`
- `contradictory_hindsight_block`
- `contamination_refusal`
- `stable_non_promotion_recommendation`

## Validation

```bash
bash -n scripts/swarm_autopilot_promotion_candidate_miner.sh
bash -n scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh
shellcheck -x scripts/swarm_autopilot_promotion_candidate_miner.sh scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh
jq empty docs/swarm_autopilot_promotion_candidate_miner_contract_v1.json scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json
bash scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh check
bash scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER.md docs/swarm_autopilot_promotion_candidate_miner_contract_v1.json scripts/swarm_autopilot_promotion_candidate_miner.sh scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json
```
