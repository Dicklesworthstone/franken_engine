# Swarm Validation Admission Recommender

`bd-7r53m.3`

`scripts/swarm_validation_admission_recommender.sh` chooses the next validation
action from already-captured snapshots. It does not run `cargo`, `rch`, `br`,
`pgrep`, `ps`, or `git`.

The recommender fails closed if process inspection, bead ownership, dirty-file
state, or the warm-target command matrix is unavailable. Its output is
`recommendation.json`, `events.jsonl`, `commands.txt`, and `report.md`.

## Recommendations

- `run_source_only_now`: run lightweight `rustfmt --check`, `jq empty`,
  `bash -n`, or `git diff --check` evidence now.
- `run_focused_rch_now`: launch a focused `focused_lib_test` or
  `focused_integration_test` RCH proof with the matrix target dir.
- `wait_existing_all_targets`: an all-targets RCH proof is already active, so
  agents should reuse or wait for that evidence.
- `validation_blocked`: required snapshots conflict or are missing.

## Snapshot Inputs

Use deterministic snapshots:

```bash
pgrep -af 'cargo|rustc|rch exec' > /tmp/swarm-validation-ps.txt
br list --status=in_progress --json > /tmp/swarm-validation-br.json
git status --porcelain=v1 | jq -R '{path: (.[3:]), overlap: false}' | jq -s '{files: .}' > /tmp/swarm-validation-dirty.json
```

Then classify the lane:

```bash
./scripts/swarm_validation_admission_recommender.sh \
  --bead-id bd-7eefz \
  --agent-id RainyBadger \
  --command-class focused_lib_test \
  --ps-snapshot /tmp/swarm-validation-ps.txt \
  --br-snapshot-json /tmp/swarm-validation-br.json \
  --dirty-files-json /tmp/swarm-validation-dirty.json \
  --output-dir /tmp/franken-engine-swarm-validation-admission/bd-7eefz
```

## Validation

```bash
jq empty scripts/testdata/swarm_validation_admission_recommender/cases.json
bash -n scripts/swarm_validation_admission_recommender.sh
bash -n scripts/e2e/swarm_validation_admission_recommender_smoke.sh
bash scripts/e2e/swarm_validation_admission_recommender_smoke.sh check
bash scripts/e2e/swarm_validation_admission_recommender_smoke.sh selftest
git diff --check -- scripts/swarm_validation_admission_recommender.sh docs/SWARM_VALIDATION_ADMISSION_RECOMMENDER.md scripts/testdata/swarm_validation_admission_recommender/cases.json scripts/e2e/swarm_validation_admission_recommender_smoke.sh
```
