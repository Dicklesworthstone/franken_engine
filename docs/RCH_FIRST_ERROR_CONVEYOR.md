# RCH First Error Conveyor

`scripts/rch_first_error_conveyor.sh` composes preserved
`rch_compile_blocker_cluster` output with a compile-proof isolation profile and
emits an ordered advisory-only plan for the next first-error action.

The conveyor exists to reduce manual handoff cost during noisy current-head
compile drift. It does not create beads, update beads, send Agent Mail, run
Cargo, invoke `rch`, mutate files, or touch workers.

## Inputs

Required:

- `--clusters-json`: `franken-engine.rch-compile-blocker-clusters.v1`
- `--profile-json`: `franken-engine.rch-compile-proof-isolation-profile.v1`

Optional:

- `--source-revision`
- `--case-id`
- `--output-dir`

## Outputs

- `first_error_conveyor_plan.json`
- `proposed_commands.txt`
- `run_manifest.json`
- `events.jsonl`
- `report.md`

`proposed_commands.txt` is review text only. Operators or agents must still
decide whether to run any suggested `br create` command manually.

## Dispositions

- `block_current_bead`: target-relevant first error should block the current
  bead until fixed.
- `new_bead_candidate`: unrelated current-head error may deserve a follow-up
  bead after review.
- `duplicate_existing_bead`: reserved for the ownership-aware follow-up lane.
- `defer_active_owner`: reserved for the ownership-aware follow-up lane.
- `insufficient_evidence`: contaminated, truncated, or fail-closed inputs cannot
  safely produce source-fix work.

## Smoke Proof

```bash
./scripts/e2e/rch_first_error_conveyor_smoke.sh check
./scripts/e2e/rch_first_error_conveyor_smoke.sh selftest
```
