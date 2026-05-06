# Remote Proof Compaction Planner

`scripts/remote_proof_compaction_planner.sh` is the SWARM-CTRL-VI planning-only
dedup layer for remote-proof archives. It consumes the retention ledger’s
residency manifest plus the content-addressed mirror manifest and emits one
deterministic compaction plan.

## Inputs

Required:

- `--residency-manifest-json`
- `--mirror-manifest-json`

Optional:

- `--output-dir`

The planner does not run `cargo`, contact workers, or mutate archive state.

## Output

Each run emits:

- `remote_proof_compaction_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The plan contains:

- `compacted_groups`: duplicate replay-critical groups that can be safely merged
- `blocked_groups`: duplicate groups detected but refused for safety reasons
- `unchanged_replay_artifacts`: replay-critical artifacts that remain untouched
- `compaction_stats`: candidate, compacted, blocked, and reclaimed counts

## Safety Rules

Compaction is allowed only when all duplicate paths in one content-address group:

- are replay-critical
- share the same retention class
- share the same derived provenance key

The planner blocks compaction instead of mutating evidence when duplicate groups
show:

- `retention_class_mismatch`
- `provenance_mismatch`
- `replay_role_mismatch`

It fails closed with exit `42` when upstream evidence is incomplete or
inconsistent, such as missing mirror content addresses for hot replay-critical
artifacts.

## Proof Expectations

`scripts/e2e/remote_proof_compaction_planner_smoke.sh` must prove:

- duplicate replay artifacts compact into one retained address
- retention-class mismatch blocks compaction
- provenance mismatch blocks compaction
- repeated identical inputs preserve the same plan hash
