# RGC Seqlock Candidate Inventory v1

Bead: `bd-1lsy.7.21.2`

This contract extends the 621A inventory into concrete reader/writer contracts, bounded retry budgets, and deterministic incumbent fallback rules for read-mostly runtime and policy surfaces.

## Classification Rules

- `accept`: read path is side-effect free, retry-safe, and the current baseline is a snapshot/query path that would benefit from optimistic readers.
- `conditional`: the surface is promising, but a versioned publication boundary or external join fence is missing.
- `reject`: the read path mutates state, writes are too hot, or the surface is already an immutable/offline artifact where seqlocks add no value.

## Required Artifacts

- `seqlock_candidate_inventory.json`
- `retry_safety_matrix.json`
- `seqlock_reader_writer_contract.json`
- `retry_budget_policy.json`
- `incumbent_fallback_matrix.json`
- `snapshot_baseline_comparator.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `env.json`
- `manifest.json`
- `repro.lock`
- `summary.md`

## Verification

```bash
./scripts/run_seqlock_candidate_inventory_suite.sh ci
./scripts/e2e/seqlock_candidate_inventory_replay.sh ci
```

The suite is `rch`-backed and emits the required 621B bundle under `artifacts/seqlock_candidate_inventory/<timestamp>/`.
