# RGC Seqlock Reader/Writer Contract v1

Bead: `bd-1lsy.7.21.2`

This contract admits seqlock-backed reads only for inventory-approved
read-mostly surfaces with explicit retry budgets, writer-pressure limits, and
deterministic fallback to the incumbent baseline.

## Guard Scope

- only accepted candidates from the seqlock candidate inventory can use the
  reader/writer contract
- read paths must remain side-effect free, retry-safe, and publish behind a
  single generation or epoch boundary
- operators must be able to inspect `total_reads`, `fast_path_reads`,
  `fallback_reads`, `total_retries`, `writer_pressure_observations`, and
  `writes`
- budget exhaustion, writer-pressure violations, or publication-boundary drift
  keep the contract fail-closed on the incumbent baseline

## Accepted Candidates

- `governance-ledger-head-view`
  - retry budget: `4`
  - writer-pressure budget: `1`
  - incumbent baseline: append-only `Vec` query plus latest checkpoint read
- `guardplane-calibration-snapshot`
  - retry budget: `3`
  - writer-pressure budget: `1`
  - incumbent baseline: deterministic clone of calibration maps
- `module-cache-snapshot`
  - retry budget: `2`
  - writer-pressure budget: `2`
  - incumbent baseline: full snapshot clone from owner-thread cache state

## Exact Fallback Conditions

- `governance-ledger-head-view`
  - fallback if entry append and checkpoint publication become independently
    visible to readers
  - fallback if query semantics grow cursor side effects or mutable pagination
    state
- `guardplane-calibration-snapshot`
  - fallback if threshold and map updates stop publishing behind one
    calibration epoch
  - fallback if readers require signed promotion metadata not covered by the
    optimistic read boundary
- `module-cache-snapshot`
  - fallback if `entries`, `latest_versions`, and `revoked_modules` stop
    publishing behind one generation boundary
  - fallback if `merge_snapshot` or revocation repair introduces read-path side
    effects

## Required Artifacts

- `commands.txt`
- `env.json`
- `events.jsonl`
- `incumbent_fallback_matrix.json`
- `manifest.json`
- `repro.lock`
- `retry_budget_policy.json`
- `run_manifest.json`
- `seqlock_reader_writer_contract.json`
- `summary.md`
- `trace_ids.json`

## Verification

```bash
./scripts/run_seqlock_reader_writer_contract_suite.sh ci
./scripts/e2e/seqlock_reader_writer_contract_replay.sh ci
```

The suite is `rch`-backed, defaults `CARGO_TARGET_DIR` to the stable repo-local
path `target_rch_seqlock_reader_writer_contract`, and emits the contract bundle
under
`artifacts/seqlock_reader_writer_contract/<timestamp>/`.

Override `CARGO_TARGET_DIR=...` only when you need isolated experimentation.
The suite manifest records both `cargo_target_dir` and
`cargo_target_dir_strategy` so timeout/debug traces show whether the run used
the reusable default or an explicit override.
