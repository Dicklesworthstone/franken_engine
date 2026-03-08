# RGC Seqlock Reader/Writer Contract v1

Bead: `bd-1lsy.7.21.2`

This contract operationalizes the accepted seqlock candidates from the inventory lane into
bounded optimistic-read policies, explicit writer pressure budgets, and deterministic fallback
paths back to the incumbent snapshot implementation.

## Contract Scope

- only accepted candidates may use optimistic reads
- every accepted candidate must declare the incumbent baseline path it falls back to
- retry budgets and writer-pressure budgets are machine-readable and replayable
- observed telemetry is emitted alongside the contract so operator surfaces can inspect retry and
  fallback behavior directly

## Required Artifacts

- `seqlock_reader_writer_contract.json`
- `retry_budget_policy.json`
- `incumbent_fallback_matrix.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `env.json`
- `manifest.json`
- `repro.lock`
- `summary.md`

## Accepted Candidate Policies

- `governance-ledger-head-view`: `max_retries=4`, `max_writer_pressure_observations=1`
- `guardplane-calibration-snapshot`: `max_retries=3`, `max_writer_pressure_observations=1`
- `module-cache-snapshot`: `max_retries=2`, `max_writer_pressure_observations=2`

## Verification

```bash
./scripts/run_seqlock_reader_writer_contract_suite.sh ci
./scripts/e2e/seqlock_reader_writer_contract_replay.sh ci
```

The suite is `rch`-backed and emits the required 621B bundle under
`artifacts/seqlock_reader_writer_contract/<timestamp>/`.
