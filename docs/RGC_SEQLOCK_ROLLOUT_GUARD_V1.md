# RGC Seqlock Rollout Guard v1

Bead: `bd-1lsy.7.21.3`

This contract gates seqlock rollout on deterministic safety-case evidence,
starvation microbenchmarks, and loom/model-check coverage so read-mostly wins do
not silently ship without correctness and rollback proof.

## Guard Scope

- only candidates already accepted by the inventory and reader/writer lanes are
  evaluated for rollout
- starvation evidence must show deterministic fallback during writer pressure
  and successful post-publication fast-path recovery
- loom/model-check coverage is a hard gate; missing or negative evidence keeps
  rollout fail-closed
- every candidate must publish an incumbent fallback target and explicit disable
  reasons so operators can see why seqlock remains off

## Default Disabled Candidates

- `governance-ledger-head-view`
- `guardplane-calibration-snapshot`
- `module-cache-snapshot`

All three remain disabled by default until positive model-check evidence exists.

## Required Artifacts

- `commands.txt`
- `env.json`
- `events.jsonl`
- `loom_schedule_coverage_report.json`
- `manifest.json`
- `repro.lock`
- `run_manifest.json`
- `seqlock_rollout_guard.json`
- `seqlock_safety_case.json`
- `starvation_microbench_report.json`
- `summary.md`
- `trace_ids.json`

## Verification

```bash
./scripts/run_seqlock_rollout_guard_suite.sh ci
./scripts/e2e/seqlock_rollout_guard_replay.sh ci
```

The suite is `rch`-backed and emits the required 621C bundle under
`artifacts/seqlock_rollout_guard/<timestamp>/`.

The suite defaults `CARGO_TARGET_DIR` to the stable external path
`/data/tmp/rch_target_franken_engine_seqlock_rollout_guard` so remote workers
can reuse incremental artifacts without syncing the build tree back through the
workspace. The replay wrapper re-runs the suite for the requested mode, then
prints the latest complete suite/runner manifests, rollout-guard artifact,
commands, trace IDs, and step-log paths. If the newest artifact directory is
incomplete, it warns and falls back to the latest complete bundle instead.

The wrapper fails closed if:

- `rch` falls back to local execution for any heavy cargo step
- `rch` reports a wrapped `timeout_secs` lower than the requested
  `RCH_BUILD_TIMEOUT_SEC` / `RCH_BUILD_TIMEOUT_SECONDS` value
- artifact retrieval fails or the remote exit marker is missing

Per-step remote logs are written under
`artifacts/seqlock_rollout_guard/<timestamp>/step_logs/`.
