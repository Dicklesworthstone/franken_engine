# Resident Remote Proof Bundle Executor

`scripts/resident_remote_proof_bundle_executor.sh` runs or validates a resident
remote proof bundle. A bundle is a declared `check` / `test` / `clippy` phase
set that must stay on one remote worker and one warm `CARGO_TARGET_DIR`.

The executor is shell-first and artifact-first:

- it accepts a phase manifest that names the expected worker, target-dir, and
  rch-wrapped phase commands
- it can consume preserved phase receipts for deterministic replay tests
- it can execute the manifest commands for operator use
- it emits a replayable bundle report, run manifest, command log, event log,
  summary, and per-phase stdout/stderr logs

It rejects local fallback markers, worker drift, target-dir drift, missing
receipts, nonzero exits, and missing completion markers.

## Contract

Output schema: `franken-engine.resident-remote-proof-bundle.v1`

Required inputs:

- `--agent-id`
- `--bead-id`
- `--phase-manifest-json`

Optional inputs:

- `--phase-receipts-json`
- `--output-dir`

Artifacts:

- `bundle_report.json`
- `run_manifest.json`
- `commands.txt`
- `events.jsonl`
- `summary.md`
- `phase_logs/*.stdout.log`
- `phase_logs/*.stderr.log`

## Phase Manifest

The phase manifest must declare:

- `bundle_id`
- `expected_worker_id`
- `expected_target_dir`
- `phases[]`

Each phase must include `phase`, `command_id`, and `requested_command`. Heavy
commands must be wrapped this way:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_doi34_bundle cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture
```

## Decisions

The executor emits `bundle_decision`:

- `pass`
  Every declared phase has a receipt, uses the expected worker, uses the
  expected target-dir, exits zero, and has a completion marker.
- `fail_closed`
  Any command is not rch-wrapped with the expected `CARGO_TARGET_DIR`, a receipt
  is missing, a worker or target-dir drifts, a local fallback marker appears, a
  phase exits nonzero, or a completion marker is missing.

## Operator Flow

For deterministic replay or smoke validation, pass preserved receipts:

```bash
./scripts/resident_remote_proof_bundle_executor.sh \
  --agent-id ScarletOwl \
  --bead-id bd-doi34 \
  --phase-manifest-json /tmp/phase-manifest.json \
  --phase-receipts-json /tmp/phase-receipts.json
```

For live operator execution, omit `--phase-receipts-json`. The executor will run
the manifest commands and capture stdout/stderr receipts. It still rejects any
phase that is not `rch exec -- env CARGO_TARGET_DIR=...` wrapped.

## Validation

```bash
bash -n scripts/resident_remote_proof_bundle_executor.sh
bash -n scripts/e2e/resident_remote_proof_bundle_executor_smoke.sh
bash scripts/e2e/resident_remote_proof_bundle_executor_smoke.sh check
bash scripts/e2e/resident_remote_proof_bundle_executor_smoke.sh selftest
```
