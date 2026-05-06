# RCH Sync Closure Hotspot Ledger

`scripts/rch_sync_closure_hotspot_ledger.sh` is a deterministic shell gate for
ranking sync-closure hotspots across preserved remote-proof runs. It consumes a
recorded suite manifest plus an optional preserved transfer log, then emits a
stable ledger that shows which closure roots are repeatedly resynced across
workers or commands.

This gate is fixture-driven:

- it does not query live `rch` state
- it does not execute Cargo
- it does not mutate bead state

## Contract

Output schema: `franken-engine.rch-sync-closure-hotspot-ledger.v1`

Inputs:

- `--suite-manifest-json FILE`
- `--transfer-log-jsonl FILE` optional

Artifacts:

- `sync_closure_hotspots.json`
- `sync_closure_summary.md`
- `commands.txt`
- `events.jsonl`

The ledger records:

- manifest command count
- logged sync command count
- total unique roots
- repeated hotspot count
- full-sync versus narrow-sync command totals
- per-root hotspot rows with stable ordering
- `input_hash` and `ledger_hash` for deterministic replay

## Input Shape

Suite manifest JSON should provide:

- `schema_version`
- `suite_id`
- `commands[]`

Each command may include:

- `command_id`
- `bead_id`
- `worker_id`
- `requested_command`

Transfer log JSONL rows should provide one JSON object per line. The gate
normalizes the following fields when present:

- `suite_id`
- `command_id`
- `worker_id`
- `transfer_bytes`
- `closure_roots[]`

Rows with at least 16 roots are classified as `full` sync commands. Smaller
rows are classified as `narrow`.

## Degraded Mode

If `--transfer-log-jsonl` is omitted, the gate does not fail open. It emits a
degraded ledger with:

- `analysis_status: "degraded"`
- `degradation_reason: "missing_transfer_log"`
- `transfer_log_status: "missing"`

This keeps the proof surface truthful when only the manifest survived.

## Validation

```bash
bash -n scripts/rch_sync_closure_hotspot_ledger.sh
bash -n scripts/e2e/rch_sync_closure_hotspot_ledger_smoke.sh
./scripts/e2e/rch_sync_closure_hotspot_ledger_smoke.sh check
./scripts/e2e/rch_sync_closure_hotspot_ledger_smoke.sh selftest
```
