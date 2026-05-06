# SWARM_RCH_STALL_REHABILITATION_LEDGER

`scripts/swarm_rch_stall_rehabilitation_ledger.sh` is the SWARM-OPS-P0-E
fixture-fed rehabilitation planner for repeated remote compile stalls. It reads
preserved SWARM-OPS state, worker/job status, and stall observations, then
emits advisory-only receipts for quarantine, probe, drain, or rehab follow-up.

Machine-readable contract:
`docs/swarm_rch_stall_rehabilitation_ledger_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_rch_stall_rehabilitation/rehab_fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh`.

## Inputs

Required:

- `--swarm-ops-state-snapshot-json FILE`
- `--worker-status-json FILE`
- `--stall-observations-json FILE`

Optional:

- `--worker-capabilities-json FILE`
- `--operator-actions-json FILE`

The ledger is evidence-only. It does not execute `rch workers probe`, `rch
workers drain`, `rch workers enable`, or `rch workers capabilities --refresh`.
It only emits those exact command forms as operator receipts.

## Classifications

Each worker is classified as exactly one of:

- `healthy`
- `watch`
- `probe_required`
- `drain_recommended`
- `drained`
- `rehab_candidate`

The planner distinguishes:

- real code failures (`source_failure`) from remote transport stalls
- repeated stale-progress / fresh-heartbeat stalls that should recommend drain
- local fallback contamination that should trigger probe, not drain
- successful rehab evidence that justifies re-enable receipts

## Artifacts

Each run emits:

- `swarm_rch_stall_rehabilitation_ledger.json`
- `swarm_rch_stall_rehabilitation_receipts.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The receipts include exact non-destructive operator command strings such as:

- `rch workers probe WORKER --json`
- `rch workers drain -y WORKER`
- `rch workers enable WORKER`
- `rch workers capabilities --refresh --json`

## Proof Cases

The checked-in fixtures cover:

- `fresh_progress`
- `stale_progress_fresh_heartbeat`
- `cancellation_clean`
- `telemetry_gap`
- `drained_worker`
- `successful_rehab`
- `local_fallback_contaminated`

Repeated remote stalls on the same worker must recommend drain before retry.
Telemetry gaps and local fallback contamination must recommend probe/refresh
instead of pretending that drain is already justified.

## Validation

```bash
bash -n scripts/swarm_rch_stall_rehabilitation_ledger.sh
bash -n scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh
shellcheck -x scripts/swarm_rch_stall_rehabilitation_ledger.sh scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh
jq empty docs/swarm_rch_stall_rehabilitation_ledger_contract_v1.json scripts/testdata/swarm_rch_stall_rehabilitation/rehab_fixtures.json
bash scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh check
bash scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh selftest
git diff --check -- docs/SWARM_RCH_STALL_REHABILITATION_LEDGER.md docs/swarm_rch_stall_rehabilitation_ledger_contract_v1.json scripts/swarm_rch_stall_rehabilitation_ledger.sh scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh scripts/testdata/swarm_rch_stall_rehabilitation/rehab_fixtures.json
```
