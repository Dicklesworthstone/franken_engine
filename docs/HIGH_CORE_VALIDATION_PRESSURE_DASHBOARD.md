# High-Core Validation Pressure Dashboard

`bd-f7zfw` adds a deterministic dashboard for deciding whether a high-core
validation lane should wait, run cheap source-only checks, run an RCH proof, or
split/file a blocker bead.

The machine contract is
[`docs/high_core_validation_pressure_dashboard_contract_v2.json`](./high_core_validation_pressure_dashboard_contract_v2.json).

The dashboard is snapshot-fed only. It does not query live `br`, Agent Mail,
`rch`, Cargo, process tables, worker state, disk state, or target directories.
It also does not mutate live queues, change beads, send mail, repair the mail
database, run Cargo, invoke `rch`, or delete/overwrite target directories.

## Inputs

Required:

- `--resource-envelope-json`: resource envelope or capacity snapshot.
- `--rch-jobs-json`: active RCH job/process snapshot.
- `--process-counts-json`: local cargo/rustc process count snapshot.
- `--proof-shard-plan-json`: proof shard plan or validation plan snapshot.
- `--br-readiness-json`: ready/open bead snapshot.
- `--mail-health-json`: Agent Mail health or captured failure snapshot.

## Recommendations

`run_rch_proof` means the supplied snapshots are nominal: ready beads exist, the
proof shard plan has reusable shards, local cargo/rustc pressure is low, RCH is
below the active-job budget, and the resource envelope is not blocked.

`run_cheap_local_non_cargo_checks` means heavy proof should not start yet, but
source-only validation such as `bash -n`, `jq empty`, and `git diff --check`
still moves the bead safely.

`wait` means host resources or RCH pressure are saturated, blocked, brownout, or
contaminated.

`split_file_blocker_bead` means there is no ready bead or the supplied proof
shard plan is stale, blocked, or empty.

## Output

Each run emits:

- `high_core_validation_pressure_dashboard.json`
- `high_core_validation_pressure_dashboard.md`
- `commands.txt`
- `events.jsonl`

## Validation

```bash
jq empty docs/high_core_validation_pressure_dashboard_contract_v2.json scripts/testdata/high_core_validation_pressure_dashboard/cases.json
bash -n scripts/high_core_validation_pressure_dashboard.sh scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh
./scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh selftest
git diff --check -- docs/HIGH_CORE_VALIDATION_PRESSURE_DASHBOARD.md docs/high_core_validation_pressure_dashboard_contract_v2.json scripts/high_core_validation_pressure_dashboard.sh scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh scripts/testdata/high_core_validation_pressure_dashboard/cases.json
```

Any executable heavy Cargo proof must still use `rch`, for example:

```bash
RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch-target-franken-engine-validation-pressure CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' CARGO_BUILD_JOBS=1 cargo check --all-targets
```
