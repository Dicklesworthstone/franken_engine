# RCH Cache Miss Forensic Ledger

`bd-n4dfb` adds a fixture-fed forensic ledger for preserved RCH summaries. It
classifies cache HIT/MISS behavior, proves whether remote execution evidence is
usable, and emits a proof freshness diff for command, toolchain, target-dir,
sync-root, and dependency-root drift.

Machine-readable contract:
[`docs/rch_cache_miss_forensic_ledger_contract_v1.json`](./rch_cache_miss_forensic_ledger_contract_v1.json).

Implementation:
`scripts/rch_cache_miss_forensic_ledger.sh`.

## Boundary

The ledger is advisory-only and proof-only. It never runs Cargo, never invokes
`rch exec`, never queries workers, never mutates `br`, never sends Agent Mail,
never changes queue policy, and never creates or deletes target directories.

The ledger requires a preserved transcript with an explicit RCH remote proof
marker. Local fallback markers fail closed and cannot be treated as remote proof.

## Inputs

Required:

- `--summary-log`: preserved RCH summary or transcript excerpt.
- `--metadata-json`: command metadata with worker id, job id, command
  fingerprint, toolchain, `CARGO_TARGET_DIR`, `RUSTFLAGS`, sync root hash,
  dependency roots, and artifact retrieval bytes.

The metadata may include an `expected` object. Differences between current and
expected values are emitted in `proof_freshness_diff.json`.

## Outputs

- `rch_cache_miss_forensic_ledger.json`
- `proof_freshness_diff.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Decisions

- `pass`: remote proof is present, no local fallback fail-closed marker exists,
  required metadata is present, and cache state is either hit or otherwise not
  degraded.
- `degraded`: remote proof is present but cache miss, artifact retrieval, or
  freshness drift evidence needs operator attention.
- `fail_closed`: remote proof is missing, local fallback fail-closed markers are
  present, worker/job metadata is missing, or the transcript is truncated.

## Validation

```bash
jq empty docs/rch_cache_miss_forensic_ledger_contract_v1.json scripts/testdata/rch_cache_miss_forensic_ledger/cases.json
bash -n scripts/rch_cache_miss_forensic_ledger.sh scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh
bash scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh check
bash scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh selftest
git diff --check -- docs/RCH_CACHE_MISS_FORENSIC_LEDGER.md docs/rch_cache_miss_forensic_ledger_contract_v1.json scripts/rch_cache_miss_forensic_ledger.sh scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh scripts/testdata/rch_cache_miss_forensic_ledger/cases.json
```
