# RGC FrankenNode Handoff Bundle V1

## Purpose

`bd-1lsy.5.10.3` defines the deterministic engine-to-product handoff bundle
that `franken_node` and later GA packaging work can consume without hidden side
channels, oral tradition, or reverse-engineering current bead state.

The handoff bundle is intentionally downstream-facing:

- it consumes engine-owned readiness artifacts rather than re-deriving them
- it proves that the repo split contract is still being honored
- it fails closed when upstream evidence is missing, stale, or orphaned

## Inputs

The workflow consumes three authoritative inputs:

1. `support_surface_contract.json`
2. `engine_product_blocker_ledger.json`
3. [`docs/REPO_SPLIT_CONTRACT.md`](./REPO_SPLIT_CONTRACT.md)

Input resolution rules:

- support-surface contract: use `RGC_HANDOFF_SUPPORT_CONTRACT_PATH` when set;
  otherwise prefer the latest complete
  `artifacts/rgc_support_surface_contract/*/support_surface_contract.json`;
  otherwise fall back to `docs/support_surface_contract.json`
- blocker ledger: use `RGC_HANDOFF_BLOCKER_LEDGER_PATH` when set; otherwise
  auto-discover the latest `engine_product_blocker_ledger.json` under
  `artifacts/`; if none exists, fail closed
- sibling repo: use `RGC_HANDOFF_SIBLING_REPO_PATH` when set; otherwise default
  to `/dp/franken_node`

## Bundle Artifacts

The runner emits:

- `franken_node_handoff_manifest.json`
- `sibling_smoke_verification.json`
- `support_surface_summary.md`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- copied input artifacts:
  `franken_node_handoff_bundle_contract.json`,
  `support_surface_contract.json`,
  `engine_product_blocker_ledger.json`,
  `repo_split_contract.md`
- `step_logs/step_*.log`

All heavy Rust verification in this lane runs through `rch`.

## Sibling Smoke Checks

The bundle must verify at least:

1. the sibling repo path exists
2. the repo split contract still documents one-way dependency direction
3. the support-surface contract still delegates product-ready claims to
   downstream `franken_node` handoff evidence
4. unresolved blocking/degraded blocker entries are not orphaned
5. the blocker ledger exposes cohort rollups that downstream rollout work can
   consume

## Failure Semantics

The workflow fails closed when any of the following occur:

- missing or invalid handoff contract JSON
- missing or invalid support-surface contract JSON
- missing or invalid blocker ledger JSON
- stale support-surface or blocker-ledger evidence beyond the configured age
- missing sibling repo
- repo split contract drift
- orphaned unresolved blocking/degraded blocker entries
- missing copied-artifact or structured-log outputs

Fail-closed means the runner may still emit a diagnostic manifest, but the run
must not be treated as a complete handoff bundle.

## Operator Verification

```bash
jq empty docs/franken_node_handoff_bundle_v1.json
jq empty docs/support_surface_contract.json
RGC_HANDOFF_BLOCKER_LEDGER_PATH=/abs/path/engine_product_blocker_ledger.json \
  ./scripts/run_rgc_franken_node_handoff_bundle.sh ci
RGC_HANDOFF_BLOCKER_LEDGER_PATH=/abs/path/engine_product_blocker_ledger.json \
  ./scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh ci
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=$PWD/target_rch_rgc_franken_node_handoff_bundle_verify \
  CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo test -p frankenengine-engine --test franken_node_handoff_bundle
```
