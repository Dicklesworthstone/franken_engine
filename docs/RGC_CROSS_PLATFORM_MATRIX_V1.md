# RGC Cross-Platform Matrix Contract V1

Status: active  
Primary bead: `bd-1lsy.11.13`  
Machine-readable contract: `docs/rgc_cross_platform_matrix_v1.json`

## Scope

This contract defines deterministic cross-platform verification for runtime
execution and CLI workflows across Linux/macOS/Windows and x64/arm64 targets.

The matrix is evidence-first:
- each target contributes a deterministic manifest input,
- drift is classified with stable class/severity codes,
- strict mode fails closed on unresolved critical drift.

## Contract Version

- `schema_version`: `franken-engine.rgc-cross-platform-matrix.v1`
- `contract_version`: `1.1.0`
- `policy_id`: `policy-rgc-cross-platform-matrix-v1`

## Matrix Dimensions

Declared targets and manifest inputs are defined in
`docs/rgc_cross_platform_matrix_v1.json`:

- `linux-x64`, `linux-arm64`
- `macos-x64`, `macos-arm64`
- `windows-x64`, `windows-arm64` (candidate tier)

Baseline target for pairwise comparison: `linux-x64`.

## Drift Classification

Deterministic classes:

- `none` (`info`): baseline and target are equivalent.
- `artifact_only_drift` (`warning`): digest drift but normalized runtime/CLI
  digests are equivalent.
- `toolchain_fingerprint_delta` (`warning`): digest drift explained by toolchain
  fingerprint changes.
- `workflow_behavior_drift` (`critical`): outcome or error code diverged.
- `unexplained_digest_drift` (`critical`): digest mismatch without explanation.
- `missing_target_input` (`critical`): target manifest input missing.
- `candidate_target_input_missing` (`warning`): candidate-tier target manifest input missing.
- `missing_baseline_input` (`critical`): baseline manifest missing.

Strict mode fails closed when required-target critical drift remains unresolved.

## Structured Logging Contract

Every gate event must carry:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `target_id`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_cross_platform_matrix_gate.sh`

Replay wrapper:

- `scripts/e2e/rgc_cross_platform_matrix_replay.sh`

Modes:

- `check`, `test`, `clippy`, `ci`, `matrix`

Strict matrix evaluation is active when:

- mode is `matrix`, or
- `RGC_CROSS_PLATFORM_REQUIRE_MATRIX=1`

Manifest inputs are provided by environment variables:

- `RGC_CROSS_PLATFORM_LINUX_X64_MANIFEST`
- `RGC_CROSS_PLATFORM_LINUX_ARM64_MANIFEST`
- `RGC_CROSS_PLATFORM_MACOS_X64_MANIFEST`
- `RGC_CROSS_PLATFORM_MACOS_ARM64_MANIFEST`
- `RGC_CROSS_PLATFORM_WINDOWS_X64_MANIFEST`
- `RGC_CROSS_PLATFORM_WINDOWS_ARM64_MANIFEST`

If per-target env vars are absent and `RGC_CROSS_PLATFORM_AUTO_DISCOVER_MANIFESTS=1`
(default), the gate scans `RGC_CROSS_PLATFORM_MANIFEST_SET_ROOT` (default:
`artifacts/rgc_cross_platform_matrix_inputs`) for the latest complete manifest
set using the filename contract:

- `<target-id>.run_manifest.json`

Resolved matrix input provenance is recorded as `env`, `auto_discovered`, or
`missing` in both `matrix_summary.json` and `run_manifest.json`.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `matrix_target_deltas.jsonl`
- `matrix_summary.json`

under `artifacts/rgc_cross_platform_matrix/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_cross_platform_matrix_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_cross_platform_matrix \
  cargo test -p frankenengine-engine --test rgc_cross_platform_matrix

./scripts/run_rgc_cross_platform_matrix_gate.sh check
./scripts/run_rgc_cross_platform_matrix_gate.sh ci

RGC_CROSS_PLATFORM_MANIFEST_SET_ROOT=artifacts/rgc_cross_platform_matrix_inputs \
  ./scripts/e2e/rgc_cross_platform_matrix_replay.sh matrix

./scripts/e2e/rgc_cross_platform_matrix_replay.sh matrix
```
