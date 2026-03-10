# RGC Support Surface Contract V1

Status: active
Primary bead: `bd-1lsy.10.11.2`
Machine-readable contracts:
- `docs/support_surface_contract.json`
- `docs/support_surface_mode_matrix.json`

## Purpose

`RGC-911B` publishes the explicit support boundary that operator-facing docs,
CLI guidance, rollout language, and downstream release gates are allowed to use.

The contract exists so the public story is derived from the same evidence that
already governs:

- shipped `frankenctl` help and README surfaces
- React capability rows and fail-closed diagnostics
- TypeScript normalization subset limits
- module-resolution fallback semantics
- cross-platform verification tiers
- observability-mode restrictions for lossless evidence

Unsupported or deferred surfaces are acceptable only when they are visible,
diagnostic, and paired with concrete remediation guidance.

## Surface Families

The machine-readable contract covers these areas:

- `parser`
- `typescript`
- `runtime`
- `module`
- `platform_support`
- `observability_mode`

Each row names:

- the current `support_status`
- the allowed public claim language (`shipped_fact` or `target_only`)
- the operator-facing entry surface
- the evidence sources that justify the status
- the diagnostic and fallback policy when the surface is not fully shipped

## Current Support Boundary

Current notable rows:

- `runtime.frankenctl_core_workflows`: shipped
- `runtime.doctor_support_bundle_export`: shipped, but lossless-mode bound
- `runtime.react_compile_contract`: deferred and fail-closed
- `runtime.react_execution_entrypoints`: unsupported and fail-closed
- `typescript.normalization_subset`: shipped only for the documented subset
- `typescript.namespace_export_extended_forms`: unsupported
- `typescript.non_class_decorators`: unsupported
- `parser.unsupported_syntax_scaffold`: unsupported and diagnostic-first
- `module.resolution_index_exact_keys`: shipped with explicit wildcard fallback
- `platform.windows_arm64_candidate`: candidate tier only
- `observability.degraded_lossless_evidence_paths`: unsupported

## Observability Mode Matrix

`docs/support_surface_mode_matrix.json` binds mode-sensitive surfaces to the
current observability contract.

Required modes:

- `default_capture`
- `degraded`
- `exact_shadow`
- `support_bundle_export`
- `incident_full_capture`

Current rules:

- `degraded` is not a valid path for replay, security, legal-provenance, or
  support-bundle claims
- support-bundle export must stay lossless
- incident-grade capture remains lossless
- exact-shadow is the minimum publication-safe shadow mode for lossless claim
  paths that are not support-bundle export

## Diagnostics And Remediation

Rows in `unsupported`, `deferred`, or `candidate` state must provide:

- a user-visible message template
- a deterministic diagnostic surface
- an explicit fallback mode
- a remediation path that keeps public wording target-only

The contract intentionally prefers clear rejection plus remediation over vague
"may work" language.

## Structured Logging And Artifacts

Gate runs emit:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `support_surface_contract_report.json`
- `support_surface_contract.json`
- `support_surface_mode_matrix.json`
- `step_logs/`

under `artifacts/rgc_support_surface_contract/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/support_surface_contract.json
jq empty docs/support_surface_mode_matrix.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_support_surface_contract \
  cargo test -p frankenengine-engine --test support_surface_contract

./scripts/run_rgc_support_surface_contract.sh ci
./scripts/e2e/rgc_support_surface_contract_replay.sh ci
```
