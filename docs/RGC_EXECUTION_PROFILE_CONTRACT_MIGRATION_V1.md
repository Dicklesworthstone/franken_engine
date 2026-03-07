# RGC Execution Profile Contract Migration V1

Status: active  
Primary bead: `bd-1lsy.4.11.1`  
Machine-readable contract: `docs/rgc_execution_profile_contract_v1.json`

## Scope

This migration re-contracts the operator-facing execution vocabulary for the
current FrankenEngine runtime.

The implementation today is one native baseline interpreter with two policy
profiles. It is not two separate engine backends. Operator surfaces, serialized
artifacts, and CLI output must describe that reality directly.

## Canonical Vocabulary

- `baseline_deterministic_profile`
- `baseline_throughput_profile`
- `adaptive_profile_router`
- `default_deterministic_profile`
- `direct_profile_invocation`

## Mapping

- `quickjs_inspired_native` -> `baseline_deterministic_profile`
- `v8_inspired_native` -> `baseline_throughput_profile`
- `QuickJsInspiredNative` -> `baseline_deterministic_profile`
- `V8InspiredNative` -> `baseline_throughput_profile`
- `Hybrid` / `hybrid_router` -> `adaptive_profile_router`
- `DefaultFallback` / `DefaultQuickJsPath` -> `default_deterministic_profile`
- `DirectEngineInvocation` -> `direct_profile_invocation`

## Compatibility Policy

- Canonical labels are emitted for new serde output, CLI output, reports, and
  freshly generated policy artifacts.
- Legacy lineage labels remain accepted on input for migration purposes.
- Existing code identifiers may keep legacy-inspired names internally when that
  avoids invasive churn, but public strings must use the canonical contract.

## Non-Scope

The FRX JS/WASM lane charter in `runtime_kernel_lane_charter.rs` is separate and
unaffected.

This migration does not rename the FRX `js`, `wasm`, or `hybrid_router`
concepts because those model a different execution charter than the current
baseline-interpreter profile router.

## Operator Rollout Guidance

- Update configs and dashboards to prefer `baseline_deterministic_profile`,
  `baseline_throughput_profile`, and `adaptive_profile_router`.
- Treat legacy lineage labels as read-only compatibility input, not as the
  source of truth for new automation.
- When replaying older evidence bundles, preserve the original payloads but map
  the labels to the canonical contract in any derived summaries or dashboards.

## Audit Pack

- `docs/rgc_execution_profile_contract_v1.json`
- `scripts/run_rgc_execution_profile_contract_audit.sh`
- `scripts/e2e/rgc_execution_profile_contract_audit_replay.sh`

## Operator Verification

```bash
jq empty docs/rgc_execution_profile_contract_v1.json
./scripts/run_rgc_execution_profile_contract_audit.sh ci
./scripts/e2e/rgc_execution_profile_contract_audit_replay.sh ci
```
