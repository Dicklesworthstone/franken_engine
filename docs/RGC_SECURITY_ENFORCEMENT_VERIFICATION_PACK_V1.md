# RGC Security Enforcement Verification Pack V1

Status: active  
Primary bead: `bd-1lsy.11.9`  
Machine-readable contract: `docs/rgc_security_enforcement_verification_pack_v1.json`

## Scope

This pack defines deterministic security-enforcement verification for capability
checks, IFC declassification controls, and containment escalation behavior.

It is a dependency-safe prework slice for `bd-1lsy.11.9` that establishes:

- versioned contract schema,
- deterministic adversarial vector set,
- focused invariant tests for vectors and contract integrity,
- rch-only gate and replay wrappers that emit artifact triads.

## Contract Version

- `schema_version`: `franken-engine.rgc-security-enforcement-verification-pack.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-security-enforcement-verification-pack-v1`

## Required Attack Classes

The contract requires coverage for all classes below:

- `capability_denial`
- `ifc_declassification`
- `containment_escalation`

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `attack_class`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_security_enforcement_verification_pack.sh`

Replay wrapper:

- `scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh`

Modes:

- `check`, `test`, `clippy`, `ci`

Heavy cargo operations are fail-closed and remote-only (`rch`); local fallback
is treated as a gate failure.

Vector contract checks are also fail-closed and include:

- required attack-class coverage,
- unique scenario ids and deterministic seeds,
- replay-required and non-empty command templates.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `security_verification_report.json`

under `artifacts/rgc_security_enforcement_verification_pack/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_security_enforcement_verification_pack_v1.json
jq empty docs/rgc_security_enforcement_verification_vectors_v1.json

rch exec -- env CARGO_TARGET_DIR="$PWD/target_rch_rgc_security_enforcement_verification_pack_verify" \
  cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack

./scripts/run_rgc_security_enforcement_verification_pack.sh ci
./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ci
```
