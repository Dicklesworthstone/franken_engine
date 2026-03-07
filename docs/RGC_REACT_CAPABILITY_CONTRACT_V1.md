# RGC React Capability Contract V1

Status: active
Primary bead: bd-1lsy.1.6.1
Track id: RGC-016A
Machine-readable contract: `docs/rgc_react_capability_contract_v1.json`
Matrix extension: `docs/rgc_executable_compatibility_target_matrix_v1.json`

## Purpose

`RGC-016A` extends the RGC compatibility target matrix so React support is
described as explicit capability rows instead of a hand-wavy claim.

The contract exists to prevent false equivalence between:

- "TS compiles"
- "TSX parses"
- "a demo renders"
- "React is shipped, supported, and parity-gated"

Every React-facing capability must name the owning implementation bead, the
parity gate that must go green before the row can be promoted, and the user or
operator surface that would expose the capability. Unsupported or deferred rows
must fail closed with explicit diagnostics.

## Capability Model

Each row in the machine-readable contract includes:

- `capability_id`
- `source_form`
- `runtime_mode`
- `entry_surface`
- `support_status`
- `owning_implementation_bead`
- `parity_gate_bead`
- `product_surface_bead`
- `verification_lane`
- `required_artifacts`
- `user_visible_diagnostic`
- `unsupported_surface_policy`

Allowed `support_status` values are:

- `unsupported`
- `deferred`
- `gated_preview`
- `shipped`

Until the shipped React operator surface (`bd-1lsy.10.12*`) and the React
parity gates (`bd-1lsy.9.7*`) are green, rows stay in `unsupported` or
`deferred` state and must not be represented as shipped support.

## Explicit Capability Rows

| Capability | Current status | Owning bead | Parity gate | Product surface |
|---|---|---|---|---|
| `jsx-classic-runtime-compile` | `deferred` | `bd-1lsy.3.6.1` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.1` |
| `tsx-classic-runtime-compile` | `deferred` | `bd-1lsy.3.6.1` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.1` |
| `fragment-lowering-contract` | `deferred` | `bd-1lsy.3.6.1` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.1` |
| `jsx-automatic-runtime-compile` | `deferred` | `bd-1lsy.3.6.2` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.1` |
| `tsx-automatic-runtime-compile` | `deferred` | `bd-1lsy.3.6.2` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.1` |
| `jsx-dev-runtime-diagnostics` | `unsupported` | `bd-1lsy.3.6.2` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.2` |
| `react-ssr-entrypoint` | `unsupported` | `bd-1lsy.5.7.2` | `bd-1lsy.9.7.2` | `bd-1lsy.10.12.3` |
| `react-client-entry-preparation` | `unsupported` | `bd-1lsy.5.7.1` | `bd-1lsy.9.7.2` | `bd-1lsy.10.12.3` |
| `react-hydration-handoff-artifacts` | `unsupported` | `bd-1lsy.5.7.2` | `bd-1lsy.9.7.2` | `bd-1lsy.10.12.3` |
| `react-diagnostics-source-maps` | `deferred` | `bd-1lsy.10.5` | `bd-1lsy.9.7.1` | `bd-1lsy.10.12.2` |

## Unsupported-Surface Governance

Rows in `unsupported` or `deferred` state are fail-closed:

- maximum waiver age: `168` hours
- waiver is mandatory before any limited preview or doc-language exception
- user-visible diagnostics are mandatory
- fallback mode must be explicit (`reject_with_guidance` or
  `diagnostic_only_reject`)
- remediation guidance must route through `bd-1lsy.10.11.2`

This contract is intentionally conservative: until a React row has a shipped
product surface plus a green parity gate, the supported user message is "not
yet shipped" rather than "probably works."

## Structured Logging and Artifact Contract

Validation and replay runs must emit structured logs with these required fields:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `component`
- `event`
- `runtime_lane`
- `seed`
- `outcome`
- `error_code`

Artifacts are emitted under:

`artifacts/rgc_react_capability_contract/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `react_capability_contract.json`

## Operator Verification

```bash
jq empty docs/rgc_react_capability_contract_v1.json

./scripts/run_rgc_react_capability_contract.sh ci

./scripts/e2e/rgc_react_capability_contract_replay.sh ci
```
