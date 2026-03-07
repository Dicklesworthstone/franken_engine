# RGC Executable Compatibility Target Matrix V1

Status: active
Primary bead: bd-1lsy.1.1
Track id: RGC-011
Machine-readable contract: `docs/rgc_executable_compatibility_target_matrix_v1.json`

## Purpose

`RGC-011` defines the normative "works for real" compatibility envelope for the
Reality Gap Closure program (`bd-1lsy`).

This matrix is executable by design:
- each mapped requirement references an explicit test or gate entrypoint,
- each row declares deterministic seed policy,
- each row declares required logs and artifact triad,
- selector coverage fails closed if any open `bd-1lsy*` bead is unmapped.

## Matrix Model

Each verification row is represented with the following fields:

- `row_id`
- `bead_selectors`
- `requirement_id`
- `test_kind` (`unit` | `integration` | `e2e`)
- `harness_entrypoint`
- `deterministic_seed_policy`
- `required_log_fields`
- `artifact_paths`
- `gate_owner`
- `pass_fail_interpretation`

Selector semantics are deterministic:
- exact selector: `bd-1lsy.4.1` matches only that bead
- wildcard selector: `bd-1lsy.4.*` matches `bd-1lsy.4` and all `bd-1lsy.4.x` children

## React/JSX/TSX Extension

`RGC-016A` extends this matrix through the dedicated React capability contract:

- `docs/RGC_REACT_CAPABILITY_CONTRACT_V1.md`
- `docs/rgc_react_capability_contract_v1.json`

That extension carries explicit rows for:

- JSX compile-path coverage
- TSX compile-path coverage
- fragment lowering
- classic runtime
- automatic runtime
- `jsx-dev` runtime diagnostics
- SSR entrypoints
- client-entry preparation
- hydration handoff artifacts
- React diagnostics and source-map fidelity

Until the React operator surface (`bd-1lsy.10.12*`) and parity gates
(`bd-1lsy.9.7*`) are actually green, these rows remain fail-closed. The
contract forbids treating narrow TSX demos as evidence that "React works" in a
shipped, user-supportable sense.

## Compatibility Targets By Milestone

| Milestone | Compatibility objective | Required beads (minimum) | Stop/Go rule |
|---|---|---|---|
| M1 | Real parse->lower->execute baseline path | `bd-1lsy.2.1`, `bd-1lsy.3.1`, `bd-1lsy.4.1` | Fail closed unless required rows have unit+integration+e2e coverage and green artifacts |
| M2 | Semantics + module interop practical readiness | `bd-1lsy.4.2`, `bd-1lsy.4.3`, `bd-1lsy.5.1`, `bd-1lsy.5.2` | No promotion when gap lacks explicit deterministic fallback + stable error code |
| M3 | Security controls in execution hot path | `bd-1lsy.6.1`, `bd-1lsy.6.2`, `bd-1lsy.6.3`, `bd-1lsy.6.4` | Block on missing replay linkage for capability/IFC/containment decisions |
| M4 | Tiered performance + statistical governance | `bd-1lsy.7.1`, `bd-1lsy.7.2`, `bd-1lsy.8.1`, `bd-1lsy.8.2` | No speed claims without reproducible significance/variance evidence |
| M5 | GA evidence closure and external reproducibility | `bd-1lsy.9.1`, `bd-1lsy.9.2`, `bd-1lsy.10.4`, `bd-1lsy.11.5` | Release blocked unless artifact triad is complete and replay command is present |

## Required Logging Fields

Every row in this matrix requires at minimum:

- `trace_id`
- `decision_id`
- `runtime_lane`
- `seed`
- `result`
- `error_code`

Additional lane-specific fields are allowed, but these six fields are mandatory
for deterministic triage parity across all RGC tracks.

## Waiver Governance

Waivers are exceptional and fail-closed:

- required fields: `waiver_id`, `bead_id`, `requirement_id`, `owner`,
  `expiry_utc`, `rationale`, `mitigation_plan`, `approval_signature_ref`
- max waiver age: 168 hours
- expired or unsigned waiver invalidates row compliance immediately

## Diff-Reviewability Contract

The machine-readable matrix file is versioned and committed:

- `docs/rgc_executable_compatibility_target_matrix_v1.json`

Any coverage change must appear as a code-reviewable diff in that file and must
be accepted by the validation tests in
`crates/franken-engine/tests/rgc_executable_compatibility_target_matrix.rs`.

## Operator Verification

```bash
jq empty docs/rgc_executable_compatibility_target_matrix_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_contract \
  cargo test -p frankenengine-engine --test rgc_executable_compatibility_target_matrix

./scripts/run_rgc_react_capability_contract.sh ci

./scripts/run_phase_a_exit_gate.sh check
```
