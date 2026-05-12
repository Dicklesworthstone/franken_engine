# Franken-Core Graduation Contract V1

Status: active
Primary bead: `bd-4w7h9.1`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_graduation_contract_v1.json`

## Scope

This contract defines the evidence required before `crates/franken-core` can move
from an excluded standalone crate toward intentional workspace participation.

The current root workspace explicitly excludes `crates/franken-core`. The crate
has regained standalone compileability and test coverage through later work, but
that does not make workspace membership complete or approved. Graduation remains
blocked until the IDEA-WIZARD-V acceptance suite (`bd-4w7h9.8`) proves the
contract, parity ledger, validation planner, no-mock drill, truth gate, staged
rehearsal, and golden reports are coherent.

## Contract Version

- `schema_version`: `franken-engine.franken-core-graduation-contract.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-franken-core-graduation-v1`

## Current Decision

`crates/franken-core` remains excluded from the root workspace until a separate
explicit workspace-membership bead is opened after `bd-4w7h9.8` passes.

The contract may describe future command evidence, but this bead must not change
root `Cargo.toml`, workspace membership, dependency direction, `franken_node`, or
cross-repo ownership.

## Historical Inputs

| Bead | Current role |
| --- | --- |
| `bd-ucemx` | Earlier investigation chose documentation-only exclusion when required modules were missing. |
| `bd-zsais` | Later work restored standalone manifest compileability for `crates/franken-core`. |
| `bd-dymfz` | Later work restored the standalone `crates/franken-core` test baseline. |
| `bd-nwhcp` | Later work replaced timer placeholder tests with executable franken-core regressions. |

These beads are inputs to the graduation decision. They are not, by themselves,
authorization to mutate workspace membership.

## Canonical Owners

| Surface | Owner |
| --- | --- |
| Root workspace topology | `/data/projects/franken_engine/Cargo.toml` |
| Native runtime engine | `crates/franken-engine` |
| Extracted core candidate | `crates/franken-core` |
| Compatibility and product surfaces | `/data/projects/franken_node` |
| SQLite-backed persistence policy | `/dp/frankensqlite` and `/dp/sqlmodel_rust` when typed schema layers are needed |

The repository split remains one-way: `franken_node` may depend on
`franken_engine`; `franken_engine` must not depend on `franken_node`.

## Mutation Boundary

This bead may add or update the contract documents and contract checker. It must
not:

- edit root workspace members or `exclude`
- add `crates/franken-core` to the workspace
- introduce engine forks inside `franken_node`
- add a core-to-node dependency
- replace sibling-repo reuse policy with local substitutes
- run heavy Cargo outside `rch`
- present standalone compileability as completed workspace inclusion

## Accepted Evidence

The graduation package must eventually include:

- an API parity ledger between `crates/franken-core` and `crates/franken-engine`
- a validation impact planner with fail-closed unknown path handling
- a no-mock drill over real manifests and source imports
- a stale-exclusion truth gate for docs and manifests
- a staged-inclusion rehearsal that does not mutate root workspace topology
- golden artifacts for every graduation report
- final acceptance output from `bd-4w7h9.8`

Missing evidence keeps the crate excluded.

## RCH Policy

Any heavy Rust proof command in this lane must be wrapped by `rch` and must name
an explicit target directory:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_graduation CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
```

Local validation for this contract is limited to JSON shape checks, shell syntax
checks, text scans, and `git diff --check`.

## Fail-Closed Conditions

The contract checker must reject:

- missing required document sections
- unknown proof states
- any claim that workspace inclusion is complete before `bd-4w7h9.8`
- a missing root `Cargo.toml` exclusion for `crates/franken-core` while this
  contract still declares the current state as excluded
- missing RCH target-dir guidance for heavy Rust command examples

## Validation

```bash
jq empty docs/franken_core_graduation_contract_v1.json
bash -n scripts/e2e/franken_core_graduation_contract_smoke.sh
bash scripts/e2e/franken_core_graduation_contract_smoke.sh check
bash scripts/e2e/franken_core_graduation_contract_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md docs/franken_core_graduation_contract_v1.json scripts/e2e/franken_core_graduation_contract_smoke.sh
```
