# Franken-Core API Parity Ledger V1

Status: active
Primary bead: `bd-4w7h9.2`
Parent wave: `bd-4w7h9`
Graduation contract: `docs/franken_core_graduation_contract_v1.json`
Machine-readable ledger: `docs/franken_core_api_parity_ledger_v1.json`

## Scope

This ledger inventories every public module exported by
`crates/franken-core/src/lib.rs` and matches it to the same module name in
`crates/franken-engine/src/lib.rs`. It is a graduation-readiness artifact only:
it does not change APIs, move code, or approve workspace membership.

The current inventory has 41 franken-core module exports. All 41 names are also
exported by `franken-engine`, but most corresponding source files differ. That
means the current state is parity-visible, not parity-proven.

## Contract Version

- `schema_version`: `franken-engine.franken-core-api-parity-ledger.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-franken-core-api-parity-ledger-v1`

## Status Vocabulary

Rows use one of these stable statuses:

- `canonical_core`: the module is ready to be owned by `franken-core`
- `canonical_engine`: the module remains owned by `franken-engine`
- `intentionally_divergent`: both crates intentionally keep different semantics
- `pending_graduation`: ownership is not settled by this ledger
- `not_comparable`: no meaningful module-level comparison exists

For this first ledger, every row is `pending_graduation`. The root workspace
still excludes `crates/franken-core`, and `bd-4w7h9.8` has not accepted the
graduation package. Any stronger owner claim must be made in a later bead with
proof attached.

## Current Inventory

| Metric | Value |
| --- | --- |
| franken-core public modules | 41 |
| matching franken-engine public modules | 41 |
| missing engine module names | 0 |
| identical source files | 3 |
| different source files | 38 |
| workspace inclusion complete | false |

## Historical Inputs

| Bead | Relevance |
| --- | --- |
| `bd-ucemx` | Earlier exclusion decision; superseded as a compileability blocker but still relevant historical context. |
| `bd-zsais` | Restored standalone manifest compileability and several extracted modules. |
| `bd-dymfz` | Restored standalone franken-core test baseline. |
| `bd-yqpka` | Fail-closed async-generator placeholder fix in franken-core. |
| `bd-la2e0` | Fail-closed async-function placeholder fix in franken-core. |
| `bd-nwhcp` | Timer placeholder tests replaced with executable regressions. |

## Fail-Closed Rules

The smoke checker rejects:

- a `crates/franken-core/src/lib.rs` export missing from the ledger
- duplicate ledger rows for the same module
- a status outside the vocabulary above
- stale source paths
- a recorded source relation that no longer matches the live files
- a missing matching `franken-engine` export
- any claim that workspace inclusion is complete

## Validation

```bash
jq empty docs/franken_core_api_parity_ledger_v1.json
bash -n scripts/e2e/franken_core_api_parity_ledger_smoke.sh
bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh check
bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md docs/franken_core_api_parity_ledger_v1.json scripts/e2e/franken_core_api_parity_ledger_smoke.sh
```
