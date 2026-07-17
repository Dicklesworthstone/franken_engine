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

The current inventory has 42 franken-core module exports. All 42 names are also
exported by `franken-engine`, but all corresponding source files differ. That
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

For this first ledger, every row is `pending_graduation`. The root workspace now
includes `crates/franken-core` under `bd-cixqu.10.7`; module ownership claims
still require row-level evidence and should not be inferred from membership
alone.

## Current Inventory

| Metric | Value |
| --- | --- |
| franken-core public modules | 42 |
| matching franken-engine public modules | 42 |
| missing engine module names | 0 |
| identical source files | 0 |
| different source files | 42 |
| workspace inclusion complete | true |

## Historical Inputs

| Bead | Relevance |
| --- | --- |
| `bd-ucemx` | Earlier exclusion decision; superseded as a compileability blocker but still relevant historical context. |
| `bd-zsais` | Restored standalone manifest compileability and several extracted modules. |
| `bd-dymfz` | Restored standalone franken-core test baseline. |
| `bd-yqpka` | Fail-closed async-generator placeholder fix in franken-core. |
| `bd-77ec1` | Open engine follow-up for suspended async-generator `.next()` body execution and truthful support claims. |
| `bd-la2e0` | Fail-closed async-function placeholder fix in franken-core. |
| `bd-nwhcp` | Timer placeholder tests replaced with executable regressions. |
| `bd-n8eta.4` | Executable Symbol property-key parity wave; ADR/API contract, engine/core carriers, hook migration, and donor closeout are separate children. |
| `bd-b12xs` | Exact UTF-16 property-key migration; exact lookup, ordered storage, and runtime adoption are separate children. |
| `bd-f1ixz` | Adds the versioned core-only `CopyDataProperties` IR path for object rest; the engine mirror remains a separate parity concern. |

## Active Parity Exception: `CopyDataProperties` IR

`bd-f1ixz` advances the core IR schema to `0.3.0` with additive
`Ir1Op::CopyDataProperties` and `Ir3Instruction::CopyDataProperties` variants.
The independently owned engine IR mirror remains at schema `0.2.0` without
those variants. The `ir_contract` row therefore stays `pending_graduation`
with ownership unsettled: future parity work must reconcile the versioned
wire, lowering, and execution behavior before changing that status.

## Active Parity Exception: Executable Symbol Keys

`bd-n8eta.4.1` records a wire-additive but Rust-source-breaking versioned
evolution in ADR-0008. Both descriptor object models already have typed Symbol
identities and correct `[[OwnPropertyKeys]]` order, but their executable
baseline heaps are not at parity: franken-core has no executable Symbol value,
while franken-engine uses heap objects and projects computed Symbol keys to
strings.

The parity row therefore remains `pending_graduation`. Evidence must land in
this order:

| Bead | Required evidence |
| --- | --- |
| `bd-n8eta.4.6` | Stages both public runtime crates at unreleased `0.2.0`, marks both `Value` enums non-exhaustive, preserves historical serde bytes, and records the clean downstream match audit. |
| `bd-n8eta.4.2` | Engine uses typed Symbol identity for lookup, ordering, replay, memory, and the correct consumer filters. |
| `bd-n8eta.4.3` | Core adds the same executable value/key contract and proves QuickJS/V8 profile parity. |
| `bd-n8eta.4.4` | The frozen string-only property-hook boundary gains an explicitly reviewed typed-key migration without a string alias. |
| `bd-n8eta.4.5` | Node/Bun donor cases and lockstep engine/core tests prove the combined surface before DISC-013 closes. |

Legacy string-only heap payloads must remain readable, and a historical string
such as `"Symbol(14)"` must remain distinct from `SymbolId(14)`. Workspace
membership or a passing descriptor-model test is not evidence that this
executable parity gap is closed. Legacy object-backed engine Symbols may be
canonicalized only by the versioned whole-artifact migration specified in
ADR-0008, never by guessing from an arbitrary heap object.

## Active Parity Exception: Exact UTF-16 String Keys

`bd-b12xs.1` added `js_string::ExactPropertyMap`, which keeps lone-surrogate
keys exact and uses a dual JSON wire shape. `bd-b12xs.2` adds the corresponding
`object_model::ExactOrderedStringMap` as a stable, additive core API: canonical
array indices iterate numerically first, other exact strings retain creation
order, and borrowed and owning iterators return `JsString` keys without a lossy
projection.

The existing `OrderedStringMap` signatures and runtime heap fields remain
unchanged. Runtime adoption and engine/core item-level parity are later
`bd-b12xs` work, so the `js_string` and `object_model` rows remain
`pending_graduation`. Required adoption evidence must preserve all of these
properties:

- lone D800, lone D801, and literal U+FFFD keys remain three distinct entries
- all-well-formed maps retain the historical map-shaped bytes
- any lone-surrogate key selects an ES-ordered exact pair sequence for the
  whole map
- decoders reject duplicate canonical keys while accepting both wire shapes

## Fail-Closed Rules

The smoke checker rejects:

- a `crates/franken-core/src/lib.rs` export missing from the ledger
- duplicate ledger rows for the same module
- a status outside the vocabulary above
- stale source paths
- a recorded source relation that no longer matches the live files
- a missing matching `franken-engine` export
- any claim that workspace inclusion alone settles canonical module ownership

## Validation

```bash
jq empty docs/franken_core_api_parity_ledger_v1.json
bash -n scripts/e2e/franken_core_api_parity_ledger_smoke.sh
bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh check
bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md docs/franken_core_api_parity_ledger_v1.json scripts/e2e/franken_core_api_parity_ledger_smoke.sh
```
