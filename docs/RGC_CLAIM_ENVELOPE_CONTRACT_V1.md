# RGC Claim Envelope Contract (`bd-1lsy.1.6.3`)

This document defines the two-tier claim ladder for the V8-supremacy story:
the frontier objective the program is still chasing, and the publishable
declared-board evidence envelope the shipped surface may state as present fact.

## Contract Version

- `schema_version`: `franken-engine.rgc-claim-envelope-contract.v1`
- `contract_version`: `0.1.0`
- `bead_id`: `bd-1lsy.1.6.3`
- `component`: `rgc_claim_envelope_contract`

Canonical machine-readable source:

- `docs/rgc_claim_envelope_contract_v1.json`

## Purpose

The contract prevents two opposite failures:

- shrinking ambition to the current board forever
- publishing frontier ambition as if it were already proven shipped fact

The rule is simple: absolute greatness remains the frontier objective, but
published present-tense language must stay inside the declared board and current
evidence envelope.

## Claim Classes

The machine-readable ladder distinguishes five classes:

- `frontier_objective`
- `publishable_universal`
- `publishable_scoped`
- `target`
- `hypothesis`

`frontier_objective` language is allowed only when it is explicitly marked as a
frontier objective. `publishable_*` classes require current shipped-path
evidence, and `publishable_scoped` statements must carry explicit
`observed`/`declared` qualifiers. `target` and `hypothesis` are the downgrade
surfaces when evidence or freshness is insufficient.

## Contract Inputs

This contract consumes the already-defined inputs from:

- `bd-1lsy.1.6.1` React capability contract
- `bd-1lsy.1.6.2` V8 supremacy claim contract

The envelope contract does not redefine the board. It binds phrase classes and
publication surfaces to those existing board and capability definitions.
Each upstream contract bead appears exactly once in `contract_inputs`.
For the React input, both `contract_inputs` and `board_linkage` pin
`policy-rgc-react-capability-contract-v1` so downstream publication consumers
cannot silently retarget the React contract while keeping the same doc/json
paths.

## Declared Board Linkage

The publishable envelope is linked directly to the declared supremacy board:

- dimensions: `workload_cell`, `environment`, `entry_mode`, `warm_state`,
  `measurement_family`
- families: parse/compile, startup, throughput, async, module graphs, npm,
  React compile, React SSR, React client, macro workloads, tail latency, memory
- React linkage is pinned to
  `docs/rgc_react_capability_contract_v1.json` with policy id
  `policy-rgc-react-capability-contract-v1`, so downstream publication
  consumers cannot silently retarget the React board contract while keeping the
  same file path.

Known uncovered regions must not disappear silently. They route into the
open-world frontier gap ledger owned by `bd-1lsy.1.6.4`.

## Downgrade Ladder

Universal language downgrades deterministically:

- incomplete declared board => `publishable_scoped`
- incomplete shipped evidence => `target`
- stale contract => `hypothesis`
- overlapping frontier gap => `target`

These downgrade rules are machine-readable so docs, advisories, rollout, and GA
surfaces cannot quietly drift apart.

## Consumer Channels

The contract is consumed by:

- docs accuracy gates
- operator advisory/unsupported-surface guidance
- rollout evidence gates
- GA evidence packaging

Each channel has an allowed subset of claim classes and must fail closed if the
required artifacts are missing.

## Required Artifacts

The gate script for this bead must emit:

- `claim_envelope_contract.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`

## Deterministic Execution Contract

All cargo-heavy validation for this contract must run through `rch`.

Canonical command:

```bash
./scripts/run_rgc_claim_envelope_contract.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci`
- `--scenario <scenario_id>`

## Operator Verification

```bash
jq empty docs/rgc_claim_envelope_contract_v1.json
./scripts/run_rgc_claim_envelope_contract.sh ci
./scripts/e2e/rgc_claim_envelope_contract_replay.sh ci
cat artifacts/rgc_claim_envelope_contract/<timestamp>/claim_envelope_contract.json
cat artifacts/rgc_claim_envelope_contract/<timestamp>/run_manifest.json
cat artifacts/rgc_claim_envelope_contract/<timestamp>/events.jsonl
cat artifacts/rgc_claim_envelope_contract/<timestamp>/commands.txt
cat artifacts/rgc_claim_envelope_contract/<timestamp>/trace_ids.json
```
