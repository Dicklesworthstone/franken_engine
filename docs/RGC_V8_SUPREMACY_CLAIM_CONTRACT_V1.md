# RGC V8 Supremacy Claim Contract (`bd-1lsy.1.6.2`)

This document defines the machine-checkable contract for V8-supremacy claims in
the Reality Gap Closure program. The goal is to make phrases like "beats V8
across the board" objectively testable, fail-closed, and tied to the shipped
path rather than marketing drift.

## Contract Version

- `schema_version`: `franken-engine.rgc-v8-supremacy-claim-contract.v1`
- `contract_version`: `0.1.0`
- `log_schema_version`: `franken-engine.rgc-v8-supremacy-claim.log-event.v1`

## Supremacy Matrix

Universal V8-dominance language is illegal unless every required cell family is
green on the shipped path. The matrix is indexed by these dimensions:

- `workload_cell`
- `environment`
- `entry_mode`
- `warm_state`
- `measurement_family`

The minimum required cell families are:

- `parse_compile`
- `startup`
- `throughput_hot_loops`
- `async`
- `module_graphs`
- `npm_cohorts`
- `react_compile`
- `react_ssr`
- `react_client`
- `macro_workloads`
- `tail_latency`
- `memory`

Every cell family must define:

- the measurement family it belongs to
- the required dimensions used to index the cell
- whether that family is mandatory for universal claim language
- confidence and effect thresholds
- tail-latency and memory side constraints
- allowed statistical procedures

## Statistical Thresholds and Side Constraints

The contract must stay machine-readable and fail closed. Each family threshold
entry therefore includes:

- `minimum_confidence_millionths`
- `minimum_effect_millionths`
- `max_tail_regression_millionths`
- `max_memory_regression_millionths`
- `allowed_procedures`

Allowed procedures are intentionally narrow:

- `fixed_horizon_ci`
- `sequential_test`
- `effect_size_guard`
- `tail_side_constraint`
- `memory_side_constraint`

Universal claims require all mandatory families to be green and all side
constraints to pass. A fast microbenchmark is not enough if tail latency or
memory regresses in mixed or product-facing workloads.

## Publication Language Policy

The publication contract distinguishes four phrase classes:

- `universal_dominance`
- `scoped_observed`
- `target`
- `hypothesis`

The following literal-universal phrases are forbidden unless every mandatory
cell is green on the shipped path and the artifact program is complete:

- `beats V8 across the board`
- `across the board`
- `faster than V8 in every case`
- `universally superior to V8`

If any mandatory family is missing, mixed, red, or unpublished, the claim must
be downgraded immediately. The downgrade ladder is:

- use `scoped_observed` when only a bounded subset of published cells is green
- use `target` when the board is incomplete but there is a concrete program to
  finish it
- use `hypothesis` when the claim remains speculative

Every published claim must carry artifact metadata fields for:

- `scope`
- `environment`
- `artifact_path`
- `publication_date`
- `revision`

## Machine-Readable Consumers

This contract is not advisory text. It is consumed by:

- benchmark gates
- docs checks
- rollout checks
- GA checks

Each consumer must treat missing or contradictory supremacy artifacts as a hard
stop for universal language.

## Required Artifacts

The gate script for this bead must emit:

- `supremacy_claim_contract.json`
- `published_language_contract.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

The JSON artifacts are extracted from the canonical fixture and published into
the run directory so benchmark, docs, rollout, and GA automation can consume
the exact same contract without re-encoding it.

## Deterministic Execution Contract

All cargo-heavy validation for this contract must run through `rch`.

Canonical command:

```bash
./scripts/run_rgc_v8_supremacy_claim_contract.sh ci
```

Modes:

- `check`: compile the focused contract test target
- `test`: run the focused contract tests
- `clippy`: lint the focused contract test target with `-D warnings`
- `ci`: run `check`, `test`, and `clippy`
- `--scenario <scenario_id>`: replay one exact publication scenario via the
  corresponding exact Rust test name (for example
  `hypothesis_pending_mixed_board`)

## Operator Verification

```bash
./scripts/run_rgc_v8_supremacy_claim_contract.sh ci
./scripts/run_rgc_v8_supremacy_claim_contract.sh ci --scenario all_green_universal
cat artifacts/rgc_v8_supremacy_claim_contract/<timestamp>/supremacy_claim_contract.json
cat artifacts/rgc_v8_supremacy_claim_contract/<timestamp>/published_language_contract.json
cat artifacts/rgc_v8_supremacy_claim_contract/<timestamp>/run_manifest.json
cat artifacts/rgc_v8_supremacy_claim_contract/<timestamp>/events.jsonl
cat artifacts/rgc_v8_supremacy_claim_contract/<timestamp>/commands.txt
```

The acceptance bar is simple: no artifact, no universal V8-supremacy language.
Scenario replay must also be truthful: if a replay command advertises a specific
scenario id, the runner must execute that exact scenario test instead of silently
falling back to the whole suite.
