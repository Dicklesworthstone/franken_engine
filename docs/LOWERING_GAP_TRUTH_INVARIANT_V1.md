# Lowering Gap Truth Invariant V1

Status: active
Primary bead: `bd-2muur.4.1`
Track id: `RGC-920D.1`
Machine-readable contract: `docs/lowering_gap_truth_invariant_v1.json`
Implementation bead: `bd-2muur.4.2`
Consumer-alignment bead: `bd-2muur.4.3`

## Purpose

`bd-2muur.4.1` defines the authoritative invariant for
`crates/franken-engine/src/lowering_gap_inventory.rs`.

The current inventory surface is internally contradictory: every tracked site
currently reports `status = resolved` and resolved prose, while
`execution_ready_semantics` is hard-coded `false`. This contract makes the
allowed status/readiness/prose relationships explicit so future code can reject
contradictory states mechanically instead of relying on human interpretation.

This bead defines the invariant only. `bd-2muur.4.2` applies it to the
generator, and `bd-2muur.4.3` aligns manifests, tests, and downstream
consumers.

## Scope

The lowering-gap inventory only tracks syntax families that the parser already
accepts and hands to lowering. That means `parser_ready_syntax` must be `true`
for every lowering-gap site. Parser-rejection surfaces belong in the parser gap
inventory, not here.

## Allowed State Matrix

Exactly these status/readiness/prose combinations are valid:

| Rule | Status | Parser-ready | Execution-ready | Required prose prefix |
|---|---|---|---|---|
| `resolved_exec_ready` | `resolved` | `true` | `true` | `resolved:` |
| `open_placeholder_parser_ready` | `open_placeholder` | `true` | `false` | `open_placeholder:` |
| `fail_closed_parser_ready` | `fail_closed` | `true` | `false` | `fail_closed:` |

The required prose prefix applies to both:

- `execution_consequence`
- `user_visible_divergence`

Any other combination is invalid.

## Disallowed State Patterns

The contract explicitly rejects at least these contradiction classes:

- `resolved` with `execution_ready_semantics = false`
- `resolved` with prose that does not begin `resolved:`
- `open_placeholder` with `execution_ready_semantics = true`
- `open_placeholder` with prose that still claims `resolved:`
- `fail_closed` with `execution_ready_semantics = true`
- `fail_closed` with prose that still claims `resolved:`
- any lowering-gap site with `parser_ready_syntax = false`

## Structured Logging and Artifact Contract

Validation and replay runs must emit structured logs with these required
fields:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `rule_id`
- `site_id`
- `status`
- `parser_ready_syntax`
- `execution_ready_semantics`

Artifacts are emitted under:

`artifacts/lowering_gap_truth_invariant/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/`
- `lowering_gap_truth_invariant.json`
- `lowering_gap_truth_invariant_validation_report.json`

## Operator Verification

```bash
jq empty docs/lowering_gap_truth_invariant_v1.json

rch exec -- env \
  CARGO_TARGET_DIR="$PWD/target_rch_lowering_gap_truth_invariant_verify" \
  cargo test -p frankenengine-engine --test lowering_gap_truth_invariant

./scripts/run_lowering_gap_truth_invariant.sh ci

./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci

LOWERING_GAP_TRUTH_INVARIANT_REPLAY_RUN_DIR=artifacts/lowering_gap_truth_invariant/<timestamp> \
  ./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci
```
