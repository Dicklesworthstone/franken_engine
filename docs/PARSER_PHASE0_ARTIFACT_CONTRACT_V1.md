# Parser Phase0 Artifact Contract V1

Status: active
Primary bead: bd-2muur.6.1
Track id: RGC-920F.1
Machine-readable contract: `docs/parser_phase0_artifact_contract_v1.json`
Implementation bead: `bd-2muur.6.2`

## Purpose

`bd-2muur.6.1` defines what counts as truthful parser phase0 performance
evidence and what must happen when truthful capture is not possible.

The current `scripts/generate_parser_phase0_artifacts.sh` lane still writes a
literal placeholder SVG. This contract makes that state explicit and fail
closed: consumers must reject placeholder visuals by content, not merely by
filename, and future implementation work must replace them with either real
capture evidence or an explicit degraded-mode receipt.

## Accepted Artifact Modes

The contract recognizes exactly three performance-artifact modes:

| Mode | Primary artifact | Meaning |
|---|---|---|
| `real_flamegraph_svg` | `flamegraph.svg` | A real sampled/profile-derived flamegraph plus a receipt proving it came from a non-placeholder capture path |
| `profile_summary_only` | `profile_summary.json` | A truthful profile summary when a full flamegraph is not the chosen output, still backed by a receipt |
| `degraded_receipt_only` | `parser_phase0_performance_artifact_receipt.json` | No performance visualization is emitted; the receipt explains why capture was skipped, blocked, or unsupported |

Every accepted mode keeps the existing baseline artifact family intact:

- `baseline.json`
- `proof_note.md`
- `env.json`
- `manifest.json`
- `repro.lock`
- `provenance.json`

The performance-specific artifact must be described by
`parser_phase0_performance_artifact_receipt.json`, and consumers must fail
closed when that receipt is missing or contradictory.

## Rejected Placeholder Content

Placeholder visuals are invalid even if they are well-formed SVGs and even if
they hash deterministically.

Consumers must reject any performance artifact whose content matches one of the
contract’s forbidden placeholder signatures, including the current generator’s
placeholder strings:

- `parser phase0 flamegraph placeholder`
- `parser_phase0 scalar_reference baseline lane (placeholder flamegraph artifact)`
- `<rect x="40" y="72" width="1200" height="24" fill="#22c55e" />`

This rule is intentionally content-based so a renamed placeholder file does not
slip through validation.

## Degraded-Mode Receipts

When truthful capture cannot happen, the generator must emit
`parser_phase0_performance_artifact_receipt.json` with:

- stable correlation fields: `trace_id`, `decision_id`, `policy_id`, `component`
- `mode = degraded_receipt`
- a typed `reason_code`
- a stable `stage`
- an explicit `consumer_action`
- `placeholder_rejected = true`

Allowed degraded reason IDs are:

- `profiler_unavailable`
- `capture_disabled_by_policy`
- `platform_unsupported`
- `permission_denied`
- `preflight_failed`
- `upstream_command_failed`

Unknown degraded reasons are invalid contract states.

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
- `artifact_mode`
- `receipt_reason_code`

Artifacts are emitted under:

`artifacts/parser_phase0_artifact_contract/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/`
- `parser_phase0_artifact_contract.json`
- `parser_phase0_artifact_contract_validation_report.json`

## Operator Verification

```bash
jq empty docs/parser_phase0_artifact_contract_v1.json

rch exec -- env \
  CARGO_TARGET_DIR="$PWD/target_rch_parser_phase0_artifact_contract_verify" \
  cargo test -p frankenengine-engine --test parser_phase0_artifact_contract

./scripts/run_parser_phase0_artifact_contract.sh ci

./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci

PARSER_PHASE0_ARTIFACT_CONTRACT_REPLAY_RUN_DIR=artifacts/parser_phase0_artifact_contract/<timestamp> \
  ./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci
```
