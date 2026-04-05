# Parser Oracle Missing-Artifact Contract V1

Status: active
Primary bead: bd-2muur.7.1
Track id: RGC-920G.1
Machine-readable contract: `docs/parser_oracle_missing_artifact_contract_v1.json`
Implementation bead: `bd-2muur.7.2`

## Purpose

`bd-2muur.7.1` defines the typed missing-artifact receipt contract for parser
oracle runs.

Today `scripts/run_parser_oracle_gate.sh` still has a `write_placeholders()`
fallback that writes anonymous placeholder files such as `{}`,
`{"status":"not_run"}`, and zero-byte backfills when the real lane has not
produced artifacts. This contract makes that behavior explicitly unacceptable
as a steady-state truth surface: future implementation work must replace those
anonymous placeholders with a machine-readable receipt that says what did not
run, why it did not run, and how downstream consumers must react.

## Covered Artifacts

The contract covers the parser-oracle artifacts that currently receive
anonymous backfills:

- `baseline.json`
- `relation_report.json`
- `relation_events.jsonl`
- `metamorphic_evidence.jsonl`
- `drift_digest.md`

When any covered artifact is intentionally absent, the lane must emit
`parser_oracle_missing_artifact_receipt.json` instead of a content-free
placeholder.

## Explicit Missing States

The receipt contract recognizes exactly four reason IDs:

| Reason ID | Code | Stage | Consumer Action |
|---|---|---|---|
| `not_run_by_design` | `FE-PO-MISSING-0001` | `mode_selection` | `record_and_continue` |
| `skipped_by_gate_condition` | `FE-PO-MISSING-0002` | `gate_condition` | `surface_degraded` |
| `failed_before_artifact_creation` | `FE-PO-MISSING-0003` | `execution` | `fail_closed` |
| `missing_unexpected_absence` | `FE-PO-MISSING-0004` | `post_run_validation` | `fail_closed` |

Every receipt must include:

- stable correlation fields: `trace_id`, `decision_id`, `policy_id`, `component`
- the affected `artifact_path`
- a typed `artifact_role`
- `stage`
- `reason_code`
- `reason_id`
- `consumer_action`
- `missing_artifacts`
- `placeholder_rejected = true`

Unknown reasons, unknown stages, or contradictory consumer actions are invalid
contract states.

## Rejected Anonymous Backfills

The following anonymous backfills are explicitly rejected:

- `baseline.json` written as `{}`.
- `relation_report.json` written as `{"status":"not_run"}`.
- zero-byte backfills for `relation_events.jsonl`.
- zero-byte backfills for `metamorphic_evidence.jsonl`.
- zero-byte backfills for `drift_digest.md`.

This rejection is intentional even when the backfill is deterministic. A
consumer must be able to distinguish “not run by design” from “failed before
artifact creation” and from “unexpected absence” without reverse-engineering
shell behavior.

## Structured Logging and Artifact Contract

Validation and replay runs must emit structured logs with these required
fields:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `artifact_path`
- `artifact_role`
- `stage`
- `reason_code`
- `consumer_action`

Artifacts are emitted under:

`artifacts/parser_oracle_missing_artifact_contract/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/`
- `parser_oracle_missing_artifact_contract.json`
- `parser_oracle_missing_artifact_contract_validation_report.json`

## Operator Verification

```bash
jq empty docs/parser_oracle_missing_artifact_contract_v1.json

rch exec -- env \
  CARGO_TARGET_DIR="$PWD/target_rch_parser_oracle_missing_artifact_contract_verify" \
  cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_contract

./scripts/run_parser_oracle_missing_artifact_contract.sh ci

./scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh ci

PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_REPLAY_RUN_DIR=artifacts/parser_oracle_missing_artifact_contract/<timestamp> \
  ./scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh ci
```
