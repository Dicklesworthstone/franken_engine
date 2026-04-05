# Parser Oracle Gate (bd-1b70)

`bd-1b70` introduces a parser-equivalence gate that combines:

- deterministic fixture-catalog comparison against scalar-reference hashes
- parser metamorphic relations (parser-only relation subset)
- report-only and fail-closed promotion modes
- reproducibility artifact bundle output

## Entrypoints

- Gate runner: `./scripts/run_parser_oracle_gate.sh`
- Report binary: `cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- ...`
- E2E wrappers:
  - `./scripts/e2e/parser_oracle_smoke.sh`
  - `./scripts/e2e/parser_oracle_full.sh`
  - `./scripts/e2e/parser_oracle_nightly.sh`
  - `./scripts/e2e/parser_oracle_replay_failure.sh`
  - `./scripts/e2e/parser_oracle_ci_matrix.sh`
  - `./scripts/e2e/parser_oracle_flake_probe.sh`
  - shared deterministic bootstrap: `./scripts/e2e/parser_oracle_env_bootstrap.sh`

## Modes

- `report_only`: always emits report/artifacts, never blocks promotion directly.
- `fail_closed`: blocks promotion on any critical drift (`semantic`, `harness_nondeterminism`, `artifact_integrity`) and holds on minor diagnostics drift.

## Partitions

- `smoke`: first 4 sorted fixtures, 64 parser metamorphic pairs
- `full`: full fixture catalog, 256 parser metamorphic pairs
- `nightly`: full fixture catalog, 1024 parser metamorphic pairs

## Usage

```bash
# parser-oracle check path
./scripts/run_parser_oracle_gate.sh check

# parser-oracle targeted tests
./scripts/run_parser_oracle_gate.sh test

# full CI gate run (default smoke/report_only unless env overrides)
./scripts/run_parser_oracle_gate.sh ci
```

Override with environment variables:

- `PARSER_ORACLE_PARTITION` = `smoke|full|nightly`
- `PARSER_ORACLE_GATE_MODE` = `report_only|fail_closed`
- `PARSER_ORACLE_SEED` = deterministic run seed
- `PARSER_ORACLE_FIXTURE_CATALOG` = fixture catalog path
- `PARSER_ORACLE_ARTIFACT_ROOT` = artifact root directory
- `PARSER_ORACLE_REPORT_SCHEMA_VERSION` = expected relation report schema version
- `PARSER_ORACLE_TAXONOMY_VERSION` = expected drift taxonomy version
- `PARSER_ORACLE_REMEDIATION_MAP_VERSION` = remediation mapping version string
- `RUSTUP_TOOLCHAIN`, `CARGO_TARGET_DIR` as usual

All heavy cargo operations in the gate script route through `rch` when available.

## Artifact Bundle

Each run writes to `artifacts/parser_oracle/<timestamp>/`:

- `baseline.json`
- `relation_report.json`
- `relation_events.jsonl`
- `metamorphic_evidence.jsonl`
- `parser_oracle_missing_artifact_receipt.json` when one or more covered artifacts are intentionally absent or missing unexpectedly
- `minimized_failures/`
- `golden_checksums.txt`
- `proof_note.md`
- `drift_digest.md`
- `env.json`
- `repro.lock`
- `manifest.json`
- `events.jsonl`
- `commands.txt`

`baseline.json`, `relation_report.json`, `relation_events.jsonl`,
`metamorphic_evidence.jsonl`, and `drift_digest.md` are now strict truth
surfaces. The gate no longer backfills them with `{}`,
`{"status":"not_run"}`, or zero-byte placeholder files. When one or more of
those artifacts is absent, the lane emits
`parser_oracle_missing_artifact_receipt.json` with the explicit reason code,
stage, consumer action, and missing-artifact list defined in
`docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md`.

## Logging Schema Validation

Parser oracle event logs are validated against parser logging schema v1:

- schema contract: `docs/PARSER_LOGGING_SCHEMA_V1.md`
- validator: `./scripts/validate_parser_log_schema.sh --events <events.jsonl>`

`scripts/run_parser_oracle_gate.sh` runs this validator automatically and
fails closed if required fields are missing or unsafe payloads are detected.

## Drift Taxonomy

The parser-oracle report classifies each fixture result:

- `equivalent`
- `semantic_drift`
- `diagnostics_drift`
- `harness_nondeterminism`
- `artifact_integrity_failure`

Comparator decisions are normalized to:

- `equivalent`
- `drift_minor`
- `drift_critical`

`run_parser_oracle_gate.sh` enforces a schema/taxonomy compatibility contract
for `relation_report.json` and fails closed when:

- `schema_version` mismatches expected report schema
- `taxonomy_version` mismatches expected taxonomy contract

The gate also emits `drift_digest.md` with:

- ranked drift-class inventory
- deterministic drift clusters (`cluster:<family_id>`)
- owner hints and remediation mapping per cluster

## Missing-Artifact Contract

The parser-oracle gate reuses the typed missing-artifact contract from
`docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md`.

Covered artifacts are:

- `baseline.json`
- `relation_report.json`
- `relation_events.jsonl`
- `metamorphic_evidence.jsonl`
- `drift_digest.md`

If any covered artifact is absent, the gate emits
`parser_oracle_missing_artifact_receipt.json` instead of a placeholder file and
records the corresponding `reason_id`, `reason_code`, `stage`,
`consumer_action`, and `missing_artifacts` metadata in `events.jsonl`,
`proof_note.md`, `manifest.json`, and `repro.lock`.

## Replay

Every fixture result includes a deterministic replay command envelope pinned to:

- partition
- gate mode
- seed
- fixture catalog path

The replay-failure E2E script intentionally corrupts fixture-hash expectations and asserts fail-closed rejection behavior.
