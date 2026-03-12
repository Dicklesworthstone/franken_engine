# RGC CI Quality Gates Contract (`bd-1lsy.11.5`)

This contract defines deterministic CI quality-gate behavior for `RGC-055`.
The gate enforces rch-backed heavy Rust verification lanes and emits
artifact-rich failure summaries for fast triage.

## Scope

This lane is implemented by:

- `scripts/run_rgc_ci_quality_gates.sh`
- `scripts/e2e/rgc_ci_quality_gates_replay.sh`
- `docs/RGC_CI_QUALITY_GATES.md`
- `crates/franken-engine/tests/fixtures/rgc_ci_quality_gates_v1.json`
- `crates/franken-engine/tests/rgc_ci_quality_gates.rs`

## Contract Version

- `schema_version`: `franken-engine.rgc-ci-quality-gates.v1`
- `gate_version`: `1.0.0`

## Lane Entry Points

The gate supports deterministic lane modes:

- `fmt`: `cargo fmt --check` (rch-backed per repo validation policy)
- `check`: `cargo check --all-targets` (rch-backed)
- `clippy`: `cargo clippy --all-targets -- -D warnings` (rch-backed)
- `unit`: `cargo test -p frankenengine-engine --lib` (rch-backed)
- `integration`: focused RGC integration tests (rch-backed)
- `e2e`:
  - `./scripts/run_rgc_test_harness_suite.sh ci`
  - `./scripts/run_rgc_verification_coverage_matrix.sh ci`
- `replay`:
  - `./scripts/e2e/rgc_test_harness_replay.sh ci`
  - `./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci`
- `regression`: regression-verdict ingestion only via `./scripts/run_rgc_ci_quality_gates.sh regression`
- `ci`: `fmt + check + clippy + unit + integration + e2e + replay + regression`

Operator-facing replay entrypoints:

- `./scripts/run_rgc_ci_quality_gates.sh ci`
- `./scripts/run_rgc_ci_quality_gates.sh regression`
- `./scripts/e2e/rgc_ci_quality_gates_replay.sh ci`
- `./scripts/e2e/rgc_ci_quality_gates_replay.sh regression`

## rch Requirement

All Cargo verification lanes in this gate run through `rch exec -- ...`.
If `rch` reports local fallback semantics, the gate fails closed.

The `fmt` lane is a special case because `cargo fmt --check` is a Cargo
subcommand that `rch` classifies as a non-compilation command. In that case the
daemon may omit the usual remote-exit marker even when the remote process exits
successfully. The gate accepts that path only when:

- the log explicitly reports `exec called with non-compilation command`
- no local-fallback signature is present in the log
- the `rch` process exit status is used as the authoritative fallback exit code

This keeps `fmt` remote-only without misclassifying a successful non-compilation
run as a provenance failure or hiding a real formatting failure behind a missing
marker artifact.

## Regression Verdict Ingestion (RGC-703 hook)

When a verdict file is provided (via `RGC_PERF_REGRESSION_VERDICT_PATH` or
`RGC_CI_QUALITY_REGRESSION_VERDICT_PATH`), the gate blocks on critical/high
regressions using deterministic policy:

- block if `blocking == true` or `is_blocking == true`
- block if `highest_severity`/`severity` is `critical` or `high`
- block if any non-waived regression entry has `severity`/`level` in
  `{critical, high}`

For strict CI enforcement, set:

- `RGC_CI_QUALITY_REQUIRE_REGRESSION_VERDICT=true`

The gate accepts either `RGC_PERF_REGRESSION_VERDICT_PATH` or
`RGC_CI_QUALITY_REGRESSION_VERDICT_PATH` for the verdict file path. Published
replay commands in `commands.txt` use the `RGC_CI_QUALITY_*` spelling so the
artifact contract stays canonical even when the legacy alias was used.

Fail-closed regression verdict error semantics:

- `FE-RGC-CI-QUALITY-GATE-0005`: strict mode enabled but no verdict path configured
- `FE-RGC-CI-QUALITY-GATE-0006`: strict mode enabled and configured verdict file is missing
- `FE-RGC-CI-QUALITY-GATE-0007`: verdict file contains blocking regression signals

## Structured Log Contract

Events include stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Failure code mapping (deterministic):

- `FE-RGC-CI-QUALITY-GATE-0000`: gate-level failure summary
- `FE-RGC-CI-QUALITY-GATE-0002`: local fallback detected (fail-closed)
- `FE-RGC-CI-QUALITY-GATE-0003`: remote command returned non-zero exit
- `FE-RGC-CI-QUALITY-GATE-0004`: local lane command failed
- `FE-RGC-CI-QUALITY-GATE-0005`: required regression verdict path missing
- `FE-RGC-CI-QUALITY-GATE-0006`: configured regression verdict file missing
- `FE-RGC-CI-QUALITY-GATE-0007`: regression verdict blocks promotion
- `FE-RGC-CI-QUALITY-GATE-0008`: remote exit marker missing (generic)
- `FE-RGC-CI-QUALITY-GATE-0009`: timeout before remote exit marker emitted
- `FE-RGC-CI-QUALITY-GATE-0010`: remote exit marker lost after remote start

## Required Artifacts

Every run emits:

- `artifacts/rgc_ci_quality_gates/<timestamp>/run_manifest.json`
- `artifacts/rgc_ci_quality_gates/<timestamp>/events.jsonl`
- `artifacts/rgc_ci_quality_gates/<timestamp>/commands.txt`
- `artifacts/rgc_ci_quality_gates/<timestamp>/failure_summary.json`

`failure_summary.json` provides machine-readable triage routing:

- failed lane
- owner hint
- failing command/detail
- replay command

For `regression` mode, `commands.txt` must contain the exact operator-facing
gate command used to replay verdict evaluation, including strict-mode and
verdict-path environment when they were part of the run contract.

## Deterministic Replay Contract

```bash
./scripts/e2e/rgc_ci_quality_gates_replay.sh ci
./scripts/e2e/rgc_ci_quality_gates_replay.sh regression
```

The replay wrapper forwards the requested mode directly to
`./scripts/run_rgc_ci_quality_gates.sh`, so `ci` and `regression` are both
first-class replay surfaces.

## Operator Verification

```bash
./scripts/run_rgc_ci_quality_gates.sh ci
./scripts/run_rgc_ci_quality_gates.sh regression
cat artifacts/rgc_ci_quality_gates/<timestamp>/run_manifest.json
cat artifacts/rgc_ci_quality_gates/<timestamp>/events.jsonl
cat artifacts/rgc_ci_quality_gates/<timestamp>/commands.txt
cat artifacts/rgc_ci_quality_gates/<timestamp>/failure_summary.json
./scripts/e2e/rgc_ci_quality_gates_replay.sh ci
./scripts/e2e/rgc_ci_quality_gates_replay.sh regression
```

## Dependency Note

`bd-1lsy.11.5` is upstream-blocked by `bd-1lsy.11.14` and `bd-1lsy.8.3`.
This gate ships prework scaffold + ingestion hooks so full fail-closed closure
can happen immediately once those dependencies land.
