# Runtime Diagnostics and Evidence Export CLI (`bd-2mm`)

Deterministic diagnostics and evidence export surface for Section 10.8 item 1.

## Binary

```bash
cargo run -p frankenengine-engine --bin runtime_diagnostics -- help
```

Unified user-facing wrapper:

```bash
frankenctl doctor --input artifacts/runtime_input.json --summary
```

`frankenctl doctor` composes the existing diagnostics preflight, onboarding
scorecard, and rollout-decision surfaces into one deterministic migration
readiness workflow. It accepts the same workload input JSON plus optional
signal/advisory inputs, and can inline compatibility advisories directly from a
scenario report via `--scenario-report <path>`.

Subcommands:

- `diagnostics`: emit runtime-state diagnostics
- `export-evidence`: export evidence bundle with deterministic filtering/sorting
- `doctor`: produce fail-closed preflight readiness report + support bundle pointers
- `compatibility-advisories`: synthesize deterministic compatibility advisory rows/signals from module-compatibility scenario reports
- `onboarding-scorecard`: derive deterministic onboarding readiness scorecard
- `rollout-decision-artifact`: consolidate onboarding/advisory/platform evidence into explicit rollout recommendation (`promote|canary_hold|rollback|defer`)

## Input Contract

The binary reads a deterministic JSON input file matching
`RuntimeDiagnosticsCliInput` from `crates/franken-engine/src/runtime_diagnostics_cli.rs`.

Input includes:

- runtime state snapshot:
  - loaded extensions + containment state
  - active policy IDs
  - security epoch
  - GC pressure samples
  - scheduler lane samples
- evidence sources:
  - decision receipts (evidence ledger entries)
  - hostcall telemetry envelopes
  - containment receipt envelopes
  - replay artifact pointers

## Commands

Diagnostics JSON output:

```bash
runtime_diagnostics diagnostics --input artifacts/runtime_input.json
```

Diagnostics human summary:

```bash
runtime_diagnostics diagnostics --input artifacts/runtime_input.json --summary
```

Evidence export JSON output:

```bash
runtime_diagnostics export-evidence --input artifacts/runtime_input.json
```

Evidence export with filters:

```bash
runtime_diagnostics export-evidence \
  --input artifacts/runtime_input.json \
  --extension-id ext-a \
  --trace-id trace-incident \
  --start-ns 1100 \
  --end-ns 1200 \
  --severity warning \
  --decision-type security_action
```

Evidence export summary mode:

```bash
runtime_diagnostics export-evidence --input artifacts/runtime_input.json --summary
```

Onboarding scorecard:

```bash
runtime_diagnostics onboarding-scorecard \
  --input artifacts/runtime_input.json \
  --signals artifacts/onboarding_signals.json \
  --summary
```

Compatibility advisories from module-compatibility scenario report:

```bash
runtime_diagnostics compatibility-advisories \
  --scenario-report artifacts/module_compat/scenario_report.json \
  --source-report artifacts/module_compat/scenario_report.json \
  --out artifacts/module_compat/compatibility_advisories.json \
  --summary
```

Rollout decision artifact:

```bash
runtime_diagnostics rollout-decision-artifact \
  --input artifacts/runtime_input.json \
  --signals artifacts/onboarding_signals.json \
  --advisories artifacts/compat_advisories.json \
  --platform-signals artifacts/platform_matrix_signals.json \
  --summary
```

Equivalent single-command workflow through `frankenctl`:

```bash
frankenctl doctor \
  --input artifacts/runtime_input.json \
  --workload-id demo-workload \
  --package-name demo-package \
  --target-platform linux-x86_64 \
  --scenario-report artifacts/module_compat/scenario_report.json \
  --platform-signals artifacts/platform_matrix_signals.json \
  --out-dir artifacts/doctor \
  --summary
```

This command emits a top-level doctor report plus:

- `support_bundle/preflight_report.json`
- `support_bundle/onboarding_scorecard.json`
- `support_bundle/rollout_decision_artifact.json`
- `support_bundle/rollout_decision_packet.json`
- `support_bundle/rollout_decision_summary.md`
- `support_bundle/platform_risk_matrix.json`
- `support_bundle/frankenctl_doctor_report.json`

`--signals`, `--advisories`, and `--platform-signals` accept either:
- JSON array of `OnboardingScorecardSignal`
- Compatibility-advisory bundle JSON emitted by `compatibility-advisories` (the embedded `signals` are consumed)

## Determinism Rules

- Stable output ordering:
  - diagnostics tables sorted by deterministic keys
  - evidence records sorted by `(timestamp_ns, kind, trace_id, decision_id, extension_id)`
- Filters are pure and deterministic for identical inputs.
- Re-running the same command over the same input yields byte-identical JSON output.

## Structured Log Fields

Both diagnostics and export emit log events with required stable fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Suite Runner

```bash
./scripts/run_runtime_diagnostics_suite.sh ci
```

Replay wrapper:

```bash
./scripts/e2e/runtime_diagnostics_suite_replay.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci`

Runner is `rch`-gated for heavy Rust commands and fails closed if remote
execution falls back to local.

Timeout policy is also fail-closed:

- requested wrapper timeout: `RCH_EXEC_TIMEOUT_SECONDS` (default `900`)
- requested remote build timeout: `RCH_BUILD_TIMEOUT_SEC` / `RCH_BUILD_TIMEOUT_SECONDS`
  (default matches `RCH_EXEC_TIMEOUT_SECONDS`)
- if the rch wrapper reports a lower internal `timeout_secs` than requested, the
  suite exits with `FE-RUNTIME-DIAGNOSTICS-TIMEOUT-0001` and records policy-drift
  evidence in `run_manifest.json`.

In `test` and `ci`, the suite also runs a fixture-backed advisory generation
step using:

- `crates/franken-engine/tests/fixtures/runtime_compatibility_scenario_report_v1.json`

## Reproducibility Artifacts

Each run writes:

- `artifacts/runtime_diagnostics/<timestamp>/commands.txt`
- `artifacts/runtime_diagnostics/<timestamp>/events.jsonl`
- `artifacts/runtime_diagnostics/<timestamp>/compatibility_advisories.json` (test/ci modes)
- `artifacts/runtime_diagnostics/<timestamp>/run_manifest.json`

`run_manifest.json` includes operator verification commands.

It also captures rch timeout-policy evidence fields:

- `rch_exec_timeout_seconds`
- `rch_build_timeout_sec`
- `rch_observed_timeout_seconds` (present when rch emits wrapped timeout metadata)
- `rch_timeout_policy_drift_detected`
- `failure_code_mapping.timeout_policy_drift = FE-RUNTIME-DIAGNOSTICS-TIMEOUT-0001`
