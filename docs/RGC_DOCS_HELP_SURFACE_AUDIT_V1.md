# RGC Docs and Help Surface Audit V1

Status: active  
Primary bead: `bd-1lsy.10.11.1`  
Machine-readable contract: `docs/rgc_docs_help_surface_audit_v1.json`

## Scope

This audit keeps `README.md` and the shipped `frankenctl --help` surface aligned
with the commands that actually parse and run today.

It intentionally narrows aspirational operator copy to the currently shipped
CLI: `version`, `compile`, `run`, `doctor`, `verify`, `benchmark`, and
`replay`.

## Contract Version

- `schema_version`: `franken-engine.rgc-docs-help-surface-audit.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-docs-help-surface-audit-v1`

## Authoritative CLI Surface

- `frankenctl version`
- `frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]`
- `frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]`
- `frankenctl doctor --input <runtime_input.json> [--summary] [--out-dir <path>]`
- `frankenctl verify compile-artifact --input <artifact.json>`
- `frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary]`
- `frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>] [--profile <name>]... [--family <name>]... [--out-dir <path>]`
- `frankenctl benchmark score --input <publication_gate_input.json> [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <results.json>]`
- `frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]`
- `frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]`

## Audited Claim Classes

- `readme-quick-example`: narrowed from aspirational workspace/promotion flow to
  shipped compile/verify/run commands
- `readme-quick-start`: narrowed from unshipped init/control-plane surfaces to
  shipped compile/run/doctor/verify/benchmark/replay workflows
- `readme-command-reference`: narrowed to the exact top-level commands exposed
  by `frankenctl --help`
- `readme-troubleshooting`: narrowed from non-existent subcommands to supported
  `doctor`, `verify`, `benchmark`, and `replay` remediation flows
- `frankenctl-top-level-help`: accurate and treated as the authoritative command
  source of truth

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_docs_help_surface_audit.sh`

Replay wrapper:

- `scripts/e2e/rgc_docs_help_surface_audit_replay.sh`

Supported modes:

- `check`, `test`, `clippy`, `ci`

Heavy cargo operations are remote-only (`rch`) and fail closed on local
fallback detection.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `docs_help_surface_report.json`
- `frankenctl_help.txt`
- `step_logs/step_*.log`

under `artifacts/rgc_docs_help_surface_audit/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_docs_help_surface_audit_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_docs_help_surface_audit \
  cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit

./scripts/run_rgc_docs_help_surface_audit.sh ci
./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ci
```
