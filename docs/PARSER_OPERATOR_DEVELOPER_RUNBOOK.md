# Parser Operator/Developer Runbook (`bd-2mds.1.10.4`)

This runbook provides replay-first troubleshooting workflows for parser lanes so
fresh operators and developers can diagnose failures without insider context.

## Scope

This runbook is the operational contract for `PSRP-10.4` and ties together:

- deterministic parser environment controls (`docs/PARSER_FRONTIER_ENV_CONTRACT.md`)
- diagnostics quality checks (`docs/PARSER_DIAGNOSTICS_QUALITY_RUBRIC.md`)
- recovery/resync adversarial drills (`docs/PARSER_ERROR_RECOVERY_RESYNC_ADVERSARIAL_E2E.md`)
- API compatibility checks (`docs/PARSER_API_COMPATIBILITY_CONTRACT.md`)
- user-impact guardrails (`docs/PARSER_USER_IMPACT_REGRESSION_ALARMS_SLO_GUARDRAILS.md`)

Implementation surfaces:

- `scripts/run_parser_operator_developer_runbook.sh`
- `scripts/e2e/parser_operator_developer_runbook_replay.sh`
- `crates/franken-engine/tests/parser_operator_developer_runbook.rs`
- `crates/franken-engine/tests/fixtures/parser_operator_developer_runbook_v1.json`

## Deterministic Environment And Log Contract

All runbook drills must source `scripts/e2e/parser_deterministic_env.sh` and
publish parser-log-schema-compatible events with stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Required policy ID:

- `policy-parser-operator-developer-runbook-v1`

All heavy Rust checks and tests for this lane run through `rch`.

The runbook wrapper defaults remote builds into a repo-local namespaced target
directory (`target_rch_parser_operator_developer_runbook_<mode>_<pid>`) so
fresh-operator drills do not depend on fragile `/tmp` worker state.

## Fresh-Operator Dry Run

Run from repository root:

```bash
./scripts/run_parser_operator_developer_runbook.sh ci
```

Expected artifacts:

- `artifacts/parser_operator_developer_runbook/<timestamp>/run_manifest.json`
- `artifacts/parser_operator_developer_runbook/<timestamp>/events.jsonl`
- `artifacts/parser_operator_developer_runbook/<timestamp>/commands.txt`
- `artifacts/parser_operator_developer_runbook/<timestamp>/step_logs/step_*.log`

## Replay-First Troubleshooting Decision Tree

1. **Symptom: diagnostics drift / unstable parser error quality**
   - Primary drill:
     - `./scripts/run_parser_diagnostics_quality_rubric.sh ci`
2. **Symptom: malformed-input recovery or resync regressions**
   - Primary drill:
     - `./scripts/e2e/parser_error_recovery_adversarial_replay.sh`
3. **Symptom: parser API or integration compatibility regressions**
   - Primary drill:
     - `./scripts/run_parser_api_compatibility_gate.sh ci`
4. **Symptom: user-impact SLO alarm or rollout quality hold**
   - Primary drill:
     - `./scripts/e2e/parser_user_impact_regression_alarms_replay.sh`
5. **Symptom: failover/fallback ambiguity under pressure**
   - Primary drill:
     - `./scripts/run_parser_failover_controls_gate.sh ci`
6. **Symptom: `rch` artifact retrieval failure / transfer corruption**
   - Primary drill:
     - `./scripts/run_parser_operator_developer_runbook.sh check`
   - Fail-closed signatures (treat as gate failure, not soft pass):
     - `Artifact retrieval failed`
     - `Failed to retrieve artifacts:`
     - `rsync artifact retrieval failed`
     - `rsync error: ... code 23`
   - Remediation:
     - inspect worker health with `rch status --jobs --workers`
     - rerun only after remote artifact transport is healthy

## Scriptable Drill Lane

Runbook drill mode (test contract + replay-path check):

```bash
./scripts/run_parser_operator_developer_runbook.sh drill
```

One-command replay wrapper:

```bash
./scripts/e2e/parser_operator_developer_runbook_replay.sh drill
```

## Escalation And Rollback Posture

- If diagnostics, recovery, or compatibility drills fail, treat parser promotion
  readiness as **blocked** until replay confirms root cause and corrective patch.
- If user-impact alarm drills fail critical thresholds, set rollout posture to
  **hold** and require a documented remediation/replay pass before re-enabling.
- If failover controls show non-deterministic behavior, enforce fail-closed
  safe-mode posture and do not advance readiness gates.
- If `rch` reports artifact retrieval failure signatures, treat the run as
  hard-fail and rerun only after remote artifact transport health is restored.

## Operator Verification Checklist

```bash
./scripts/run_parser_operator_developer_runbook.sh ci
cat artifacts/parser_operator_developer_runbook/<timestamp>/run_manifest.json
cat artifacts/parser_operator_developer_runbook/<timestamp>/events.jsonl
cat artifacts/parser_operator_developer_runbook/<timestamp>/commands.txt
cat artifacts/parser_operator_developer_runbook/<timestamp>/step_logs/step_000.log
./scripts/e2e/parser_operator_developer_runbook_replay.sh ci
```
