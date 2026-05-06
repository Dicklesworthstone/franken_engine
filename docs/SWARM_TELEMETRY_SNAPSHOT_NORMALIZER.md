# Swarm Telemetry Snapshot Normalizer

`scripts/swarm_telemetry_snapshot_normalizer.sh` consumes existing predictive
admission, archive lifecycle, and proof-economy artifacts and produces one
deterministic `swarm_capacity_snapshot.json` bundle for the SWARM-CTRL-VIII
entry surface.

The script is fixture-fed only. It does not query live `br`, Agent Mail, `rch`,
or execute Cargo.

## Inputs

Required:

- `--ready-json`
- `--in-progress-json`
- `--validation-plan-json`
- `--resource-decision-json`

Optional direct reuse surfaces:

- `--agent-mail-reservations-json`
- `--stale-lock-recommendations-json`
- `--proof-freshness-json`
- `--admission-drill-report-json`
- `--predictive-wrapper-report-json`
- `--archive-lifecycle-report-json`
- `--proof-economy-drill-report-json`

The normalizer reuses shipped artifact families instead of inventing a parallel
telemetry dialect:

- `franken-engine.swarm-validation-plan.v1`
- `franken-engine.swarm-resource-governor-decision.v1`
- `franken-engine.stale-lock-recommendations.v1`
- `franken-engine.proof-freshness-decay-report.v1`
- `franken-engine.swarm-admission-drill-report.v1`
- `franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1`
- `franken-engine.remote-proof-archive-lifecycle-no-mock-drill-report.v1`
- `franken-engine.proof-economy-scheduler-replay-drill-report.v1`

## Output

- `swarm_capacity_snapshot.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable schema version is `franken-engine.swarm-capacity-snapshot.v1`.

## Fail-Closed Rules

The normalizer exits `42` and records `decision: "fail_closed"` when it finds:

- missing required fields in the validation plan or resource decision
- stale timestamps on time-scoped coordination or report snapshots
- contradictory active-agent ownership between `in_progress` and Agent Mail
  reservation evidence
- non-replayable artifact references in supplied drill or wrapper reports

Optional missing inputs remain visible in `missing_inputs` instead of being
treated as silently healthy evidence.

## Dashboard Extension

The current predictive dashboard contract remains owned by
`docs/swarm_predictive_dashboard_contract_v1.json`. This bead extends that
contract by publishing a pre-dashboard normalized snapshot feed. The future
dashboard renderer in `/dp/frankentui` can consume the standalone
`franken-engine.swarm-capacity-snapshot.v1` surface without requiring schema
churn in the original operator-status producer.

## Validation

```bash
bash -n scripts/swarm_telemetry_snapshot_normalizer.sh
bash -n scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh
./scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh check
./scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh selftest
jq empty docs/swarm_telemetry_snapshot_contract_v1.json
```
