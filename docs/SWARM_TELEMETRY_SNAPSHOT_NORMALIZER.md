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
- `--stress-suite-manifest-json`
- `--tail-latency-report-json`
- `--chaos-verification-report-json`
- `--swarm-responsiveness-claim-map-json`

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
- `franken-engine.stress-concurrency.suite-manifest.v1`
- `franken-engine.tail-latency-control-plane.v1`
- `franken-engine.rgc-fault-injection-chaos-verification-pack.report.v1`
- `franken-engine.swarm-responsiveness-claim-map.v1`

## Output

- `swarm_capacity_snapshot.json`
- `swarm_slo_input_snapshot.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable schema version is `franken-engine.swarm-capacity-snapshot.v1`.
When the SWARM-CTRL-IX high-core evidence inputs are supplied, the same run also
emits `franken-engine.swarm-slo-input-snapshot.v1` in
`swarm_slo_input_snapshot.json`.

## Fail-Closed Rules

The normalizer exits `42` and records `decision: "fail_closed"` when it finds:

- missing required fields in the validation plan or resource decision
- stale timestamps on time-scoped coordination or report snapshots
- contradictory active-agent ownership between `in_progress` and Agent Mail
  reservation evidence
- non-replayable artifact references in supplied drill or wrapper reports
- high-core stress, tail-latency, chaos, or responsiveness evidence that is
  stale or not traceable to `rch`-backed commands when those inputs are
  requested

Optional missing inputs remain visible in `missing_inputs` instead of being
treated as silently healthy evidence. The high-core SLO extension is stricter:
once any SWARM-CTRL-IX input is requested, the normalizer requires all four of
those high-core evidence inputs and fail-closes their dedicated SLO snapshot if
any one is missing, stale, or locally executed.

## Dashboard Extension

The current predictive dashboard contract remains owned by
`docs/swarm_predictive_dashboard_contract_v1.json`. This bead extends that
contract by publishing a pre-dashboard normalized snapshot feed. The future
dashboard renderer in `/dp/frankentui` can consume the standalone
`franken-engine.swarm-capacity-snapshot.v1` surface without requiring schema
churn in the original operator-status producer.

For SWARM-CTRL-IX, the same normalizer now also emits a dedicated
`franken-engine.swarm-slo-input-snapshot.v1` surface that carries normalized
high-core stress, tail-latency, chaos, and responsiveness claim-map evidence
for downstream scenario-matrix and SLO-calibration lanes.

## Validation

```bash
bash -n scripts/swarm_telemetry_snapshot_normalizer.sh
bash -n scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh
./scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh check
./scripts/e2e/swarm_telemetry_snapshot_normalizer_smoke.sh selftest
jq empty docs/swarm_telemetry_snapshot_contract_v1.json
```
