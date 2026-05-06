# SWARM Operator SLO Tuning Advisory

`scripts/swarm_operator_slo_tuning_advisory.sh` composes the reviewed
SWARM-CTRL-IX threshold receipt, capacity forecast, chaos conformance report,
admission budget plan, lease-exchange / salvage simulation, and warm-target ROI
advisory into a bounded operator-only tuning handoff.

It is report-only. It does not mutate queue state, lease state, archive
residency, or worker assignment.

## Inputs

Required:

- `--threshold-receipt-json`
- `--capacity-forecast-json`
- `--admission-budget-plan-json`
- `--lease-exchange-salvage-simulation-json`
- `--warm-target-prefetch-roi-advisory-json`
- `--chaos-conformance-report-json`

Compatible reviewed inputs:

- `franken-engine.swarm-slo-threshold-receipt.v1`
- `franken-engine.swarm-capacity-forecast.v1`
- `franken-engine.swarm-admission-budget-plan.v1`
- `franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1`
- `franken-engine.swarm-warm-target-prefetch-roi-advisory.v1`
- `franken-engine.swarm-high-core-chaos-conformance-report.v1`

## Output

- `swarm_operator_slo_tuning_advisory.json`
- `report.md`
- `commands.txt`
- `events.jsonl`

The report schema is `franken-engine.swarm-operator-slo-tuning-advisory.v1`.

## Advisory Requirements

The advisory must:

- summarize evidence quality, calibrated thresholds, confidence, and reviewed
  claim support
- recommend when to admit, narrow, defer, prewarm, archive, salvage, or require
  human coordination
- distinguish advisory thresholds from live control knobs
- hand off a future dashboard section path
  `predictive_dashboard.slo_tuning_advisory`
- keep any future rich renderer explicitly `/dp/frankentui`-owned

## Fail-Closed Rules

The advisory exits `42` when it finds:

- unsupported SLO claims in the threshold receipt or chaos conformance report
- missing evidence links for reviewed child artifacts
- stale forecast references
- an already fail-closed threshold receipt
- an already fail-closed chaos conformance report

The smoke truth gate must also reject duplicate UI-stack claims, including any
documentation drift that implies a shipped local TUI or a second predictive
dashboard producer in `franken_engine`.

## Truth Constraints

- `scripts/swarm_operator_status_report.sh` remains the only predictive
  dashboard producer in `franken_engine`.
- This advisory is a future dashboard handoff only. It is not a second
  dashboard implementation.
- Any future rich dashboard for this advisory must reuse `/dp/frankentui`.
- Advisory sections must preserve deterministic evidence links back to each
  reviewed child artifact.

## Validation

```bash
bash -n scripts/swarm_operator_slo_tuning_advisory.sh
bash -n scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh
shellcheck -x scripts/swarm_operator_slo_tuning_advisory.sh scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh
./scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh check
./scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh selftest
jq empty docs/swarm_operator_slo_tuning_advisory_contract_v1.json
```

