# Proof Economy Operator What-If Report

`scripts/proof_economy_operator_what_if_report.sh` publishes a stable
operator-facing report over proof-economy scheduler replay artifacts.
It emits `franken-engine.proof-economy-operator-what-if-report.v1`.

The report is JSON and Markdown only. Any future interactive dashboard or TUI
must reuse `/dp/frankentui`; this repo must not grow a parallel local TUI
surface.

## Usage

```bash
./scripts/proof_economy_operator_what_if_report.sh \
  --replay-trace-json /tmp/proof-economy/replay_trace.normalized.json \
  --counterfactual-report-json /tmp/proof-economy-counterfactual/counterfactual_replay_report.json \
  --brownout-report-json /tmp/proof-queue-brownout/brownout_report.json \
  --output-dir /tmp/proof-economy-what-if
```

## Artifacts

Each run emits:

- `what_if_report.json`
- `dashboard_contract.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`what_if_report.json` includes changed-decision evidence links back to the
policy matrix, trace command rows, counterfactual policy id, and brownout
findings.

`dashboard_contract.json` inventories the future UI fields:

- `queue_depth`
- `fair_share_score_millionths`
- `p1_slo_risk`
- `brownout_state`
- `recommended_operator_action`

Missing counterfactual or brownout artifacts fail closed with actionable
diagnostics in `findings[]`.

## Validation

```bash
bash -n scripts/proof_economy_operator_what_if_report.sh
bash -n scripts/e2e/proof_economy_operator_what_if_report_smoke.sh
bash scripts/e2e/proof_economy_operator_what_if_report_smoke.sh check
bash scripts/e2e/proof_economy_operator_what_if_report_smoke.sh selftest
```
