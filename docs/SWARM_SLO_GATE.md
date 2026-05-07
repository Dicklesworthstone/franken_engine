# Swarm SLO Gate

`scripts/swarm_slo_gate.sh` is the fail-closed operator gate for brownout and proof-fanout control during multi-agent swarm runs. It consumes preserved JSON outputs from the admission planner, RCH rehabilitation ledger, proof-cache locality optimizer, and saturation replay drill, then emits a deterministic SLO report without touching live queues or workers.

Machine-readable contract: `docs/swarm_slo_gate_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_slo_gate_smoke.sh`

Fixture cases: `scripts/testdata/swarm_slo_gate/cases.json`

## Inputs

The gate requires five input files:

- `--slo-input-json`: SLO thresholds plus tracker age and unknown dirty-file pressure.
- `--admission-budget-plan-json`: admission planner bundle.
- `--rch-rehabilitation-ledger-json`: worker pressure and latest progress ledger.
- `--proof-cache-locality-plan-json`: proof-cache pressure plan.
- `--saturation-replay-report-json`: saturation replay report and fanout observations.

All inputs are fixture-fed or preserved artifacts. The gate does not query Agent Mail, inspect live workers, run RCH, or mutate beads. It does not execute build commands.

## SLOs

The report evaluates these six SLOs:

- `max_admitted_heavy_lanes`: caps admitted heavy lanes before proof fanout can saturate remote capacity.
- `minimum_free_rch_slots`: preserves slack for urgent validation work.
- `maximum_stale_progress_seconds`: fails or warns when worker progress telemetry is too old.
- `maximum_stale_tracker_age_seconds`: fails or warns when the bead/tracker snapshot is stale.
- `maximum_unknown_dirty_files`: fails when dirty worktree paths have not been classified or reserved.
- `maximum_proof_cache_pressure`: fails or warns when proof-cache pressure is above the configured rank.

The max admitted heavy lanes SLO is the primary brownout guard for proof fanout.

The gate returns `pass`, `warn`, or `fail_closed`. Any missing upstream bundle, malformed schema, incomplete worker pressure telemetry, local fallback contamination, or upstream `fail_closed` decision forces `fail_closed` even when the numeric SLOs are otherwise green.

## Outputs

Each run writes these artifacts under the output directory:

- `slo_gate_report.json`: SLO verdicts, observed values, fail-closed reasons, remediation commands, and evidence paths.
- `run_manifest.json`: source revision, gate id, artifact paths, and mutation policy.
- `events.jsonl`: input-load and report-emission events.
- `commands.txt`: the exact invocation used for the run.

Every fail verdict in `slo_gate_report.json` must include an `error_code`, a non-empty `remediation_command`, and a non-empty `evidence_path`. The report hash intentionally excludes artifact path fields and input path locations so repeated fixture runs produce a stable hash.

## Operator Use

Run a preserved-artifact gate:

```bash
./scripts/swarm_slo_gate.sh \
  --slo-input-json artifact/slo_input.json \
  --admission-budget-plan-json artifact/admission_budget_plan.json \
  --rch-rehabilitation-ledger-json artifact/rch_rehabilitation_ledger.json \
  --proof-cache-locality-plan-json artifact/proof_cache_locality_plan.json \
  --saturation-replay-report-json artifact/saturation_replay_report.json \
  --output-dir artifact/slo_gate
```

The gate is advisory-only. It prints output artifact paths and exits `0` for `pass` or `warn`; it exits `42` for `fail_closed`.

## Fixture Coverage

The smoke suite covers:

- `green`: all SLOs pass.
- `warning`: heavy-lane cap, stale progress, stale tracker, and proof-cache pressure warn without closing the gate.
- `brownout_fail`: excessive heavy fanout and insufficient free RCH slots fail closed.
- `stale_tracker_fail`: stale tracker age and unknown dirty files fail closed.
- `local_fallback_contamination`: local fallback evidence fails closed even if numeric SLOs are green.

Use the smoke gate for contract validation:

```bash
bash scripts/e2e/swarm_slo_gate_smoke.sh check
bash scripts/e2e/swarm_slo_gate_smoke.sh selftest
```
