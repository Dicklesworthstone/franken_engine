# Swarm Validation Control Plane Operator Runbook

**Status:** Active
**Bead:** bd-1npwf
**Predictive orchestration follow-up:** bd-1y2bu
**Policy ID:** policy-swarm-validation-control-plane-v1

## Scope

This runbook is the fresh-operator workflow for the swarm validation control
plane. It covers bead selection, file ownership, validation planning, resource
admission, proof execution, artifact inspection, and status publication.
The SWARM-CTRL-II extension adds predictive proof-cost, collision-risk,
proof-freshness, and rch-incident evidence to that same workflow so operators
can see why a run was admitted, narrowed, deferred, or failed closed.

Implementation surfaces:

- `docs/swarm_validation_control_plane_contract_v1.json`
- `docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md`
- `docs/swarm_predictive_dashboard_contract_v1.json`
- `scripts/e2e/swarm_validation_control_plane_contract_smoke.sh`
- `scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh`
- `scripts/e2e/swarm_validation_control_plane_e2e.sh`
- `scripts/e2e/swarm_operator_status_report_smoke.sh`
- `scripts/e2e/swarm_predictive_orchestration_e2e.sh`
- `scripts/proof_freshness_decay_gate.sh`
- `scripts/rch_incident_packet_gate.sh`
- `scripts/swarm_validation_planner.sh`
- `scripts/swarm_resource_governor.sh`
- `scripts/swarm_operator_status_report.sh`

The control plane fails closed when it cannot prove ownership, resource health,
remote execution routing, or artifact freshness. Heavy Rust validation uses
`rch exec -- env` with an explicit `CARGO_TARGET_DIR=...`.

## Fresh Operator Workflow

1. Inspect the candidate work queue and current ownership:

```bash
br ready --json --no-auto-import --no-auto-flush
br list --status=in_progress --json --no-auto-import --no-auto-flush
bv --recipe actionable --robot-plan
git status --short
```

2. Capture coordination snapshots before editing:

```bash
file_reservation_paths(project=/data/projects/franken_engine, paths=planned_write_set, exclusive=true)
fetch_inbox(project=/data/projects/franken_engine)
br list --status=in_progress --json --no-auto-import --no-auto-flush > /tmp/swarm-in-progress.json
```

Persist the Agent Mail reservation response to `/tmp/swarm-reservations.json`
before invoking the planner so the collision receipt uses explicit snapshot
evidence instead of live service calls.

If Agent Mail is missing or degraded, continue only when the bead assignee and
dirty-path evidence show no overlap. Record the degraded coordination state in
the final status update.

3. Ask the planner for the narrow validation command set and collision receipt:

```bash
./scripts/swarm_validation_planner.sh --bead-id bd-1onpa --source-revision smoke-rev --output-dir /tmp/franken-engine-swarm-validation-plan --changed-path scripts/swarm_validation_planner.sh --planned-write-path scripts/swarm_validation_planner.sh --reservation-snapshot-json /tmp/swarm-reservations.json --in-progress-json /tmp/swarm-in-progress.json
cat /tmp/franken-engine-swarm-validation-plan/plan.json
cat /tmp/franken-engine-swarm-validation-plan/commands.txt
cat /tmp/franken-engine-swarm-validation-plan/collision_receipt.json
```

Unknown path mappings are fail-closed. Do not replace them with broad
`cargo check --all-targets`; either add a precise mapping or choose a different
bead.

Before reserving files, inspect the planner receipt fields:

- `collision_risk`
- `conflicting_agents`
- `safe_alternatives`
- `reservation_recommendations`

Reserved-file overlap is fail-closed. Missing Agent Mail snapshots or dirty
overlap evidence must stay visibly degraded until the operator captures fresh
reservation data or narrows the write set to a safe alternative.

4. For predictive orchestration work, keep the planner, freshness, incident,
and status evidence connected by explicit artifact paths:

```bash
./scripts/e2e/swarm_predictive_orchestration_e2e.sh check
./scripts/e2e/swarm_predictive_orchestration_e2e.sh selftest
cat /tmp/franken-engine-swarm-predictive-orchestration/<run-id>/wrapper/report.json
```

The predictive drill is shell and JSON only. It must not execute Cargo. It
proves that the validation planner can emit high-cost and collision-risk
signals, that `scripts/proof_freshness_decay_gate.sh` rejects stale proof
artifacts, that `scripts/rch_incident_packet_gate.sh` classifies remote proof
failures, and that `scripts/swarm_operator_status_report.sh` publishes those
signals in `franken-engine.swarm-predictive-dashboard.v1`.

5. Run the resource governor before any heavy proof:

```bash
./scripts/swarm_resource_governor.sh --bead-id bd-zmuv5 --output-dir /tmp/franken-engine-swarm-resource-decision --active-compile-count 0 --disk-available-bytes 2147483648 --target-dir /tmp/rch_target_franken_engine_bd_zmuv5 --target-dir-writable true --memory-available-bytes 2147483648 --rch-present true --rch-status ok --rch-fallback-detected false --command-exit-code none --command-failure-kind none --ownership-state none --dirty-state clean
cat /tmp/franken-engine-swarm-resource-decision/decision.json
```

If the decision is `defer` or `fail_closed`, do not start a heavy proof. Follow
the remediation in the decision artifact and publish the blocker.

6. Execute only admitted proof commands. Shell and docs gates can run directly:

```bash
./scripts/e2e/swarm_validation_control_plane_contract_smoke.sh check
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check
./scripts/e2e/swarm_validation_control_plane_e2e.sh check
./scripts/e2e/proof_freshness_decay_gate_smoke.sh check
./scripts/e2e/rch_incident_packet_gate_smoke.sh check
./scripts/e2e/swarm_operator_status_report_smoke.sh check
```

Heavy Rust proof commands must keep this shape:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_validation PROOF_ARTIFACT_SOURCE_REVISION=smoke-rev cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture
```

7. Inspect proof artifacts before reporting success:

```bash
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/commands.txt
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/events.jsonl
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/report.json
```

If the newest artifact bundle is stale, incomplete, or from another source
revision, mark the proof stale and refresh it before relying on it.

8. Publish operator status from explicit snapshots:

```bash
./scripts/swarm_operator_status_report.sh --output-dir /tmp/franken-engine-swarm-operator-status --source-revision smoke-rev --agent-mail-status ok --rch-status ok --proof-index-status ok --validation-plan-json /tmp/franken-engine-swarm-validation-plan/plan.json --collision-receipt-json /tmp/franken-engine-swarm-validation-plan/collision_receipt.json --proof-freshness-json /tmp/franken-engine-proof-freshness/proof_freshness_report.json --rch-incident-packet-json /tmp/franken-engine-rch-incident/incident_packet.json --resource-lease-plan-json /tmp/franken-engine-swarm-resource-lease/resource_lease_plan.json --proof-cache-plan-json /tmp/franken-engine-proof-reuse-cache/proof_cache_plan.json --qos-batch-plan-json /tmp/franken-engine-build-storm-qos/build_storm_batch_plan.json --stale-lock-recommendations-json /tmp/franken-engine-stale-lock/stale_lock_recommendations.json --staged-ownership-report-json /tmp/franken-engine-staged-ownership/staged_ownership_report.json
cat /tmp/franken-engine-swarm-operator-status/status.json
cat /tmp/franken-engine-swarm-operator-status/report.md
```

The predictive dashboard contract is a JSON feed contract only:

- Schema: `franken-engine.swarm-predictive-dashboard.v1`
- Contract: `docs/swarm_predictive_dashboard_contract_v1.json`
- Human-readable contract: `docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md`

The status feed composes the older predictive dashboard sections with the
SWARM-CTRL-III admission-control artifacts: resource leases, proof-cache reuse,
QoS batches, stale-lock recommendations, and staged-ownership contamination.
Missing admission artifacts are reported as degraded `artifact_status:
"missing"` sections so operators can distinguish incomplete evidence from
healthy idle state.

FrankenEngine does not ship a local interactive dashboard for this feed. The
future rich rendering implementation belongs in `/dp/frankentui`; until that
implementation exists, treat the JSON and Markdown reports as the shipped
operator surface.

## SWARM-CTRL-II Closeout Evidence

`bd-uhzkf` closes when every predictive orchestration claim maps to shipped
repo artifacts and executable checks:

| Epic claim | Shipped evidence |
| --- | --- |
| Predictive validation plans show likely cost, target selection, artifact freshness, and collision risk before heavy commands run. | `scripts/swarm_validation_planner.sh`, `scripts/e2e/swarm_validation_planner_smoke.sh`, `scripts/proof_freshness_decay_gate.sh`, and `scripts/e2e/proof_freshness_decay_gate_smoke.sh` publish predicted-cost, recommended target-dir, collision, and reusable-proof decisions from explicit snapshots. |
| `rch` fallback and worker-pressure failures produce compact incident packets instead of ambiguous logs. | `scripts/rch_incident_packet_gate.sh` and `scripts/e2e/rch_incident_packet_gate_smoke.sh` classify local fallback, worker timeout, SIGKILL, artifact retrieval failure, missing completion markers, and unknown remote failures into `franken-engine.rch-incident-packet.v1`. |
| Proof artifacts are indexed with freshness and decay status tied to source revisions and changed paths. | `scripts/proof_freshness_decay_gate.sh`, `scripts/proof_reuse_cache_planner.sh`, `scripts/e2e/proof_reuse_cache_planner_smoke.sh`, and the proof-cost history inputs consumed by the validation planner keep stale, superseded, incomplete, mismatched, and source-revision-drift evidence fail-closed. |
| The operator status feed can power a future frankentui dashboard without schema churn. | `scripts/swarm_operator_status_report.sh`, `scripts/e2e/swarm_operator_status_report_smoke.sh`, `docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md`, and `docs/swarm_predictive_dashboard_contract_v1.json` publish `franken-engine.swarm-predictive-dashboard.v1`, including resource lease, proof cache, QoS batch, stale-lock, and staged-contamination sections, while keeping local interactive rendering non-shipped and `/dp/frankentui`-owned. |
| The composed workflow has a no-mock drill, stable logs, deterministic artifacts, and docs truth coverage. | `scripts/e2e/swarm_predictive_orchestration_e2e.sh` composes the planner, freshness gate, rch incident gate, and operator status reporter without executing Cargo; `scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh` verifies shipped paths, contract fields, future-tense frankentui claims, and rch-wrapped heavy Cargo examples. |

Child-bead closure evidence:

| Bead | Scope | Closure artifact |
| --- | --- | --- |
| `bd-tgc6r` | Proof-cost history indexing | Proof-cost history rows consumed by `scripts/swarm_validation_planner.sh`. |
| `bd-etd0s` | Predictive cost and target recommendations | Planner predicted-cost fields and `scripts/e2e/swarm_validation_planner_smoke.sh`. |
| `bd-wlux9` | `rch` incident packets | `scripts/rch_incident_packet_gate.sh` and smoke coverage. |
| `bd-l158y` | Conflict-aware write-set planning | Planner reservation and in-progress snapshots plus `collision_receipt.json`. |
| `bd-wnl6b` | Proof freshness and decay | `scripts/proof_freshness_decay_gate.sh` and smoke coverage. |
| `bd-znc7s` | Predictive dashboard contract | Dashboard contract docs, JSON contract, and operator-status goldens. |
| `bd-ad31e` | No-mock predictive orchestration drill | `scripts/e2e/swarm_predictive_orchestration_e2e.sh` report artifacts. |
| `bd-1y2bu` | Runbook and docs truth gate | This runbook plus `scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh`. |

## Failure Handling

| Condition | Decision | Operator action |
| --- | --- | --- |
| `rch` local fallback marker in stdout or stderr | `fail_closed` | Stop the proof, keep artifacts, report local fallback, and rerun only after remote routing is healthy. |
| Missing or degraded Agent Mail | `admit_narrow` or `defer` | Use bead assignee plus dirty-path evidence as fallback, record the degraded collision receipt, and do not edit overlapping files. |
| High compiler count, low disk, or low memory pressure | `defer` | Wait, narrow the command set, or publish the resource-pressure blocker. |
| Unknown path mapping from the planner | `fail_closed` | Add a precise mapping or choose a mapped bead; do not broaden validation. |
| Stale or incomplete proof artifacts | `fail_closed` | Refresh proof artifacts or clearly mark the evidence stale. |
| Dirty overlapping files or reservations | `defer` | Coordinate with the holder, inspect `safe_alternatives`, or pick a non-overlapping bead. |

## Truth Gate

Run the docs truth gate whenever this runbook, the swarm-control contract, or
the e2e wrapper changes:

```bash
bash -n scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh selftest
jq empty docs/swarm_predictive_dashboard_contract_v1.json
```

The truth gate verifies that referenced docs and scripts exist, that the
contract advertises the runbook surface, that predictive dashboard fields are
contract-only and `/dp/frankentui`-owned, and that heavy Cargo examples remain
`rch exec -- env CARGO_TARGET_DIR=...` wrapped.
