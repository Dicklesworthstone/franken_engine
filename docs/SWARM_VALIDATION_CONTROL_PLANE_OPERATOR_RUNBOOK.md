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
- `scripts/e2e/source_local_rch_validation_admission_smoke.sh`
- `scripts/e2e/source_local_rch_admission_no_mock_proof.sh`
- `scripts/e2e/build_storm_qos_batch_planner_smoke.sh`
- `scripts/e2e/swarm_operator_status_report_smoke.sh`
- `scripts/e2e/swarm_predictive_orchestration_e2e.sh`
- `scripts/e2e/swarm_admission_drill.sh`
- `scripts/e2e/swarm_resource_lease_planner_smoke.sh`
- `scripts/e2e/proof_reuse_cache_planner_smoke.sh`
- `scripts/e2e/staged_ownership_contamination_guard_smoke.sh`
- `scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh`
- `scripts/build_storm_qos_batch_planner.sh`
- `scripts/proof_freshness_decay_gate.sh`
- `scripts/proof_reuse_cache_planner.sh`
- `scripts/source_local_rch_validation_admission.sh`
- `scripts/rch_incident_packet_gate.sh`
- `scripts/staged_ownership_contamination_guard.sh`
- `scripts/stale_lock_stalled_bead_recommender.sh`
- `scripts/swarm_resource_lease_planner.sh`
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
br doctor
bv --recipe actionable --robot-plan
git status --short
```

If `br doctor` reports DB degradation, do not infer that the queue is empty.
Use `.beads/issues.jsonl`, the current bead assignee, and Agent Mail messages as
degraded fallback evidence, then report the exact `br doctor` failure in the
operator status update. Resume normal closeout only after `br sync --flush-only`
or an explicit tracker repair succeeds.

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

6. Produce the SWARM-CTRL-III admission artifacts that feed operator status:

```bash
./scripts/swarm_resource_lease_planner.sh --agent-id ScarletOwl --bead-id bd-mkz2h --requested-command "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_mkz2h cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e" --target-dir /tmp/rch_target_franken_engine_bd_mkz2h --reservation-snapshot-json /tmp/swarm-reservations.json --br-snapshot-json /tmp/swarm-in-progress.json --rch-workers-json /tmp/swarm-rch-workers.json --dirty-files-json /tmp/swarm-dirty-files.json --output-dir /tmp/franken-engine-swarm-resource-lease
./scripts/proof_reuse_cache_planner.sh --proof-index-json /tmp/franken-engine-proof-index/proof_index.json --freshness-report /tmp/franken-engine-proof-freshness/proof_freshness_report.json --expected-source-revision smoke-rev --changed-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md --output-dir /tmp/franken-engine-proof-reuse-cache
./scripts/build_storm_qos_batch_planner.sh --pending-requests-json /tmp/swarm-pending-validation-requests.json --resource-lease-plans-json /tmp/swarm-resource-lease-plans.json --proof-cost-history-json /tmp/swarm-proof-cost-history.json --rch-workers-json /tmp/swarm-rch-workers.json --output-dir /tmp/franken-engine-build-storm-qos
./scripts/stale_lock_stalled_bead_recommender.sh --in-progress-json /tmp/swarm-in-progress.json --agent-profiles-json /tmp/swarm-agent-profiles.json --thread-timestamps-json /tmp/swarm-thread-timestamps.json --file-reservations-json /tmp/swarm-reservations.json --git-activity-json /tmp/swarm-git-activity.json --output-dir /tmp/franken-engine-stale-lock
```

Inspect these outputs before admitting more work:

```bash
cat /tmp/franken-engine-swarm-resource-lease/resource_lease_plan.json
cat /tmp/franken-engine-proof-reuse-cache/proof_cache_plan.json
cat /tmp/franken-engine-build-storm-qos/build_storm_batch_plan.json
cat /tmp/franken-engine-stale-lock/stale_lock_recommendations.json
```

If `safe_to_reopen` is non-empty, reopen only the listed bead IDs with the
suggested commands. If `contact_first` is non-empty, send Agent Mail to the
listed owner before changing tracker ownership.

### Source-Local Lib-Unit Admission

Use the source-local admission path when the proof is tied to a single package,
target kind, test filter, and source file lane. The command identity must record
`source_revision`, `source_hash`, `cargo_lock_hash`, `dependency_root_hash`,
`package`, `target_kind`, `test_filter`, `rustflags`, `toolchain`,
`cargo_target_dir`, and `command_fingerprint`.

The cold-refresh command shape is intentionally narrow and copy/pasteable:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_source_local_bd_lnks9 RUSTFLAGS=-Clinker=cc cargo test -p frankenengine-engine --lib shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release -- --exact --nocapture
```

Use compact `RUSTFLAGS=-Clinker=cc` in source-local proof commands so the
preflight parser treats the linker flag as one environment value. Do not widen
the command to `--tests`, `--all-targets`, or an unfiltered package test unless
the admission report selects a cold refresh and the closeout says why the
source-local proof no longer covers the requested lane.

Generate advisory admission artifacts before any live proof:

```bash
./scripts/source_local_rch_validation_admission.sh --case-id bd-lnks9-live --request-json /tmp/source-local/request.json --preflight-json /tmp/source-local/preflight/preflight_report.json --proof-admission-json /tmp/source-local/proof_admission.json --sticky-plan-json /tmp/source-local/sticky_plan.json --output-dir /tmp/source-local/admission
```

The admission artifact schema is
`franken-engine.source-local-rch-validation-admission.v1`.

For a no-mock live proof, use the shipped runner:

```bash
SOURCE_LOCAL_RCH_PROOF_ARTIFACT_ROOT=/tmp/franken-engine-source-local-rch-proof ./scripts/e2e/source_local_rch_admission_no_mock_proof.sh
```

Future closeouts must cite these evidence files when present:

- `request.json`
- `preflight/preflight_report.json`
- `admission/source_local_rch_validation_admission.json`
- `rch-output.log`
- `rch-output.plain.log`
- `log_scan.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Operator status wording for source-local proof admission:

| State | Machine value | Operator wording | Required action |
| --- | --- | --- | --- |
| Reusable | `admit_reuse` | reusable source-local proof | Reuse only the selected command and cite `source_local_rch_validation_admission.json`. |
| Cold refresh | `cold_refresh_required` | cold refresh required | Run only `selected_command` or `suggested_cold_refresh_command`; do not claim warm reuse. |
| Contaminated | `fail_closed` with `local_fallback_contamination` or `support_crate_contamination` | fail closed: contaminated proof | Discard the proof and rerun remote-only after removing fallback or support-crate compile contamination. |
| Stale | `cold_refresh_required` with `source_revision_mismatch`, `source_hash_mismatch`, `cargo_lock_hash_mismatch`, `dependency_root_hash_mismatch`, `changed_path_overlap`, or `missing_freshness` | fail closed for reuse: stale warm-target proof | Refresh the proof for the current source/Cargo.lock/dependency root and exact filter. |
| Remote blocked | `remote_blocker` in the no-mock proof manifest | remote fleet blocker | Keep the bead open or close with the worker/toolchain/timeout blocker and the preserved rch log. |

Common remediation:

- Bare Cargo: rerun through `rch exec -- env` with explicit `CARGO_TARGET_DIR=`.
- Local fallback: fail closed; the log cannot be used as remote evidence.
- Missing target dir: add an off-repo `CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_source_local_<bead>`.
- Broadening to tests or all targets: return to the exact package, `--lib`, and test filter unless the admission report explicitly selects a cold refresh.
- Missing freshness: regenerate proof-reuse admission rows with current source and dependency root hashes.
- Stale source or `Cargo.lock` hash: refresh the proof; never relabel stale evidence as reusable.

7. Execute only admitted proof commands. Shell and docs gates can run directly:

```bash
./scripts/e2e/swarm_validation_control_plane_contract_smoke.sh check
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check
./scripts/e2e/swarm_validation_control_plane_e2e.sh check
./scripts/e2e/source_local_rch_validation_admission_smoke.sh check
./scripts/e2e/proof_freshness_decay_gate_smoke.sh check
./scripts/e2e/proof_reuse_cache_planner_smoke.sh check
./scripts/e2e/rch_incident_packet_gate_smoke.sh check
./scripts/e2e/build_storm_qos_batch_planner_smoke.sh check
./scripts/e2e/swarm_resource_lease_planner_smoke.sh check
./scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh check
./scripts/e2e/staged_ownership_contamination_guard_smoke.sh check
./scripts/e2e/swarm_operator_status_report_smoke.sh check
./scripts/e2e/swarm_admission_drill.sh check
```

Heavy Rust proof commands must keep this shape:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_validation PROOF_ARTIFACT_SOURCE_REVISION=smoke-rev cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture
```

8. Inspect proof artifacts before reporting success:

```bash
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/commands.txt
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/events.jsonl
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/report.json
```

If the newest artifact bundle is stale, incomplete, or from another source
revision, mark the proof stale and refresh it before relying on it.

9. Guard the staged index before committing or closing the bead:

```bash
git diff --cached --name-status
./scripts/staged_ownership_contamination_guard.sh --agent-id ScarletOwl --bead-id bd-mkz2h --reservation-snapshot-json /tmp/swarm-reservations.json --allowed-path docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md --allowed-path scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh --allowed-path docs/swarm_validation_control_plane_contract_v1.json --output-dir /tmp/franken-engine-staged-ownership
cat /tmp/franken-engine-staged-ownership/staged_ownership_report.json
```

If the staged ownership report is not `pass`, unstage the offending paths or
coordinate with the listed reservation holder. Do not commit a `pass_degraded`
closeout unless the degraded evidence is explicitly called out in Agent Mail.

10. Publish operator status from explicit snapshots:

```bash
./scripts/swarm_operator_status_report.sh --output-dir /tmp/franken-engine-swarm-operator-status --source-revision smoke-rev --agent-mail-status ok --rch-status ok --proof-index-status ok --validation-plan-json /tmp/franken-engine-swarm-validation-plan/plan.json --collision-receipt-json /tmp/franken-engine-swarm-validation-plan/collision_receipt.json --proof-freshness-json /tmp/franken-engine-proof-freshness/proof_freshness_report.json --rch-incident-packet-json /tmp/franken-engine-rch-incident/incident_packet.json --resource-lease-plan-json /tmp/franken-engine-swarm-resource-lease/resource_lease_plan.json --proof-cache-plan-json /tmp/franken-engine-proof-reuse-cache/proof_cache_plan.json --qos-batch-plan-json /tmp/franken-engine-build-storm-qos/build_storm_batch_plan.json --stale-lock-recommendations-json /tmp/franken-engine-stale-lock/stale_lock_recommendations.json --staged-ownership-report-json /tmp/franken-engine-staged-ownership/staged_ownership_report.json
cat /tmp/franken-engine-swarm-operator-status/status.json
cat /tmp/franken-engine-swarm-operator-status/report.md
```

11. Commit, close, sync, and notify:

```bash
git diff --cached --check
git commit -m "docs(swarm): publish admission-control runbook"
br close bd-mkz2h --reason "Published admission-control runbook and docs truth gate"
br sync --flush-only
send_message(thread_id=bd-mkz2h, subject="[bd-mkz2h] closed", body=validation_summary)
release_file_reservations(project=/data/projects/franken_engine, agent=ScarletOwl)
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
./scripts/e2e/build_storm_qos_batch_planner_smoke.sh check
./scripts/e2e/staged_ownership_contamination_guard_smoke.sh check
./scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh check
./scripts/e2e/swarm_resource_lease_planner_smoke.sh check
jq empty docs/swarm_predictive_dashboard_contract_v1.json
```

The truth gate verifies that referenced docs and scripts exist, that the
contract advertises the runbook surface, that predictive dashboard fields are
contract-only and `/dp/frankentui`-owned, and that heavy Cargo examples remain
`rch exec -- env CARGO_TARGET_DIR=...` wrapped.
