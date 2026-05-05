# Swarm Validation Control Plane Operator Runbook

**Status:** Active
**Bead:** bd-1npwf
**Policy ID:** policy-swarm-validation-control-plane-v1

## Scope

This runbook is the fresh-operator workflow for the swarm validation control
plane. It covers bead selection, file ownership, validation planning, resource
admission, proof execution, artifact inspection, and status publication.

Implementation surfaces:

- `docs/swarm_validation_control_plane_contract_v1.json`
- `scripts/e2e/swarm_validation_control_plane_contract_smoke.sh`
- `scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh`
- `scripts/e2e/swarm_validation_control_plane_e2e.sh`
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

2. Coordinate file ownership before editing:

```bash
file_reservation_paths(project=/data/projects/franken_engine, paths=planned_write_set, exclusive=true)
fetch_inbox(project=/data/projects/franken_engine)
```

If Agent Mail is missing or degraded, continue only when the bead assignee and
dirty-path evidence show no overlap. Record the degraded coordination state in
the final status update.

3. Ask the planner for the narrow validation command set:

```bash
./scripts/swarm_validation_planner.sh --bead-id bd-1onpa --source-revision smoke-rev --output-dir /tmp/franken-engine-swarm-validation-plan --changed-path scripts/swarm_validation_planner.sh
cat /tmp/franken-engine-swarm-validation-plan/plan.json
cat /tmp/franken-engine-swarm-validation-plan/commands.txt
```

Unknown path mappings are fail-closed. Do not replace them with broad
`cargo check --all-targets`; either add a precise mapping or choose a different
bead.

4. Run the resource governor before any heavy proof:

```bash
./scripts/swarm_resource_governor.sh --bead-id bd-zmuv5 --output-dir /tmp/franken-engine-swarm-resource-decision --active-compile-count 0 --disk-available-bytes 2147483648 --target-dir /tmp/rch_target_franken_engine_bd_zmuv5 --target-dir-writable true --memory-available-bytes 2147483648 --rch-present true --rch-status ok --rch-fallback-detected false --command-exit-code none --command-failure-kind none --ownership-state none --dirty-state clean
cat /tmp/franken-engine-swarm-resource-decision/decision.json
```

If the decision is `defer` or `fail_closed`, do not start a heavy proof. Follow
the remediation in the decision artifact and publish the blocker.

5. Execute only admitted proof commands. Shell and docs gates can run directly:

```bash
./scripts/e2e/swarm_validation_control_plane_contract_smoke.sh check
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check
./scripts/e2e/swarm_validation_control_plane_e2e.sh check
```

Heavy Rust proof commands must keep this shape:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_validation PROOF_ARTIFACT_SOURCE_REVISION=smoke-rev cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture
```

6. Inspect proof artifacts before reporting success:

```bash
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/commands.txt
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/events.jsonl
cat artifacts/swarm_validation_control_plane_e2e/<run-id>/wrapper/report.json
```

If the newest artifact bundle is stale, incomplete, or from another source
revision, mark the proof stale and refresh it before relying on it.

7. Publish operator status from explicit snapshots:

```bash
./scripts/swarm_operator_status_report.sh --output-dir /tmp/franken-engine-swarm-operator-status --source-revision smoke-rev --agent-mail-status ok --rch-status ok --proof-index-status ok
cat /tmp/franken-engine-swarm-operator-status/status.json
cat /tmp/franken-engine-swarm-operator-status/report.md
```

## Failure Handling

| Condition | Decision | Operator action |
| --- | --- | --- |
| `rch` local fallback marker in stdout or stderr | `fail_closed` | Stop the proof, keep artifacts, report local fallback, and rerun only after remote routing is healthy. |
| Missing or degraded Agent Mail | `admit_narrow` or `defer` | Use bead assignee plus dirty-path evidence as fallback; do not edit overlapping files. |
| High compiler count, low disk, or low memory pressure | `defer` | Wait, narrow the command set, or publish the resource-pressure blocker. |
| Unknown path mapping from the planner | `fail_closed` | Add a precise mapping or choose a mapped bead; do not broaden validation. |
| Stale or incomplete proof artifacts | `fail_closed` | Refresh proof artifacts or clearly mark the evidence stale. |
| Dirty overlapping files or reservations | `defer` | Coordinate with the holder or pick a non-overlapping bead. |

## Truth Gate

Run the docs truth gate whenever this runbook, the swarm-control contract, or
the e2e wrapper changes:

```bash
bash -n scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check
./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh selftest
```

The truth gate verifies that referenced docs and scripts exist, that the
contract advertises the runbook surface, and that heavy Cargo examples remain
`rch exec -- env CARGO_TARGET_DIR=...` wrapped.
