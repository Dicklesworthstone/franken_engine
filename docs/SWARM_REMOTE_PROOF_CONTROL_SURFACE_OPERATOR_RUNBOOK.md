# SWARM REMOTE-PROOF CONTROL SURFACE OPERATOR RUNBOOK

> Canonical runbook for swarm remote-proof/proof-economy control surface no-mock drill and truth gate validation.  
> Bead: `bd-in9cl` (SWARM-CTRL-XVIII-E)  
> Contract: `docs/swarm_remote_proof_control_surface_runbook_truth_contract_v1.json`

## Overview

This runbook provides operator guidance for the remote-proof/proof-economy control surface no-mock drill and truth gate validation. It composes the expanded catalog, router, drift gate, and operator-status handoff into one unified validation flow for remote-proof and proof-economy surfaces.

## Quick Start

### Run No-Mock Drill

```bash
./scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh ci
```

### Run Truth Gate

```bash
./scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh ci
```

### Check Validation

```bash
./scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh check
./scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh check
```

## Drill Cases

The no-mock drill validates six core remote-proof/proof-economy scenarios:

### 1. Resident Remote Proof

**Scenario**: Remote proof residency and artifact retrieval optimization  
**Expected routing**: `remote_proof_artifact_retrieval`  
**Producer scripts**: resident remote proof bundle, archive exporter  
**Intent**: artifact residency optimization

### 2. Proof-Economy Replay

**Scenario**: Proof-economy policy evaluator and replay trace surfaces  
**Expected routing**: `proof_economy_policy_evaluation`  
**Producer scripts**: policy evaluator, counterfactual replay runner  
**Intent**: cost optimization replay

### 3. Warm-Target ROI

**Scenario**: Warm-target ROI and sticky worker lease optimization  
**Expected routing**: `warm_target_roi_optimization`  
**Producer scripts**: warm target prefetch ROI advisory, sticky worker lease planner  
**Intent**: worker locality optimization

### 4. Build-Storm QoS

**Scenario**: Build-storm QoS batching and worker capability normalization  
**Expected routing**: `build_storm_qos_batching`  
**Producer scripts**: build storm QoS batch planner, worker capability toolchain normalizer  
**Intent**: resource pressure QoS optimization

### 5. Uncataloged Script Fail-Closed

**Scenario**: Drift gate fail-closed behavior on uncataloged remote-proof scripts  
**Expected routing**: `fail_closed`  
**Reason**: uncataloged remote-proof script detected

### 6. Local-Fallback Contamination

**Scenario**: Local-fallback contamination detection and fail-closed response  
**Expected routing**: `fail_closed`  
**Reason**: local fallback contamination detected

## Truth Gate Rejections

The truth gate verifies that drill surfaces do NOT:

- Mutate br (beads, reservations, assignments)
- Query or send Agent Mail
- Release reservations
- Run Cargo/RCH directly  
- Mutate remote workers
- Change queue policy
- Replace operator status reports

## Producer Scripts Used

### Core Control Surface Scripts
- `scripts/swarm_control_surface_catalog_normalizer.sh` - Catalog normalization
- `scripts/swarm_control_surface_intent_router.sh` - Intent routing
- `scripts/swarm_control_surface_drift_gate.sh` - Drift detection and fail-closed enforcement
- `scripts/swarm_operator_status_report.sh` - Status handoff

### Remote-Proof/Proof-Economy Scripts
- `scripts/proof_economy_policy_evaluator.sh` - Cost policy evaluation
- `scripts/proof_economy_replay_trace_normalizer.sh` - Replay trace normalization
- `scripts/swarm_warm_target_prefetch_roi_advisory.sh` - Warm target ROI analysis
- `scripts/build_storm_qos_batch_planner.sh` - Build storm QoS planning
- `scripts/swarm_worker_capability_toolchain_normalizer.sh` - Worker capability analysis
- `scripts/sticky_worker_warm_target_lease_planner.sh` - Worker lease planning

## Troubleshooting

### Drill Failures

1. **Producer script missing**: Ensure required control surface and remote-proof scripts exist and are executable
2. **Malformed artifacts**: Validate JSON artifacts with `jq empty`
3. **Routing mismatch**: Check case expectations against actual routing decisions
4. **Remote-proof script unavailable**: Drill gracefully handles missing optional scripts

### Truth Gate Failures

1. **Mutation policy violations**: Review drill script for forbidden operations
2. **Missing validation commands**: Ensure all required validation commands pass
3. **Dependency cycles**: Run `br dep cycles` when available to check cycles

### Validation Commands

All validation commands must pass:

```bash
bash -n scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh
bash -n scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh
shellcheck -x scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh
shellcheck -x scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh
./scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh check
./scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh check
./scripts/e2e/swarm_remote_proof_control_surface_no_mock_drill.sh selftest
./scripts/e2e/swarm_remote_proof_control_surface_truth_gate.sh selftest
git diff --check
```

## Operator Questions

This runbook helps answer:

1. **Do remote-proof control surfaces route correctly?** - Run the no-mock drill to verify routing decisions
2. **Are control surface operations mutation-safe?** - Run the truth gate to verify no forbidden mutations
3. **Is the remote-proof catalog composition truthful?** - Validate that real producer scripts are used
4. **Are proof-economy surfaces operational?** - Check routing for cost optimization and replay traces
5. **Do warm-target optimizations work?** - Verify ROI advisory and worker locality optimization

## Integration Points

### Upstream Dependencies

- Swarm control surface catalog and normalization infrastructure
- Remote-proof artifact retrieval and residency systems
- Proof-economy policy evaluation and replay systems
- Worker capability and warm-target optimization systems

### Downstream Consumers

- Swarm operator status dashboard
- Remote-proof advisory routing
- Build-storm QoS optimization
- Worker locality and cost optimization

## Artifacts

### No-Mock Drill Artifacts

- `swarm_remote_proof_control_surface_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `case_results/*/` - Per-case validation results for each remote-proof scenario

### Truth Gate Artifacts

- `swarm_remote_proof_control_surface_truth_validation_report.json`
- `mutation_policy_verification.json`
- `validation_commands_results.json`

## Exit Codes

- **0**: Drill/truth gate passed
- **42**: Fail-closed evidence or policy violation
- **64**: Invalid argument or malformed contract

## Remote-Proof Surface Family Coverage

The drill covers the expanded remote-proof/proof-economy family:

- **Remote proof residency**: Artifact retrieval and mirror systems
- **Proof-economy optimization**: Cost policy and replay trace analysis  
- **Warm-target leasing**: ROI-driven worker locality optimization
- **Build-storm QoS**: Resource pressure batching and worker capability matching
- **Drift detection**: Fail-closed enforcement on uncataloged scripts
- **Contamination detection**: Local-fallback contamination and fail-closed response