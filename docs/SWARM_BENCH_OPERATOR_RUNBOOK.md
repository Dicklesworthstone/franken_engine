# SWARM BENCHMARK OPERATOR RUNBOOK

> Canonical runbook for swarm benchmark no-mock drill and truth gate validation.  
> Bead: `bd-k2prt` (SWARM-BENCH-I-F)  
> Contract: `docs/swarm_benchmark_runbook_truth_contract_v1.json`

## Overview

This runbook provides operator guidance for the swarm benchmark no-mock drill and runbook truth gate. It composes the swarm benchmark workload catalog, benchmark bundle normalizer, responsiveness scorer, and operator-status handoff into one unified validation flow.

## Quick Start

### Run No-Mock Drill

```bash
./scripts/e2e/swarm_benchmark_no_mock_drill.sh ci
```

### Run Truth Gate

```bash
./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh ci
```

### Check Validation

```bash
./scripts/e2e/swarm_benchmark_no_mock_drill.sh check
./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh check
```

## Drill Cases

The no-mock drill validates five core operator scenarios:

### 1. Healthy Observed Benchmark

**Scenario**: Healthy observed benchmark suggests warm-cache or throughput-optimized action  
**Expected routing**: `warm_cache_or_throughput_optimized_action`  
**Producer scripts**: workload catalog normalizer, bundle replay normalizer, responsiveness scorer, operator status report  

### 2. Blocked FrankenEngine Measurement

**Scenario**: Blocked FrankenEngine measurement routes to prerequisite guidance  
**Expected routing**: `prerequisite_guidance`  
**Producer scripts**: workload catalog normalizer, responsiveness scorer  

### 3. Local-Fallback Contaminated

**Scenario**: Local-fallback contaminated results fail closed  
**Expected routing**: `fail_closed`  
**Producer scripts**: bundle replay normalizer, responsiveness scorer  

### 4. Resource Saturation

**Scenario**: Resource saturation routes to resource-envelope/fair-share follow-up  
**Expected routing**: `resource_envelope_fair_share_followup`  
**Producer scripts**: responsiveness scorer, operator status report  

### 5. Stale Baseline Evidence

**Scenario**: Stale baseline evidence degrades without inventing throughput  
**Expected routing**: `degraded`  
**Producer scripts**: workload catalog normalizer, responsiveness scorer  

## Truth Gate Rejections

The truth gate verifies that benchmark surfaces do NOT:

- Execute Cargo/RCH themselves
- Mutate beads or reservations  
- Change queue policy
- Replace operator status reports
- Perform live mutations outside advisory scope

## Troubleshooting

### Drill Failures

1. **Producer script missing**: Ensure all required producer scripts exist and are executable
2. **Malformed artifacts**: Validate JSON artifacts with `jq empty`
3. **Routing mismatch**: Check case expectations against actual routing decisions

### Truth Gate Failures

1. **Mutation policy violations**: Review scripts for forbidden live mutations
2. **Missing validation commands**: Ensure all required validation commands pass
3. **Dependency cycles**: Run `br dep cycles` to check for circular dependencies

### Validation Commands

All validation commands must pass:

```bash
jq empty docs/swarm_benchmark_runbook_truth_contract_v1.json
bash -n scripts/e2e/swarm_benchmark_no_mock_drill.sh
bash -n scripts/e2e/swarm_benchmark_runbook_truth_gate.sh
shellcheck -x scripts/e2e/swarm_benchmark_no_mock_drill.sh
shellcheck -x scripts/e2e/swarm_benchmark_runbook_truth_gate.sh
./scripts/e2e/swarm_benchmark_no_mock_drill.sh check
./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh check
./scripts/e2e/swarm_benchmark_no_mock_drill.sh selftest
./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh selftest
br dep cycles
git diff --check
```

## Operator Questions

This runbook helps answer:

1. **Do the benchmark drill cases route correctly?** - Run the no-mock drill and verify routing decisions match expectations
2. **Are benchmark surfaces mutation-safe?** - Run the truth gate to verify no forbidden mutations
3. **Is the benchmark composition truthful?** - Validate that real producer scripts are used, not checked-in artifacts
4. **Are validation requirements met?** - All validation commands must pass cleanly

## Integration Points

### Upstream Dependencies

- `scripts/swarm_benchmark_workload_catalog_normalizer.sh`
- `scripts/swarm_benchmark_bundle_replay_normalizer.sh`  
- `scripts/swarm_benchmark_responsiveness_scorer.sh`
- `scripts/swarm_operator_status_report.sh`

### Downstream Consumers

- Swarm operator status dashboard
- Benchmark advisory routing
- Performance regression gates

## Artifacts

### No-Mock Drill Artifacts

- `swarm_benchmark_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `case_results/*/` - Per-case validation results

### Truth Gate Artifacts

- `swarm_benchmark_runbook_truth_validation_report.json`
- `mutation_policy_verification.json`
- `validation_commands_results.json`

## Exit Codes

- **0**: Drill/truth gate passed
- **42**: Fail-closed benchmark evidence or policy violation
- **64**: Invalid argument or malformed JSON