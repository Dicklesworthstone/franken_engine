# FrankenEngine Operator Runbooks V1

**Status:** Active  
**Bead:** bd-1lsy.10.2  
**Policy ID:** policy-rgc-operator-runbooks-v1

## Purpose

This document provides concrete, actionable runbooks for FrankenEngine operators handling:
- Production incidents and failures
- Divergence triage and containment
- Observability escalation procedures
- Emergency rollback and recovery
- Operational drill validation

## Emergency Contact Information

**Escalation Chain:**
1. On-call Engineer (primary)
2. Engineering Manager (secondary) 
3. Security Team (for containment events)
4. Infrastructure Team (for platform issues)

**Critical Thresholds:**
- **RED:** >5% execution divergence from Node/V8 baseline
- **AMBER:** >1% divergence or >3 security policy violations/hour
- **GREEN:** Normal operations, <1% divergence

---

## 1. Failure Response Runbooks

### 1.1 Compilation Failure Response

**Trigger:** frankenctl compile/run commands failing

**Immediate Actions (5 minutes):**
```bash
# 1. Check system status
./scripts/run_rgc_support_surface_contract.sh test
frankenctl doctor --summary

# 2. Capture diagnostics
mkdir -p incident-$(date +%Y%m%d-%H%M%S)
cd incident-$(date +%Y%m%d-%H%M%S)

# 3. Run triage commands
frankenctl verify --trace-id "incident-$(date +%Y%m%d-%H%M%S)" \
  --decision-id "triage-compilation-failure" \
  --out diagnostics.json

# 4. Check for known issues
grep -r "$(echo "$ERROR_MSG" | head -c 50)" docs/operator-gates/
```

**Escalation Triggers:**
- Compilation failure rate >10% over 15 minutes
- Security policy violations in error messages
- Cross-platform divergence detected

### 1.2 Runtime Execution Divergence

**Trigger:** Execution results differ from Node.js/V8 baseline

**Immediate Actions (2 minutes):**
```bash
# 1. Enable maximum observability
export FRANKEN_OBSERVABILITY_MODE=lossless
export FRANKEN_DETERMINISTIC_REPLAY=enabled

# 2. Capture execution artifacts
frankenctl replay --input problematic_script.js \
  --trace-id "divergence-$(date +%Y%m%d-%H%M%S)" \
  --artifact-dir ./divergence-artifacts/

# 3. Compare with reference
node problematic_script.js > reference_output.txt
frankenctl run problematic_script.js > franken_output.txt
diff -u reference_output.txt franken_output.txt

# 4. Verify shipped containment/quarantine surfaces
./scripts/test_fleet_quarantine_e2e.sh
```

**Escalation Triggers:**
- Divergence affects >3 execution paths
- Security boundaries compromised
- Deterministic replay fails to reproduce

### 1.3 Security Policy Violation

**Trigger:** Ambient authority rejection or capability violation

**Immediate Actions (1 minute):**
```bash
# 1. STOP execution immediately
pkill -f frankenctl
pkill -f franken-engine

# 2. Enable quarantine mode
export FRANKEN_QUARANTINE_MODE=strict
export FRANKEN_CAPABILITY_ENFORCEMENT=fail_closed

# 3. Capture security evidence
mkdir -p security-incident-$(date +%Y%m%d-%H%M%S)
frankenctl verify --security-mode strict \
  --out security-incident-$(date +%Y%m%d-%H%M%S)/security_report.json

# 4. Immediate escalation to security team
echo "SECURITY INCIDENT: $(date)" > security_alert.txt
echo "Host: $(hostname)" >> security_alert.txt
echo "User: $(whoami)" >> security_alert.txt
# Send to security monitoring
```

**NO DELAY - Security incidents require immediate escalation**

---

## 2. Divergence Triage Procedures

### 2.1 Classification Matrix

| Severity | Criteria | Response Time | Actions |
|----------|----------|---------------|---------|
| **P0** | >5% execution divergence, security implications | 5 minutes | Full containment, leadership notification |
| **P1** | 1-5% divergence, functional impact | 15 minutes | Investigation, partial containment |
| **P2** | <1% divergence, cosmetic differences | 1 hour | Analysis, documentation |

### 2.2 Triage Workflow

```bash
#!/usr/bin/env bash
# Divergence Triage Script

set -euo pipefail

divergence_percent="$1"
affected_workload="$2"
trace_id="triage-$(date +%Y%m%d-%H%M%S)"

if (( $(echo "$divergence_percent > 5.0" | bc -l) )); then
    echo "P0 INCIDENT: $divergence_percent% divergence in $affected_workload"
    ./runbooks/scripts/p0_containment.sh "$trace_id"
elif (( $(echo "$divergence_percent > 1.0" | bc -l) )); then
    echo "P1 INCIDENT: $divergence_percent% divergence in $affected_workload"
    ./runbooks/scripts/p1_investigation.sh "$trace_id"
else
    echo "P2 DIVERGENCE: $divergence_percent% divergence in $affected_workload"
    ./runbooks/scripts/p2_analysis.sh "$trace_id"
fi
```

### 2.3 Root Cause Analysis Template

For each divergence incident, capture:

1. **Timeline:** When first detected, progression, resolution
2. **Scope:** Which workloads affected, percentage impact
3. **Evidence:** Replay artifacts, comparison diffs, logs
4. **Root Cause:** Parser bug, runtime difference, configuration issue
5. **Resolution:** Immediate fix, workaround, long-term prevention
6. **Prevention:** Code changes, test additions, monitoring improvements

---

## 3. Containment Response Procedures

### 3.1 Quarantine Mesh Activation

**When:** Security violations or >5% execution divergence

```bash
# 1. Activate global quarantine
export FRANKEN_GLOBAL_QUARANTINE=enabled
export FRANKEN_MESH_PROPAGATION=strict

# 2. Verify fleet quarantine propagation with the shipped E2E surface
./scripts/test_fleet_quarantine_e2e.sh

# 3. Block new executions
touch /tmp/franken_execution_blocked
echo "CONTAINMENT ACTIVE: $(date)" > /tmp/franken_containment_status

# 4. Notify fleet
./runbooks/scripts/fleet_containment_notification.sh \
  --severity P0 \
  --reason "execution-divergence"
```

### 3.2 Fleet Propagation Protocol

1. **Local Node:** Immediate containment activation
2. **Regional Cluster:** Propagate quarantine within 30 seconds
3. **Global Fleet:** Full mesh update within 2 minutes
4. **Rollback Ready:** Prepare previous known-good version

### 3.3 Workload Isolation

```bash
# Verify fleet quarantine propagation
./scripts/test_fleet_quarantine_e2e.sh

# Monitor containment latency with measured evidence
CONTAINMENT_LATENCY_METRIC_INPUT="$CONTAINMENT_LATENCY_METRIC_INPUT" \
  ./scripts/run_containment_latency_metric_gate.sh ci
```

---

## 4. Observability Mode Escalation

### 4.1 Observability Levels

| Level | Purpose | Performance Impact | Retention |
|-------|---------|-------------------|-----------|
| **Minimal** | Normal operations | <1% overhead | 24 hours |
| **Standard** | Basic debugging | <5% overhead | 48 hours |
| **Detailed** | Deep investigation | <15% overhead | 7 days |
| **Lossless** | Incident response | <30% overhead | 30 days |

### 4.2 Escalation Triggers

```bash
# Auto-escalate to Standard on error rate >1%
if [[ "$ERROR_RATE" > 1 ]]; then
    export FRANKEN_OBSERVABILITY_MODE=standard
    echo "Auto-escalated to STANDARD observability: error rate $ERROR_RATE%"
fi

# Auto-escalate to Detailed on divergence >0.5%
if [[ "$DIVERGENCE_RATE" > 0.5 ]]; then
    export FRANKEN_OBSERVABILITY_MODE=detailed
    echo "Auto-escalated to DETAILED observability: divergence $DIVERGENCE_RATE%"
fi

# Manual escalation to Lossless (operator decision)
export FRANKEN_OBSERVABILITY_MODE=lossless
echo "MANUAL escalation to LOSSLESS observability: full incident investigation"
```

### 4.3 Evidence Collection

```bash
#!/usr/bin/env bash
# Evidence Collection for Lossless Mode

incident_id="incident-$(date +%Y%m%d-%H%M%S)"
evidence_dir="./evidence/$incident_id"
mkdir -p "$evidence_dir"

# Capture all execution artifacts
frankenctl benchmark --mode lossless \
  --artifact-dir "$evidence_dir/benchmark_artifacts/"

# Capture deterministic replay data  
frankenctl replay --mode lossless \
  --input-workload problematic_workload.js \
  --artifact-dir "$evidence_dir/replay_artifacts/"

# Capture system state
./scripts/run_rgc_system_snapshot.sh "$evidence_dir/system_snapshot/"

# Package for analysis
tar -czf "evidence-$incident_id.tar.gz" "$evidence_dir/"
echo "Evidence package ready: evidence-$incident_id.tar.gz"
```

---

## 5. Rollback Procedures

### 5.1 Emergency Rollback (P0 incidents)

**Target:** Rollback within 10 minutes

```bash
#!/usr/bin/env bash
# Emergency Rollback Script

set -euo pipefail

echo "EMERGENCY ROLLBACK INITIATED: $(date)"

# 1. Stop all FrankenEngine processes
systemctl stop franken-engine
pkill -f frankenctl

# 2. Switch to previous known-good version
PREVIOUS_VERSION=$(cat /etc/franken-engine/previous-good-version)
echo "Rolling back to version: $PREVIOUS_VERSION"

# 3. Swap binaries
mv /usr/local/bin/frankenctl /usr/local/bin/frankenctl.failed
mv /usr/local/bin/frankenctl.previous /usr/local/bin/frankenctl

# 4. Restart with previous version
systemctl start franken-engine

# 5. Verify rollback success
sleep 5
frankenctl version
frankenctl doctor --quick

echo "EMERGENCY ROLLBACK COMPLETED: $(date)"
```

### 5.2 Graceful Rollback (P1 incidents)

**Target:** Rollback within 30 minutes with validation

```bash
# 1. Prepare rollback environment
./runbooks/scripts/prepare_rollback_environment.sh

# 2. Run validation suite on previous version
frankenctl.previous verify --comprehensive

# 3. Execute graceful switchover
./runbooks/scripts/graceful_version_switch.sh \
  --from-version "$CURRENT_VERSION" \
  --to-version "$PREVIOUS_VERSION" \
  --validation-required

# 4. Post-rollback verification
./scripts/run_rgc_post_rollback_verification.sh
```

### 5.3 Rollback Validation Checklist

- [ ] Previous version binary integrity verified
- [ ] Configuration compatibility confirmed  
- [ ] Critical workload paths tested
- [ ] Performance baseline restored
- [ ] Security policies enforced
- [ ] Monitoring and alerts functional
- [ ] Documentation updated

---

## 6. Scripted Drill Procedures

### 6.1 Monthly Incident Drill

**Schedule:** First Tuesday of each month, 2 PM UTC

```bash
#!/usr/bin/env bash
# Monthly Incident Response Drill

echo "=== INCIDENT DRILL START: $(date) ==="

# Simulate compilation failure
./runbooks/drills/simulate_compilation_failure.sh

# Test operator response time
start_time=$(date +%s)
echo "DRILL: Operator should run frankenctl doctor within 60 seconds"

# Wait for operator action (manual)
read -p "Press ENTER when doctor command completed: "
end_time=$(date +%s)
response_time=$((end_time - start_time))

if [[ $response_time -le 60 ]]; then
    echo "✓ PASS: Response time ${response_time}s (target: <60s)"
else
    echo "✗ FAIL: Response time ${response_time}s exceeded target"
fi

echo "=== INCIDENT DRILL END: $(date) ==="
```

### 6.2 Quarterly Rollback Drill

**Schedule:** 15th day of quarter months (Mar, Jun, Sep, Dec)

```bash
#!/usr/bin/env bash
# Quarterly Rollback Drill

echo "=== ROLLBACK DRILL START: $(date) ==="

# Test graceful rollback procedure
./runbooks/drills/test_graceful_rollback.sh

# Verify all systems functional after rollback
./scripts/run_rgc_comprehensive_verification.sh

# Test rollback time (target: <30 minutes)
# Automated timing built into rollback script

echo "=== ROLLBACK DRILL END: $(date) ==="
```

### 6.3 Drill Validation Metrics

| Drill Type | Success Criteria | Target Time | Pass Threshold |
|------------|------------------|-------------|----------------|
| **Incident Response** | Correct triage actions | <5 minutes | 90% |
| **Containment** | Quarantine activation | <2 minutes | 95% |
| **Rollback** | Service restoration | <30 minutes | 85% |
| **Communication** | Escalation notifications | <3 minutes | 100% |

---

## 7. Quick Reference Cards

### 7.1 Emergency Commands

```bash
# STOP EVERYTHING (security incident)
pkill -f franken; export FRANKEN_QUARANTINE_MODE=strict

# Basic health check
frankenctl doctor --summary

# Detailed diagnostics
frankenctl verify --comprehensive

# Emergency rollback
./runbooks/scripts/emergency_rollback.sh

# Evidence collection  
./runbooks/scripts/collect_incident_evidence.sh
```

### 7.2 Key File Locations

- **Runbooks:** `/data/projects/franken_engine/docs/OPERATOR_RUNBOOKS_V1.md`
- **Scripts:** `/data/projects/franken_engine/runbooks/scripts/`
- **Evidence:** `/data/projects/franken_engine/evidence/`
- **Previous Binary:** `/usr/local/bin/frankenctl.previous`
- **Configuration:** `/etc/franken-engine/`

### 7.3 Critical Environment Variables

```bash
# Emergency containment
export FRANKEN_QUARANTINE_MODE=strict
export FRANKEN_CAPABILITY_ENFORCEMENT=fail_closed

# Maximum observability
export FRANKEN_OBSERVABILITY_MODE=lossless
export FRANKEN_DETERMINISTIC_REPLAY=enabled

# Rollback preparation
export FRANKEN_ROLLBACK_MODE=ready
export FRANKEN_PREVIOUS_VERSION_ACTIVE=true
```

---

## Appendix A: Incident Classification Examples

### A.1 P0 Examples
- Parser accepts malicious code that Node.js rejects
- Capability system bypassed (ambient authority violation)
- >5% execution divergence on production workload
- Security policy enforcement failures

### A.2 P1 Examples  
- 1-5% execution divergence on non-critical workload
- Performance degradation >2x baseline
- Feature unavailable but workarounds exist
- Incorrect but non-security-impacting behavior

### A.3 P2 Examples
- <1% execution divergence in edge cases
- Cosmetic output differences
- Non-functional test failures
- Documentation inconsistencies

---

**Document Version:** 1.0  
**Last Updated:** $(date -u +%Y-%m-%d)  
**Next Review:** $(date -u -d '+3 months' +%Y-%m-%d)
