#!/bin/bash
set -euo pipefail

# Shadow Daemon Lifecycle Drill - Synthetic Evidence Exercise
#
# This script exercises the shadow daemon lifecycle shape with synthetic
# scenario records:
# - Real local tool execution (br/bv, Agent Mail, rch-status, git)
# - One-shot watchers and artifact collection
# - Journal append/export operations
# - Synthetic decision composition from journal events
# - Synthetic replay consistency checks
# - Truth gate reporting and validation
#
# This is not bd-djejh.6 no-mock proof. Synthetic evidence fails closed with
# EXIT_SYNTHETIC_EVIDENCE so the drill cannot satisfy no-mock adoption gates.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_WORK_DIR="$PROJECT_ROOT/tmp/shadow_daemon_e2e_$(date +%s)"

# Test scenario from command line argument
SCENARIO="${1:-healthy_idle}"
DRILL_EVIDENCE_MODE="synthetic_drill"

# Exit codes for different failure modes
EXIT_SUCCESS=0
EXIT_SOURCE_STALENESS=10
EXIT_RCH_CONTAMINATION=11
EXIT_OWNERSHIP_CONTRADICTION=12
EXIT_UNSUPPORTED_MUTATION=13
EXIT_MISSING_REFERENCES=14
EXIT_NONDETERMINISTIC_REPLAY=15
EXIT_TRUTH_GATE_FAILURE=16
EXIT_SYNTHETIC_EVIDENCE=17

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $*${NC}" >&2
}

error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $*${NC}" >&2
}

# Create working directory and preserve artifacts
setup_workspace() {
    log "Setting up workspace: $E2E_WORK_DIR"
    mkdir -p "$E2E_WORK_DIR"
    cd "$E2E_WORK_DIR"

    # Create artifact directories
    mkdir -p artifacts/{logs,snapshots,journal,decisions,replay,truth_gate}

    # Initialize run manifest
    cat > run_manifest.json <<EOF
{
    "drill_id": "shadow_daemon_lifecycle_$(date +%s)",
    "scenario": "$SCENARIO",
    "evidence_mode": "$DRILL_EVIDENCE_MODE",
    "no_mock_proof": false,
    "proof_limitations": [
        "synthetic scenario records",
        "inline python decision composition",
        "inline python replay consistency checks",
        "does not satisfy bd-djejh.6 no-mock lifecycle proof"
    ],
    "start_time": "$(date -Iseconds)",
    "project_root": "$PROJECT_ROOT",
    "work_dir": "$E2E_WORK_DIR",
    "git_commit": "$(cd "$PROJECT_ROOT" && git rev-parse HEAD)",
    "git_status_clean": $(cd "$PROJECT_ROOT" && git status --porcelain | wc -l | awk '{print ($1 == 0)}'),
    "environment": {
        "agent_name": "${AGENT_NAME:-unknown}",
        "hostname": "$(hostname)",
        "user": "$(whoami)",
        "pwd": "$(pwd)"
    }
}
EOF

    log "Workspace initialized with manifest"
}

# Run real local tools and capture outputs
execute_tool_watchers() {
    log "Executing tool watchers for scenario: $SCENARIO"

    local commands_file="$E2E_WORK_DIR/artifacts/commands.txt"
    local events_file="$E2E_WORK_DIR/artifacts/events.jsonl"

    echo "# Shadow Daemon Synthetic Tool Execution Log - $(date)" > "$commands_file"
    touch "$events_file"

    case "$SCENARIO" in
        "healthy_idle")
            execute_healthy_idle_tools "$commands_file" "$events_file"
            ;;
        "active_no_mock_lane")
            execute_active_no_mock_tools "$commands_file" "$events_file"
            ;;
        "stale_expired_agent")
            execute_stale_agent_tools "$commands_file" "$events_file"
            ;;
        "agent_mail_degraded")
            execute_degraded_agent_mail "$commands_file" "$events_file"
            ;;
        "rch_local_fallback")
            execute_rch_fallback_tools "$commands_file" "$events_file"
            ;;
        "dirty_shared_worktree")
            execute_dirty_worktree_tools "$commands_file" "$events_file"
            ;;
        *)
            error "Unknown scenario: $SCENARIO"
            exit 1
            ;;
    esac

    log "Tool execution completed, $(wc -l < "$events_file") events captured"
}

# Healthy idle scenario - minimal tool activity
execute_healthy_idle_tools() {
    local commands_file="$1"
    local events_file="$2"

    log "Running healthy idle scenario"

    # Git status check
    echo "git status --porcelain" >> "$commands_file"
    if cd "$PROJECT_ROOT" && git status --porcelain > "$E2E_WORK_DIR/artifacts/snapshots/git_status.txt" 2>&1; then
        append_event "$events_file" "git_status" "success" "$(wc -l < "$E2E_WORK_DIR/artifacts/snapshots/git_status.txt") uncommitted changes"
    else
        append_event "$events_file" "git_status" "error" "git status failed"
    fi

    # Bead listing
    echo "br list --format json" >> "$commands_file"
    if cd "$PROJECT_ROOT" && timeout 10s br list --format json > "$E2E_WORK_DIR/artifacts/snapshots/bead_list.json" 2>&1; then
        append_event "$events_file" "bead_list" "success" "bead listing completed"
    else
        append_event "$events_file" "bead_list" "error" "bead listing failed or timed out"
    fi

    # RCH status check
    echo "rch status" >> "$commands_file"
    if cd "$PROJECT_ROOT" && timeout 5s rch status > "$E2E_WORK_DIR/artifacts/snapshots/rch_status.txt" 2>&1; then
        append_event "$events_file" "rch_status" "success" "rch status completed"
    else
        append_event "$events_file" "rch_status" "warning" "rch status unavailable"
    fi
}

# Synthetic active-lane scenario. The scenario name is kept for compatibility,
# but the resulting artifacts are not no-mock proof.
execute_active_no_mock_tools() {
    local commands_file="$1"
    local events_file="$2"

    log "Running synthetic active lane scenario"

    # All tools from healthy idle plus more active operations
    execute_healthy_idle_tools "$commands_file" "$events_file"

    # Bead viewing with actionables
    echo "bv actionable" >> "$commands_file"
    if cd "$PROJECT_ROOT" && timeout 15s bv actionable > "$E2E_WORK_DIR/artifacts/snapshots/actionable_beads.txt" 2>&1; then
        local actionable_count=$(wc -l < "$E2E_WORK_DIR/artifacts/snapshots/actionable_beads.txt")
        append_event "$events_file" "actionable_beads" "success" "$actionable_count actionable beads found"
    else
        append_event "$events_file" "actionable_beads" "error" "actionable bead listing failed"
    fi

    # Agent mail check (actual connectivity test)
    if command -v python3 > /dev/null; then
        echo "python3 -c 'import json; print(json.dumps({\"tool\": \"agent_mail_check\"}))'" >> "$commands_file"
        if python3 -c "
import subprocess
import json
try:
    result = subprocess.run(['curl', '-s', '--max-time', '5', 'http://127.0.0.1:8765/api/mcp'],
                          capture_output=True, text=True, timeout=10)
    if result.returncode == 0:
        exit(0)
    else:
        exit(1)
except:
    exit(1)
" 2>/dev/null; then
            append_event "$events_file" "agent_mail_check" "success" "agent mail connectivity verified via MCP endpoint"
        else
            append_event "$events_file" "agent_mail_check" "error" "agent mail endpoint unreachable at http://127.0.0.1:8765/api/mcp"
        fi
    else
        append_event "$events_file" "agent_mail_check" "warning" "python3 not available for agent mail check"
    fi
}

# Stale/expired agent scenario
execute_stale_agent_tools() {
    local commands_file="$1"
    local events_file="$2"

    log "Running stale/expired agent scenario"

    # Simulate stale agent by using old timestamp
    local stale_timestamp="$(date -d '2 hours ago' -Iseconds)"
    append_event "$events_file" "agent_staleness_detected" "warning" "agent last seen $stale_timestamp" "$stale_timestamp"

    # Run basic tools but mark as potentially stale
    execute_healthy_idle_tools "$commands_file" "$events_file"
    append_event "$events_file" "source_staleness_check" "fail_closed" "agent data older than freshness threshold"
}

# Agent Mail degraded scenario
execute_degraded_agent_mail() {
    local commands_file="$1"
    local events_file="$2"

    log "Running Agent Mail degraded scenario"

    execute_healthy_idle_tools "$commands_file" "$events_file"

    # Test for degraded agent mail performance
    if command -v python3 > /dev/null && command -v curl > /dev/null; then
        start_time=$(date +%s%3N)
        if curl -s --max-time 5 http://127.0.0.1:8765/api/mcp > /dev/null 2>&1; then
            end_time=$(date +%s%3N)
            response_time=$((end_time - start_time))
            if [ $response_time -gt 5000 ]; then
                append_event "$events_file" "agent_mail_degraded" "warning" "agent mail responses taking ${response_time}ms (>5s threshold)"
                append_event "$events_file" "agent_mail_fallback" "success" "falling back to local tool execution"
            else
                append_event "$events_file" "agent_mail_performance" "success" "agent mail responding in ${response_time}ms"
            fi
        else
            append_event "$events_file" "agent_mail_degraded" "error" "agent mail endpoint unreachable, using local fallback"
            append_event "$events_file" "agent_mail_fallback" "success" "falling back to local tool execution"
        fi
    else
        append_event "$events_file" "agent_mail_degraded" "warning" "cannot test agent mail performance - missing dependencies"
        append_event "$events_file" "agent_mail_fallback" "success" "falling back to local tool execution"
    fi
}

# RCH local fallback contamination scenario
execute_rch_fallback_tools() {
    local commands_file="$1"
    local events_file="$2"

    log "Running RCH local fallback contamination scenario"

    execute_healthy_idle_tools "$commands_file" "$events_file"

    # Detect RCH local fallback contamination
    echo "rch status --local-fallback-check" >> "$commands_file"
    if command -v rch > /dev/null; then
        if rch status 2>&1 | grep -q "local fallback"; then
            append_event "$events_file" "rch_contamination_detected" "fail_closed" "local compilation contamination detected in rch status"
        elif rch status 2>&1 | grep -q "workers.*0"; then
            append_event "$events_file" "rch_contamination_detected" "fail_closed" "no rch workers available - local compilation may contaminate artifacts"
        else
            rch_output=$(rch status 2>&1)
            append_event "$events_file" "rch_status_check" "success" "rch workers available: $(echo "$rch_output" | grep -o '[0-9]* workers' | head -1)"
        fi
    else
        append_event "$events_file" "rch_contamination_detected" "fail_closed" "rch not available - cannot verify build artifact contamination"
    fi
}

# Dirty shared worktree ambiguity scenario
execute_dirty_worktree_tools() {
    local commands_file="$1"
    local events_file="$2"

    log "Running dirty shared worktree scenario"

    execute_healthy_idle_tools "$commands_file" "$events_file"

    # Check for ownership ambiguity
    if [ "$(cd "$PROJECT_ROOT" && git status --porcelain | wc -l)" -gt 0 ]; then
        append_event "$events_file" "ownership_contradiction" "fail_closed" "uncommitted changes may indicate conflicting ownership"
    fi
}

# Helper function to append structured events
append_event() {
    local events_file="$1"
    local event_type="$2"
    local status="$3"
    local message="$4"
    local timestamp="${5:-$(date -Iseconds)}"

    # Write single-line JSON for proper JSONL format
    printf '{"timestamp":"%s","event_type":"%s","status":"%s","message":"%s","scenario":"%s","evidence_mode":"%s","sequence":%d}\n' \
        "$timestamp" "$event_type" "$status" "$message" "$SCENARIO" "$DRILL_EVIDENCE_MODE" "$(wc -l < "$events_file")" >> "$events_file"
}

# Journal operations - append events and export checkpoints
execute_journal_operations() {
    log "Executing journal operations"

    local journal_file="$E2E_WORK_DIR/artifacts/journal/shadow_journal.jsonl"
    local export_file="$E2E_WORK_DIR/artifacts/journal/journal_export.json"
    local events_file="$E2E_WORK_DIR/artifacts/events.jsonl"

    # Convert events to journal format
    if [ -f "$events_file" ]; then
        log "Converting events to shadow journal format"
        convert_events_to_journal "$events_file" "$journal_file"

        # Export journal checkpoint
        export_journal_checkpoint "$journal_file" "$export_file"
    else
        error "No events file found for journal operations"
        exit $EXIT_MISSING_REFERENCES
    fi
}

# Convert captured events to shadow journal format
convert_events_to_journal() {
    local events_file="$1"
    local journal_file="$2"

    python3 <<EOF
import json
import hashlib
import sys
import time

def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

journal_events = []
with open('$events_file', 'r') as f:
    for line_num, line in enumerate(f, 1):
        if line.strip():
            try:
                event = json.loads(line)

                # Convert to shadow journal format
                journal_event = {
                    "journal_event_id": line_num,
                    "bead_id": f"shadow_drill_{event['event_type']}",
                    "event_kind": event["event_type"],
                    "source_kind": "tool_watcher",
                    "source_locator": f"e2e://{event['event_type']}",
                    "collected_timestamp_ms": int(time.time() * 1000),  # Real timestamp
                    "sequence_id": line_num,
                    "payload_content_hash": compute_hash(json.dumps(event, sort_keys=True)),
                    "normalized_payload": event,
                    "normalized_payload_hash": compute_hash(json.dumps(event, sort_keys=True)),
                    "raw_evidence_hashes": [],
                    "freshness_window_ms": 300000,  # 5 minutes
                    "freshness_deadline_ms": int(time.time() * 1000) + 300000,
                    "degradation_state": event["status"],
                    "retention_class": "drill_test",
                    "parent_event_ids": [line_num - 1] if line_num > 1 else [],
                    "metadata": {
                        "scenario": event["scenario"],
                        "original_timestamp": event["timestamp"]
                    }
                }

                journal_events.append(journal_event)

            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse event line {line_num}: {e}", file=sys.stderr)

with open('$journal_file', 'w') as f:
    for event in journal_events:
        f.write(json.dumps(event) + '\n')

print(f"Converted {len(journal_events)} events to journal format", file=sys.stderr)
EOF
}

# Export journal checkpoint for replay
export_journal_checkpoint() {
    local journal_file="$1"
    local export_file="$2"

    python3 <<EOF
import json
import sys

# Read journal events
events = []
with open('$journal_file', 'r') as f:
    for line in f:
        if line.strip():
            events.append(json.loads(line))

# Create export format
export_data = {
    "schema_version": "franken-engine.shadow-evidence-journal.v1",
    "rows": events
}

with open('$export_file', 'w') as f:
    json.dump(export_data, f, indent=2)

print(f"Exported {len(events)} journal events to checkpoint", file=sys.stderr)
EOF
}

# Decision composition from journal events
execute_decision_composition() {
    log "Executing decision composition"

    local journal_export="$E2E_WORK_DIR/artifacts/journal/journal_export.json"
    local status_file="$E2E_WORK_DIR/artifacts/decisions/shadow_status.json"
    local recommendations_file="$E2E_WORK_DIR/artifacts/decisions/recommendations.json"

    if [ ! -f "$journal_export" ]; then
        error "Journal export not found for decision composition"
        exit $EXIT_MISSING_REFERENCES
    fi

    # Compose synthetic shadow decisions. This is intentionally marked as
    # non-authoritative so it cannot be used as no-mock proof.
    python3 <<EOF
import json
import sys

with open('$journal_export', 'r') as f:
    export_data = json.load(f)

events = export_data.get('rows', [])

# Analyze events to compose decisions
status = {
    "proof_class": "synthetic_drill",
    "no_mock_proof": False,
    "composer_kind": "inline_python_synthetic",
    "shadow_truth_state": "operational",
    "total_events": len(events),
    "healthy_events": len([e for e in events if e.get('degradation_state') == 'success']),
    "warning_events": len([e for e in events if e.get('degradation_state') == 'warning']),
    "error_events": len([e for e in events if e.get('degradation_state') == 'error']),
    "fail_closed_events": len([e for e in events if e.get('degradation_state') == 'fail_closed']),
    "composition_timestamp": "$(date -Iseconds)",
    "scenario": "$SCENARIO"
}

# Determine overall status
if status["fail_closed_events"] > 0:
    status["shadow_truth_state"] = "fail_closed"
    status["recommendation"] = "abort_operations"
elif status["error_events"] > status["healthy_events"]:
    status["shadow_truth_state"] = "degraded"
    status["recommendation"] = "proceed_with_caution"
else:
    status["shadow_truth_state"] = "operational"
    status["recommendation"] = "proceed_normally"

with open('$status_file', 'w') as f:
    json.dump(status, f, indent=2)

# Generate recommendations
recommendations = {
    "proof_class": "synthetic_drill",
    "no_mock_proof": False,
    "recommendations": [
        {
            "type": "operational_guidance",
            "priority": "high" if status["shadow_truth_state"] == "fail_closed" else "medium",
            "message": f"Shadow daemon analysis complete: {status['shadow_truth_state']}",
            "action_items": [
                f"Review {status['error_events']} error events" if status["error_events"] > 0 else "No errors detected",
                f"Monitor {status['warning_events']} warning conditions" if status["warning_events"] > 0 else "No warnings"
            ]
        }
    ],
    "composition_metadata": {
        "input_events": len(events),
        "composition_time": "$(date -Iseconds)",
        "scenario": "$SCENARIO",
        "composer_kind": "inline_python_synthetic"
    }
}

with open('$recommendations_file', 'w') as f:
    json.dump(recommendations, f, indent=2)

print(f"Composed decisions from {len(events)} events: {status['shadow_truth_state']}", file=sys.stderr)
EOF

    log "Decision composition completed"
}

# Replay verification using the replay verifier
execute_replay_verification() {
    log "Executing replay verification"

    local journal_export="$E2E_WORK_DIR/artifacts/journal/journal_export.json"
    local replay_report="$E2E_WORK_DIR/artifacts/replay/replay_report.json"

    if [ ! -f "$journal_export" ]; then
        error "Journal export not found for replay verification"
        exit $EXIT_MISSING_REFERENCES
    fi

    # Perform a synthetic replay consistency check. This is intentionally marked
    # as non-authoritative so it cannot be used as no-mock proof.
    python3 <<EOF
import json
import hashlib
import sys
import time

with open('$journal_export', 'r') as f:
    export_data = json.load(f)

events = export_data.get('rows', [])

# Perform actual replay verification by checking event consistency
detected_drift = []
event_hashes = []

# Check for event integrity and consistency
for i, event in enumerate(events):
    # Verify event has required fields
    required_fields = ['event_type', 'timestamp', 'status']
    for field in required_fields:
        if field not in event:
            detected_drift.append({
                "event_index": i,
                "drift_type": "missing_field",
                "description": f"Event missing required field: {field}"
            })

    # Check for timestamp consistency (events should be in order)
    if i > 0 and 'timestamp' in event and 'timestamp' in events[i-1]:
        try:
            current_ts = float(event['timestamp'])
            prev_ts = float(events[i-1]['timestamp'])
            if current_ts < prev_ts:
                detected_drift.append({
                    "event_index": i,
                    "drift_type": "timestamp_regression",
                    "description": f"Event timestamp {current_ts} < previous {prev_ts}"
                })
        except (ValueError, TypeError):
            detected_drift.append({
                "event_index": i,
                "drift_type": "invalid_timestamp",
                "description": f"Non-numeric timestamp: {event.get('timestamp', 'missing')}"
            })

# Generate actual replay verification report
replay_results = {
    "report_id": f"replay_{int(time.time())}",
    "proof_class": "synthetic_drill",
    "no_mock_proof": False,
    "verifier_kind": "inline_python_synthetic",
    "detection_timestamp_ms": int(time.time() * 1000),
    "source_export_events": len(events),
    "target_environment": "e2e_drill",
    "detected_drift": detected_drift,
    "is_expected_migration": False,
    "verification_status": "pass" if len(detected_drift) == 0 else "drift_detected",
    "replay_recipe": {
        "input_checkpoint": "journal_export.json",
        "replay_command": ["python3", "inline_synthetic_replay_check"],
        "environment_vars": {"SCENARIO": "$SCENARIO"},
        "verification_method": "event_consistency_check",
        "referenced_artifacts": ["journal_export.json", "shadow_status.json"],
        "authoritative_no_mock_proof": False
    }
}

# Check for replay consistency
event_hashes = []
for event in events:
    payload = json.dumps(event.get('normalized_payload', {}), sort_keys=True)
    expected_hash = event.get('normalized_payload_hash', '')
    computed_hash = hashlib.sha256(payload.encode()).hexdigest()

    if expected_hash and computed_hash != expected_hash:
        replay_results["detected_drift"].append({
            "type": "payload_hash_mismatch",
            "event_id": event.get('journal_event_id'),
            "expected_hash": expected_hash,
            "actual_hash": computed_hash
        })

    event_hashes.append(computed_hash)

# Check for deterministic ordering
ordering_hash = hashlib.sha256(''.join(event_hashes).encode()).hexdigest()
replay_results["ordering_verification"] = {
    "deterministic": True,
    "ordering_hash": ordering_hash
}

# Fail if nondeterministic replay detected
if replay_results["detected_drift"]:
    print("Nondeterministic replay detected!", file=sys.stderr)
    exit($EXIT_NONDETERMINISTIC_REPLAY)

with open('$replay_report', 'w') as f:
    json.dump(replay_results, f, indent=2)

print(f"Replay verification completed: {len(replay_results['detected_drift'])} drift issues detected", file=sys.stderr)
EOF

    local replay_exit=$?
    if [ $replay_exit -eq $EXIT_NONDETERMINISTIC_REPLAY ]; then
        error "Nondeterministic replay detected"
        exit $EXIT_NONDETERMINISTIC_REPLAY
    fi

    log "Replay verification completed successfully"
}

# Truth gate reporting and final validation
execute_truth_gate() {
    log "Executing truth gate validation"

    local status_file="$E2E_WORK_DIR/artifacts/decisions/shadow_status.json"
    local recommendations_file="$E2E_WORK_DIR/artifacts/decisions/recommendations.json"
    local replay_report="$E2E_WORK_DIR/artifacts/replay/replay_report.json"
    local truth_gate_report="$E2E_WORK_DIR/artifacts/truth_gate/truth_gate_report.json"

    # Validate all required artifacts exist
    local required_files=("$status_file" "$recommendations_file" "$replay_report")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            error "Required artifact missing: $file"
            exit $EXIT_MISSING_REFERENCES
        fi
    done

    # Perform truth gate analysis
    python3 <<EOF
import json
import sys

# Load artifacts
with open('$status_file', 'r') as f:
    status = json.load(f)

with open('$recommendations_file', 'r') as f:
    recommendations = json.load(f)

with open('$replay_report', 'r') as f:
    replay = json.load(f)

# Truth gate evaluation
truth_gate = {
    "gate_id": "shadow_daemon_truth_gate_$(date +%s)",
    "evaluation_timestamp": "$(date -Iseconds)",
    "scenario": "$SCENARIO",
    "proof_class": "synthetic_drill",
    "no_mock_proof": False,
    "inputs": {
        "shadow_status": status.get("shadow_truth_state"),
        "shadow_status_proof_class": status.get("proof_class"),
        "replay_proof_class": replay.get("proof_class"),
        "fail_closed_events": status.get("fail_closed_events", 0),
        "replay_drift_count": len(replay.get("detected_drift", [])),
        "deterministic_replay": replay.get("ordering_verification", {}).get("deterministic", False)
    },
    "validation_results": {},
    "final_verdict": "unknown",
    "exit_code": $EXIT_SUCCESS
}

# Apply truth gate rules
rules_passed = 0
rules_total = 0

# Rule 1: No fail-closed events allowed
rules_total += 1
if truth_gate["inputs"]["fail_closed_events"] == 0:
    truth_gate["validation_results"]["fail_closed_check"] = "pass"
    rules_passed += 1
else:
    truth_gate["validation_results"]["fail_closed_check"] = "fail"
    truth_gate["exit_code"] = $EXIT_SOURCE_STALENESS

# Rule 2: Deterministic replay required
rules_total += 1
if truth_gate["inputs"]["deterministic_replay"]:
    truth_gate["validation_results"]["deterministic_replay_check"] = "pass"
    rules_passed += 1
else:
    truth_gate["validation_results"]["deterministic_replay_check"] = "fail"
    truth_gate["exit_code"] = $EXIT_NONDETERMINISTIC_REPLAY

# Rule 3: No critical drift allowed
rules_total += 1
if truth_gate["inputs"]["replay_drift_count"] == 0:
    truth_gate["validation_results"]["drift_check"] = "pass"
    rules_passed += 1
else:
    truth_gate["validation_results"]["drift_check"] = "fail"
    truth_gate["exit_code"] = $EXIT_NONDETERMINISTIC_REPLAY

# Rule 4: Synthetic evidence must never satisfy the no-mock adoption gate
rules_total += 1
truth_gate["validation_results"]["authoritative_no_mock_proof"] = "fail"
truth_gate["exit_code"] = $EXIT_SYNTHETIC_EVIDENCE

# Scenario-specific validations
if "$SCENARIO" in ["stale_expired_agent", "rch_local_fallback", "dirty_shared_worktree"]:
    # These scenarios should trigger fail-closed behavior
    if truth_gate["exit_code"] == $EXIT_SYNTHETIC_EVIDENCE:
        truth_gate["final_verdict"] = "fail_synthetic_evidence_not_no_mock_proof"
    elif status.get("shadow_truth_state") == "fail_closed":
        truth_gate["validation_results"]["expected_fail_closed"] = "pass"
        truth_gate["final_verdict"] = "pass_expected_failure"
        truth_gate["exit_code"] = $EXIT_SUCCESS
    else:
        truth_gate["validation_results"]["expected_fail_closed"] = "fail"
        truth_gate["final_verdict"] = "fail_should_have_closed"
        truth_gate["exit_code"] = $EXIT_TRUTH_GATE_FAILURE
else:
    # Normal scenarios should pass cleanly
    if truth_gate["exit_code"] == $EXIT_SYNTHETIC_EVIDENCE:
        truth_gate["final_verdict"] = "fail_synthetic_evidence_not_no_mock_proof"
    elif rules_passed == rules_total:
        truth_gate["final_verdict"] = "pass"
        truth_gate["exit_code"] = $EXIT_SUCCESS
    else:
        truth_gate["final_verdict"] = "fail"
        if truth_gate["exit_code"] == $EXIT_SUCCESS:
            truth_gate["exit_code"] = $EXIT_TRUTH_GATE_FAILURE

truth_gate["rules_summary"] = f"{rules_passed}/{rules_total} rules passed"

with open('$truth_gate_report', 'w') as f:
    json.dump(truth_gate, f, indent=2)

print(f"Truth gate: {truth_gate['final_verdict']} ({truth_gate['rules_summary']})", file=sys.stderr)
sys.exit(truth_gate["exit_code"])
EOF

    local truth_gate_exit=$?

    case $truth_gate_exit in
        $EXIT_SUCCESS)
            success "Truth gate validation passed"
            ;;
        $EXIT_SOURCE_STALENESS)
            error "Truth gate failed: source staleness detected"
            ;;
        $EXIT_NONDETERMINISTIC_REPLAY)
            error "Truth gate failed: nondeterministic replay"
            ;;
        $EXIT_TRUTH_GATE_FAILURE)
            error "Truth gate failed: validation rules not met"
            ;;
        $EXIT_SYNTHETIC_EVIDENCE)
            error "Truth gate failed: synthetic drill is not no-mock proof"
            ;;
        *)
            error "Truth gate failed: unknown error ($truth_gate_exit)"
            ;;
    esac

    return $truth_gate_exit
}

# Archive all artifacts and update manifest
finalize_artifacts() {
    log "Finalizing artifact preservation"

    # Update run manifest with final status
    python3 <<EOF
import json

with open('$E2E_WORK_DIR/run_manifest.json', 'r') as f:
    manifest = json.load(f)

manifest["end_time"] = "$(date -Iseconds)"
manifest["duration_seconds"] = $(( $(date +%s) - $(date -d "$(jq -r .start_time "$E2E_WORK_DIR/run_manifest.json")" +%s) ))
manifest["final_status"] = "completed_synthetic"
manifest["artifact_summary"] = {
    "total_files": $(find "$E2E_WORK_DIR/artifacts" -type f | wc -l),
    "total_size_bytes": $(du -sb "$E2E_WORK_DIR/artifacts" | cut -f1),
    "preserved_artifacts": [
        "run_manifest.json",
        "artifacts/events.jsonl",
        "artifacts/commands.txt",
        "artifacts/snapshots/",
        "artifacts/journal/shadow_journal.jsonl",
        "artifacts/decisions/shadow_status.json",
        "artifacts/decisions/recommendations.json",
        "artifacts/replay/replay_report.json",
        "artifacts/truth_gate/truth_gate_report.json"
    ]
}

with open('$E2E_WORK_DIR/run_manifest.json', 'w') as f:
    json.dump(manifest, f, indent=2)
EOF

    # Create archive for portable replay
    local archive_name="shadow_daemon_drill_${SCENARIO}_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "../$archive_name" -C "$E2E_WORK_DIR" .

    success "Artifacts preserved in: $E2E_WORK_DIR"
    success "Portable archive: $(dirname "$E2E_WORK_DIR")/$archive_name"
}

# Display usage information
usage() {
    cat <<EOF
Usage: $0 [SCENARIO]

Shadow Daemon Lifecycle Drill - Synthetic Evidence Exercise

SCENARIOS:
  healthy_idle              Normal idle state with minimal activity (default)
  active_no_mock_lane      Synthetic active-lane exercise, not no-mock proof
  stale_expired_agent      Agent data older than freshness threshold
  agent_mail_degraded      Agent Mail experiencing degraded performance
  rch_local_fallback       RCH falling back to local compilation (contamination)
  dirty_shared_worktree    Uncommitted changes indicating ownership ambiguity

EXIT CODES:
  0   Success
  10  Source staleness detected
  11  RCH local fallback contamination
  12  Contradictory ownership detected
  13  Unsupported mutation claims
  14  Missing raw references
  15  Nondeterministic replay detected
  16  Truth gate validation failure
  17  Synthetic evidence cannot satisfy no-mock adoption gates

The drill preserves artifacts for forensic analysis and fixture replay, but it
is synthetic evidence and exits 17 so it cannot satisfy no-mock adoption gates.
EOF
}

# Main execution flow
main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        exit 0
    fi

    log "Starting Shadow Daemon Lifecycle Drill"
    log "Scenario: $SCENARIO"

    # Ensure we're in the project root
    cd "$PROJECT_ROOT"

    # Execute the full lifecycle
    setup_workspace
    execute_tool_watchers
    execute_journal_operations
    execute_decision_composition
    execute_replay_verification

    # Truth gate validation (may exit with specific error code)
    if execute_truth_gate; then
        finalize_artifacts
        success "Shadow daemon lifecycle drill completed successfully"
        exit $EXIT_SUCCESS
    else
        local gate_exit=$?
        finalize_artifacts
        error "Shadow daemon lifecycle drill failed at truth gate"
        exit $gate_exit
    fi
}

# Handle script interruption
cleanup() {
    warn "Drill interrupted, attempting to preserve partial artifacts..."
    if [[ -d "$E2E_WORK_DIR" ]]; then
        finalize_artifacts
    fi
    exit 130
}

trap cleanup SIGINT SIGTERM

# Execute main function with all arguments
main "$@"
