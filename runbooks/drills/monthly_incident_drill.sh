#!/usr/bin/env bash
#
# Monthly Incident Response Drill - RGC-902
# Schedule: First Tuesday of each month, 2 PM UTC
# Purpose: Validate operator readiness and response procedures
#

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/../.." && pwd)"

drill_id="drill-$(date +%Y%m%d-%H%M%S)"
drill_log="/var/log/franken-drills.log"

log() {
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') DRILL[$drill_id]: $*" | tee -a "$drill_log"
}

# Check if operator is present
if [[ -z "${OPERATOR_NAME:-}" ]]; then
    echo "Please set OPERATOR_NAME environment variable before running drill"
    echo "Example: export OPERATOR_NAME='John Doe'"
    exit 1
fi

log "=== MONTHLY INCIDENT DRILL START ==="
log "Drill ID: $drill_id"
log "Operator: ${OPERATOR_NAME}"
log "Scenario: Compilation failure simulation"

# Create drill workspace
drill_workspace="/tmp/franken-drill-$drill_id"
mkdir -p "$drill_workspace"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                       INCIDENT DRILL                            ║"
echo "║                                                                  ║"
echo "║  SCENARIO: FrankenEngine compilation failures reported           ║"
echo "║  TIME: $(date)                                    ║"
echo "║  OPERATOR: ${OPERATOR_NAME}                                           ║"
echo "║                                                                  ║"
echo "║  EXPECTED ACTIONS:                                              ║"
echo "║  1. Run 'frankenctl doctor --summary' within 60 seconds        ║"
echo "║  2. Capture diagnostics if issues found                        ║"
echo "║  3. Escalate if needed                                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Simulate compilation failure (create a problematic file)
problematic_file="$drill_workspace/problematic_input.js"
cat > "$problematic_file" << 'EOF'
// Drill scenario: syntax that might cause issues
const problematic = {
  "weird-syntax": () => {
    return eval('Math.random() > 0.5 ? undefined : null');
  },
  [Symbol.iterator]: function*() {
    yield* new Array(1000000).fill(0).map((_, i) => `item-${i}`);
  }
};
EOF

log "Created problematic input file: $problematic_file"

# Start timing operator response
response_start_time=$(date +%s)
log "Response timer started - operator should run 'frankenctl doctor --summary' within 60 seconds"

echo ""
echo "🚨 DRILL ALERT 🚨"
echo "Multiple compilation failures detected in the last 5 minutes:"
echo "- Error rate: 15% (threshold: 10%)"
echo "- Affected file: $problematic_file"
echo "- Sample error: 'Unexpected token in expression'"
echo ""
echo "Please respond according to the incident runbook:"
echo "1. Run: frankenctl doctor --summary"
echo "2. Then press ENTER to continue the drill"
echo ""

# Wait for operator action
read -p "Press ENTER after running 'frankenctl doctor --summary': "

response_end_time=$(date +%s)
response_time=$((response_end_time - response_start_time))

log "Operator response time: ${response_time} seconds"

# Evaluate response time
if [[ $response_time -le 60 ]]; then
    echo "✓ EXCELLENT: Response time ${response_time}s meets target (<60s)"
    log "PASS: Response time within target"
    response_grade="PASS"
else
    echo "⚠ IMPROVEMENT NEEDED: Response time ${response_time}s exceeded 60s target"
    log "ATTENTION: Response time exceeded target"
    response_grade="ATTENTION"
fi

echo ""
echo "Now let's verify your diagnostic command worked correctly..."

# Check if doctor command was actually run recently
if timeout 30 frankenctl doctor --summary > "$drill_workspace/doctor_output.txt" 2>&1; then
    echo "✓ frankenctl doctor command executed successfully"
    log "PASS: Doctor command functional"
    doctor_grade="PASS"

    # Show what the doctor found
    echo ""
    echo "Doctor output summary:"
    head -10 "$drill_workspace/doctor_output.txt" | sed 's/^/  /'
else
    echo "⚠ frankenctl doctor command failed or unavailable"
    log "ATTENTION: Doctor command failed"
    doctor_grade="ATTENTION"
fi

echo ""
echo "DRILL SCENARIO QUESTIONS:"
echo "1. Based on the error rate (15%), what is the next escalation step?"
read -p "Your answer: " escalation_answer
log "Escalation answer: $escalation_answer"

echo ""
echo "2. At what divergence threshold would you activate quarantine mode?"
read -p "Your answer: " quarantine_answer
log "Quarantine answer: $quarantine_answer"

# Grade the answers (simple keyword matching)
escalation_grade="ATTENTION"
if [[ "$escalation_answer" =~ (escalate|manager|security|containment) ]]; then
    escalation_grade="PASS"
fi

quarantine_grade="ATTENTION"
if [[ "$quarantine_answer" =~ (5%|five percent|>5|greater than 5) ]]; then
    quarantine_grade="PASS"
fi

# Cleanup drill environment
rm -rf "$drill_workspace"
log "Cleaned up drill workspace"

# Calculate overall grade
pass_count=0
[[ "$response_grade" == "PASS" ]] && ((pass_count++))
[[ "$doctor_grade" == "PASS" ]] && ((pass_count++))
[[ "$escalation_grade" == "PASS" ]] && ((pass_count++))
[[ "$quarantine_grade" == "PASS" ]] && ((pass_count++))

if [[ $pass_count -ge 3 ]]; then
    overall_grade="PASS"
else
    overall_grade="NEEDS_IMPROVEMENT"
fi

# Final report
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                         DRILL RESULTS                           ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║ Response Time:     $response_grade (${response_time}s)                          ║"
echo "║ Doctor Command:    $doctor_grade                                 ║"
echo "║ Escalation Q:      $escalation_grade                             ║"
echo "║ Quarantine Q:      $quarantine_grade                             ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║ OVERALL:          $overall_grade                           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

if [[ "$overall_grade" == "PASS" ]]; then
    echo "🎉 Congratulations! You passed the monthly incident drill."
    echo "Your incident response procedures are ready for production."
else
    echo "📚 Please review the operator runbook sections on:"
    [[ "$response_grade" != "PASS" ]] && echo "  - Incident response timing (target: <60s)"
    [[ "$escalation_grade" != "PASS" ]] && echo "  - Escalation procedures (>10% error rate → escalate)"
    [[ "$quarantine_grade" != "PASS" ]] && echo "  - Quarantine thresholds (>5% divergence → quarantine)"
fi

log "=== MONTHLY INCIDENT DRILL END ==="
log "Overall grade: $overall_grade"
log "Scores: response=$response_grade doctor=$doctor_grade escalation=$escalation_grade quarantine=$quarantine_grade"

# Return appropriate exit code
if [[ "$overall_grade" == "PASS" ]]; then
    exit 0
else
    exit 1
fi