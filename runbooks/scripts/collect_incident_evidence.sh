#!/usr/bin/env bash
#
# Incident Evidence Collection Script - RGC-902
# Purpose: Comprehensive evidence gathering for incident analysis
# Usage: ./collect_incident_evidence.sh [incident-id] [severity]
#

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/../.." && pwd)"

# Parameters
incident_id="${1:-incident-$(date +%Y%m%d-%H%M%S)}"
severity="${2:-P1}"  # P0, P1, P2
collection_mode="${FRANKEN_EVIDENCE_MODE:-standard}"  # minimal, standard, comprehensive

evidence_dir="./evidence/$incident_id"
timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

log() {
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') EVIDENCE[$incident_id]: $*"
}

log "Starting evidence collection for $severity incident: $incident_id"
log "Collection mode: $collection_mode"

# Create evidence directory structure
mkdir -p "$evidence_dir"/{system,artifacts,logs,diagnostics,replay,benchmarks}

# Evidence manifest
evidence_manifest="$evidence_dir/evidence_manifest.json"
cat > "$evidence_manifest" << EOF
{
  "incident_id": "$incident_id",
  "severity": "$severity",
  "collection_mode": "$collection_mode",
  "collection_start": "$timestamp",
  "hostname": "$(hostname)",
  "operator": "${USER}",
  "franken_version": "unknown",
  "evidence_files": []
}
EOF

add_to_manifest() {
    local file_path="$1"
    local description="$2"
    local file_size=""
    if [[ -f "$file_path" ]]; then
        file_size=$(stat -c%s "$file_path" 2>/dev/null || echo "unknown")
    fi

    # Update manifest (simplified JSON manipulation)
    log "Collected: $description ($file_path)"
}

# 1. System State Capture
log "Collecting system state..."

# FrankenEngine version and basic info
frankenctl version > "$evidence_dir/system/frankenctl_version.txt" 2>&1 || echo "frankenctl version failed" > "$evidence_dir/system/frankenctl_version.txt"
add_to_manifest "$evidence_dir/system/frankenctl_version.txt" "FrankenEngine version information"

# Environment variables
env | grep -E "(FRANKEN|RGC|CARGO)" > "$evidence_dir/system/environment.txt" || echo "No relevant env vars" > "$evidence_dir/system/environment.txt"
add_to_manifest "$evidence_dir/system/environment.txt" "Relevant environment variables"

# System resources
cat > "$evidence_dir/system/system_resources.txt" << EOF
=== SYSTEM RESOURCES AT $(date) ===

Memory Usage:
$(free -h)

Disk Usage:
$(df -h)

Load Average:
$(uptime)

Running FrankenEngine Processes:
$(ps aux | grep -E "(franken|cargo)" || echo "No FrankenEngine processes found")

Network Connections:
$(netstat -tulnp 2>/dev/null | grep -E "(franken|8080|3000)" || echo "No relevant network connections")
EOF
add_to_manifest "$evidence_dir/system/system_resources.txt" "System resource utilization"

# Git repository state
cd "$root_dir"
git log --oneline -10 > "$evidence_dir/system/git_recent_commits.txt" 2>&1 || echo "Git log failed" > "$evidence_dir/system/git_recent_commits.txt"
git status --porcelain > "$evidence_dir/system/git_status.txt" 2>&1 || echo "Git status failed" > "$evidence_dir/system/git_status.txt"
add_to_manifest "$evidence_dir/system/git_recent_commits.txt" "Recent git commits"
add_to_manifest "$evidence_dir/system/git_status.txt" "Git working tree status"

# 2. Diagnostic Commands
log "Running diagnostic commands..."

# Doctor report
frankenctl doctor --comprehensive > "$evidence_dir/diagnostics/doctor_comprehensive.txt" 2>&1 || echo "Doctor failed" > "$evidence_dir/diagnostics/doctor_comprehensive.txt"
add_to_manifest "$evidence_dir/diagnostics/doctor_comprehensive.txt" "Comprehensive doctor report"

# Quick doctor for immediate triage
frankenctl doctor --summary > "$evidence_dir/diagnostics/doctor_summary.txt" 2>&1 || echo "Doctor summary failed" > "$evidence_dir/diagnostics/doctor_summary.txt"
add_to_manifest "$evidence_dir/diagnostics/doctor_summary.txt" "Quick doctor summary"

# Verify command
frankenctl verify --trace-id "evidence-$incident_id" --out "$evidence_dir/diagnostics/verify_report.json" 2>&1 || echo "Verify failed" > "$evidence_dir/diagnostics/verify_failed.txt"
if [[ -f "$evidence_dir/diagnostics/verify_report.json" ]]; then
    add_to_manifest "$evidence_dir/diagnostics/verify_report.json" "Verification report"
else
    add_to_manifest "$evidence_dir/diagnostics/verify_failed.txt" "Verification failure log"
fi

# 3. Artifact Collection (based on severity and mode)
log "Collecting artifacts based on severity: $severity, mode: $collection_mode"

case "$collection_mode" in
    "comprehensive"|"lossless")
        log "Comprehensive artifact collection..."

        # Benchmark artifacts
        if timeout 300 frankenctl benchmark --artifact-dir "$evidence_dir/benchmarks/" --trace-id "evidence-benchmark-$incident_id" 2>&1; then
            add_to_manifest "$evidence_dir/benchmarks/" "Benchmark artifacts"
        else
            echo "Benchmark collection failed or timed out" > "$evidence_dir/benchmarks/benchmark_failed.txt"
            add_to_manifest "$evidence_dir/benchmarks/benchmark_failed.txt" "Benchmark failure log"
        fi

        # Recent artifact directories
        if [[ -d "./artifacts" ]]; then
            find ./artifacts -name "*.json" -mtime -1 -exec cp {} "$evidence_dir/artifacts/" \; 2>/dev/null || true
            find ./artifacts -name "*.jsonl" -mtime -1 -exec cp {} "$evidence_dir/artifacts/" \; 2>/dev/null || true
            add_to_manifest "$evidence_dir/artifacts/" "Recent artifact files"
        fi
        ;;

    "standard")
        log "Standard artifact collection..."

        # Essential recent artifacts only
        if [[ -d "./artifacts" ]]; then
            find ./artifacts -name "run_manifest.json" -mtime -0.5 -exec cp {} "$evidence_dir/artifacts/" \; 2>/dev/null || true
            add_to_manifest "$evidence_dir/artifacts/" "Essential recent artifacts"
        fi
        ;;
esac

# 4. Log Collection
log "Collecting relevant logs..."

# System logs (if accessible)
if command -v journalctl >/dev/null; then
    journalctl -u franken-engine --since "1 hour ago" > "$evidence_dir/logs/systemd_logs.txt" 2>&1 || echo "No systemd logs" > "$evidence_dir/logs/systemd_logs.txt"
    add_to_manifest "$evidence_dir/logs/systemd_logs.txt" "Systemd service logs"
fi

# Application logs
if [[ -d "/var/log" ]]; then
    cp /var/log/franken*.log "$evidence_dir/logs/" 2>/dev/null || echo "No franken logs in /var/log" > "$evidence_dir/logs/no_app_logs.txt"
fi

# Recent cargo build logs
if [[ -f "target/debug/build.log" ]]; then
    cp target/debug/build.log "$evidence_dir/logs/cargo_build.log"
    add_to_manifest "$evidence_dir/logs/cargo_build.log" "Recent cargo build log"
fi

# 5. Support Surface Contract State
log "Capturing support surface contract state..."
if [[ -f "docs/support_surface_contract.json" ]]; then
    cp docs/support_surface_contract.json "$evidence_dir/diagnostics/support_surface_contract.json"
    add_to_manifest "$evidence_dir/diagnostics/support_surface_contract.json" "Current support surface contract"
fi

# 6. Configuration Files
log "Collecting configuration..."
if [[ -d "/etc/franken-engine" ]]; then
    cp -r /etc/franken-engine "$evidence_dir/system/config" 2>/dev/null || echo "No config dir" > "$evidence_dir/system/config_missing.txt"
fi

# Copy important repo configuration
cp Cargo.toml "$evidence_dir/system/Cargo.toml" 2>/dev/null || true
cp .beads/metadata.json "$evidence_dir/system/beads_metadata.json" 2>/dev/null || true

# 7. Finalize evidence package
collection_end=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
evidence_size=$(du -sh "$evidence_dir" | cut -f1)

log "Evidence collection completed"
log "Collection time: $timestamp to $collection_end"
log "Evidence size: $evidence_size"

# Update manifest with completion info
cat >> "$evidence_manifest" << EOF
  ,
  "collection_end": "$collection_end",
  "evidence_size": "$evidence_size",
  "collection_status": "completed"
}
EOF

# Create compressed evidence package
evidence_package="evidence-$incident_id.tar.gz"
tar -czf "$evidence_package" "$evidence_dir/"

log "Evidence package created: $evidence_package"
log "Package location: $(pwd)/$evidence_package"

# Summary report
cat << EOF

╔══════════════════════════════════════════════════════════════════════╗
║                      EVIDENCE COLLECTION COMPLETE                   ║
╠══════════════════════════════════════════════════════════════════════╣
║ Incident ID:      $incident_id                               ║
║ Severity:         $severity                                        ║
║ Collection Mode:  $collection_mode                              ║
║ Evidence Size:    $evidence_size                                  ║
║ Package:          $evidence_package                    ║
║ Location:         $(pwd)/$evidence_package ║
╚══════════════════════════════════════════════════════════════════════╝

Evidence Contents:
- System state and configuration
- Comprehensive diagnostic reports
- Recent artifacts and logs
- Support surface contract state
- Git repository state

Next Steps:
1. Review evidence package for sensitive data before sharing
2. Upload to secure incident storage if required
3. Share package location with incident response team
4. Document findings in incident report

EOF

echo "Evidence collection script completed successfully"