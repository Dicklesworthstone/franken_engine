#!/usr/bin/env bash
#
# Emergency Rollback Script - RGC-902
# Purpose: Immediate rollback to previous known-good version
# Target: Complete rollback within 10 minutes
#

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/../.." && pwd)"

log() {
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') EMERGENCY_ROLLBACK: $*" | tee -a /var/log/franken-rollback.log
}

rollback_start_time=$(date +%s)
log "EMERGENCY ROLLBACK INITIATED"

# Capture current state for forensics
current_version=$(frankenctl version 2>/dev/null || echo "unknown")
log "Current version before rollback: $current_version"

# Step 1: Stop all FrankenEngine processes
log "Step 1: Stopping all FrankenEngine processes"
systemctl stop franken-engine 2>/dev/null || true
pkill -f frankenctl 2>/dev/null || true
pkill -f franken-engine 2>/dev/null || true
sleep 2

# Step 2: Switch to previous known-good version
previous_version_file="/etc/franken-engine/previous-good-version"
if [[ -f "$previous_version_file" ]]; then
    previous_version=$(cat "$previous_version_file")
    log "Rolling back to previous version: $previous_version"
else
    log "WARNING: No previous version recorded, attempting binary swap"
    previous_version="unknown-previous"
fi

# Step 3: Swap binaries (fail-safe approach)
log "Step 3: Swapping binary files"
if [[ -f "/usr/local/bin/frankenctl.previous" ]]; then
    # Backup current (failed) version
    cp /usr/local/bin/frankenctl /usr/local/bin/frankenctl.failed 2>/dev/null || true

    # Restore previous version
    cp /usr/local/bin/frankenctl.previous /usr/local/bin/frankenctl
    chmod +x /usr/local/bin/frankenctl
    log "Binary swap completed successfully"
else
    log "ERROR: Previous binary not found at /usr/local/bin/frankenctl.previous"
    log "CRITICAL: Cannot complete rollback - manual intervention required"
    exit 1
fi

# Step 4: Restart with previous version
log "Step 4: Restarting FrankenEngine with previous version"
systemctl start franken-engine 2>/dev/null || true
sleep 3

# Step 5: Verify rollback success
log "Step 5: Verifying rollback success"
rollback_success=false

if timeout 30 frankenctl version >/dev/null 2>&1; then
    rolled_back_version=$(frankenctl version)
    log "Rollback verification: version command successful"
    log "New version: $rolled_back_version"

    if timeout 60 frankenctl doctor --quick >/dev/null 2>&1; then
        log "Rollback verification: doctor command successful"
        rollback_success=true
    else
        log "ERROR: Doctor command failed after rollback"
    fi
else
    log "ERROR: Version command failed after rollback"
fi

# Calculate total rollback time
rollback_end_time=$(date +%s)
total_time=$((rollback_end_time - rollback_start_time))

if [[ "$rollback_success" == "true" ]]; then
    log "EMERGENCY ROLLBACK COMPLETED SUCCESSFULLY in ${total_time} seconds"
    log "Previous version: $current_version"
    log "Current version: $rolled_back_version"

    # Update system state
    echo "$(date -u)" > /var/lib/franken-engine/last-rollback-time
    echo "$current_version" > /var/lib/franken-engine/last-failed-version

    exit 0
else
    log "EMERGENCY ROLLBACK FAILED after ${total_time} seconds"
    log "CRITICAL: Manual intervention required immediately"
    log "Contact: Engineering Manager + Infrastructure Team"
    exit 1
fi