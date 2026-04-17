#!/bin/bash
# Gate replay runner for validation
# Usage: ./replay_gate.sh <gate_name>

set -euo pipefail

GATE_NAME="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/gates.toml"

if [[ -z "${GATE_NAME}" ]]; then
    echo "Usage: $0 <gate_name>" >&2
    echo "Available replay gates:" >&2
    grep '^\[gates\.' "${CONFIG_FILE}" | grep -A5 "^\[gates\..*_replay\]$" | grep '^\[gates\.' | sed 's/\[gates\.//;s/\]//' | sort
    exit 1
fi

# Parse gate config from TOML
GATE_SECTION="[gates.${GATE_NAME}]"
if ! grep -q "^${GATE_SECTION}$" "${CONFIG_FILE}"; then
    echo "Error: Gate '${GATE_NAME}' not found in configuration" >&2
    exit 1
fi

# Extract configuration values
extract_config() {
    local key="$1"
    local default="$2"
    local value=$(awk "/^${GATE_SECTION}$/,/^\[/ { if (/^${key} = /) { gsub(/^${key} = \"|\"$/, \"\"); print } }" "${CONFIG_FILE}")
    echo "${value:-${default}}"
}

extract_bool() {
    local key="$1"
    local default="$2"
    local value=$(awk "/^${GATE_SECTION}$/,/^\[/ { if (/^${key} = /) { gsub(/^${key} = /, \"\"); print } }" "${CONFIG_FILE}")
    echo "${value:-${default}}"
}

# Check if this is a replay gate
IS_REPLAY=$(extract_bool "is_replay" "false")
SOURCE_GATE=$(extract_config "replay_source_gate" "")
ARTIFACT_ROOT=$(extract_config "artifact_root" "")

if [[ "${IS_REPLAY}" != "true" ]]; then
    echo "Error: ${GATE_NAME} is not a replay gate" >&2
    echo "Use ./run_gate.sh for regular gate execution" >&2
    exit 1
fi

if [[ -z "${SOURCE_GATE}" ]]; then
    echo "Error: ${GATE_NAME} missing replay_source_gate configuration" >&2
    exit 1
fi

echo "Replaying gate: ${GATE_NAME} (source: ${SOURCE_GATE})"

# If no artifact_root specified, derive from source gate
if [[ -z "${ARTIFACT_ROOT}" ]]; then
    SOURCE_SECTION="[gates.${SOURCE_GATE}]"
    ARTIFACT_ROOT=$(awk "/^${SOURCE_SECTION}$/,/^\[/ { if (/^artifact_root = /) { gsub(/^artifact_root = \"|\"$/, \"\"); print } }" "${CONFIG_FILE}")
fi

if [[ -z "${ARTIFACT_ROOT}" ]]; then
    echo "Error: Could not determine artifact root for replay" >&2
    exit 1
fi

echo "Using artifact root: ${ARTIFACT_ROOT}"

if [[ ! -d "${ARTIFACT_ROOT}" ]]; then
    echo "Error: Source artifacts not found at ${ARTIFACT_ROOT}" >&2
    echo "Run source gate first: ./run_gate.sh ${SOURCE_GATE}" >&2
    exit 1
fi

cd "${ARTIFACT_ROOT}"

# Initialize replay events
echo "{\"event\": \"replay_start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"gate_name\": \"${GATE_NAME}\", \"source_gate\": \"${SOURCE_GATE}\"}" >> events.jsonl

# Validate core replay artifacts
echo "Validating replay artifacts..."
replay_valid=true
missing_artifacts=()

# Check required files
required_files=(
    "run_manifest.json"
    "events.jsonl"
    "commands.txt"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
        missing_artifacts+=("${file}")
        replay_valid=false
    fi
done

# Check directory structure
required_dirs=(
    "step_logs"
)

for dir in "${required_dirs[@]}"; do
    if [[ ! -d "${dir}" ]]; then
        missing_artifacts+=("${dir}/")
        replay_valid=false
    fi
done

if [[ "${replay_valid}" != "true" ]]; then
    echo "Error: Missing replay artifacts:" >&2
    printf '%s\n' "${missing_artifacts[@]}" >&2
    echo "{\"event\": \"replay_failed\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"reason\": \"missing_artifacts\", \"missing\": [$(printf '\"%s\",' "${missing_artifacts[@]}" | sed 's/,$//')]}" >> events.jsonl
    exit 1
fi

# Validate manifest structure
echo "Validating run manifest..."
if ! jq . run_manifest.json > /dev/null 2>&1; then
    echo "Error: run_manifest.json is not valid JSON" >&2
    echo "{\"event\": \"replay_failed\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"reason\": \"invalid_manifest\"}" >> events.jsonl
    exit 1
fi

# Extract key information from manifest
ORIGINAL_GATE=$(jq -r '.gate_name // "unknown"' run_manifest.json)
ORIGINAL_TIMESTAMP=$(jq -r '.timestamp // "unknown"' run_manifest.json)
ORIGINAL_EXIT_CODE=$(jq -r '.exit_code // "null"' run_manifest.json)

echo "Original gate: ${ORIGINAL_GATE}"
echo "Original timestamp: ${ORIGINAL_TIMESTAMP}"
echo "Original exit code: ${ORIGINAL_EXIT_CODE}"

# Validate events log
echo "Validating events log..."
event_count=$(wc -l < events.jsonl || echo "0")
echo "Events: ${event_count} entries"

if [[ ${event_count} -eq 0 ]]; then
    echo "Warning: Empty events log" >&2
fi

# Check for specific events that indicate successful execution
gate_start_events=$(grep -c '"event": "gate_start"' events.jsonl || echo "0")
gate_complete_events=$(grep -c '"event": "gate_complete"' events.jsonl || echo "0")

echo "Gate start events: ${gate_start_events}"
echo "Gate complete events: ${gate_complete_events}"

# Validate gate result if it exists
if [[ -f "gate_result.json" ]]; then
    echo "Validating gate result..."
    if jq . gate_result.json > /dev/null 2>&1; then
        VERDICT=$(jq -r '.verdict // "unknown"' gate_result.json)
        echo "Gate result verdict: ${VERDICT}"
    else
        echo "Warning: gate_result.json is not valid JSON" >&2
    fi
fi

# Check step logs
if [[ -f "step_logs/cargo_execution.log" ]]; then
    log_size=$(wc -c < step_logs/cargo_execution.log || echo "0")
    echo "Cargo execution log: ${log_size} bytes"
else
    echo "Warning: No cargo execution log found" >&2
fi

# Generate replay summary
cat > replay_summary.json <<EOF
{
  "replay_gate": "${GATE_NAME}",
  "source_gate": "${SOURCE_GATE}",
  "artifact_root": "${ARTIFACT_ROOT}",
  "replay_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "original_timestamp": "${ORIGINAL_TIMESTAMP}",
  "original_exit_code": ${ORIGINAL_EXIT_CODE},
  "event_count": ${event_count},
  "validation_status": "passed",
  "schema_version": "replay-summary.v1"
}
EOF

echo "{\"event\": \"replay_complete\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"gate_name\": \"${GATE_NAME}\", \"validation_status\": \"passed\"}" >> events.jsonl

echo "Replay validation successful"
echo "Artifacts validated:"
echo "  - Run manifest: ${ORIGINAL_GATE} (exit code: ${ORIGINAL_EXIT_CODE})"
echo "  - Events: ${event_count} entries"
echo "  - Step logs: available"
echo "  - Replay summary: replay_summary.json"

exit 0