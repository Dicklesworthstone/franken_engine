#!/bin/bash
# Parameterized gate runner using gates.toml configuration
# Usage: ./run_gate.sh <gate_name> [mode]

set -euo pipefail

GATE_NAME="${1:-}"
MODE="${2:-ci}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/gates.toml"

if [[ -z "${GATE_NAME}" ]]; then
    echo "Usage: $0 <gate_name> [mode]" >&2
    echo "Available gates:" >&2
    grep '^\[gates\.' "${CONFIG_FILE}" | sed 's/\[gates\.//;s/\]//' | sort
    exit 1
fi

# Parse gate config from TOML (basic parsing)
GATE_SECTION="[gates.${GATE_NAME}]"
if ! grep -q "^${GATE_SECTION}$" "${CONFIG_FILE}"; then
    echo "Error: Gate '${GATE_NAME}' not found in configuration" >&2
    exit 1
fi

# Extract configuration values using awk
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

extract_int() {
    local key="$1"
    local default="$2"
    local value=$(awk "/^${GATE_SECTION}$/,/^\[/ { if (/^${key} = /) { gsub(/^${key} = /, \"\"); print } }" "${CONFIG_FILE}")
    echo "${value:-${default}}"
}

# Read gate configuration
ARTIFACT_ROOT=$(extract_config "artifact_root" "artifacts/${GATE_NAME}")
CARGO_COMMAND=$(extract_config "cargo_command" "cargo test -p frankenengine-engine --lib ${GATE_NAME}")
NEEDS_RCH=$(extract_bool "needs_rch" "true")
RCH_TIMEOUT=$(extract_int "rch_timeout_seconds" "900")
ENV_BOOTSTRAP=$(extract_config "env_bootstrap" "")
INPUT_FIXTURE=$(extract_config "input_fixture" "")
GENERATES_GATE_RESULT=$(extract_bool "generates_gate_result" "false")
GENERATES_MANIFEST=$(extract_bool "generates_manifest" "false")

# Read global defaults
DEFAULT_TARGET_DIR_PREFIX=$(awk '/^\[global\]$/,/^\[/ { if (/^default_target_dir_prefix = /) { gsub(/^default_target_dir_prefix = \"|\"$/, \"\"); print } }' "${CONFIG_FILE}")
TARGET_DIR_PREFIX="${TARGET_DIR_PREFIX:-${DEFAULT_TARGET_DIR_PREFIX:-/tmp/rch_target_franken_engine}}"

echo "Running gate: ${GATE_NAME}"
echo "Mode: ${MODE}"
echo "Artifact root: ${ARTIFACT_ROOT}"
echo "Needs RCH: ${NEEDS_RCH}"
echo "RCH timeout: ${RCH_TIMEOUT}s"

# Create artifact directory
mkdir -p "${ARTIFACT_ROOT}"
cd "${ARTIFACT_ROOT}"

# Initialize run manifest
cat > run_manifest.json <<EOF
{
  "gate_name": "${GATE_NAME}",
  "mode": "${MODE}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "artifact_root": "${ARTIFACT_ROOT}",
  "cargo_command": "${CARGO_COMMAND}",
  "needs_rch": ${NEEDS_RCH},
  "rch_timeout_seconds": ${RCH_TIMEOUT}
}
EOF

# Initialize events log
echo "{\"event\": \"gate_start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"gate_name\": \"${GATE_NAME}\"}" > events.jsonl

# Initialize commands file
echo "# Gate: ${GATE_NAME}" > commands.txt
echo "# Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> commands.txt

# Create step logs directory
mkdir -p step_logs rch_step_logs

# Run environment bootstrap if specified
if [[ -n "${ENV_BOOTSTRAP}" && -f "${SCRIPT_DIR}/${ENV_BOOTSTRAP}" ]]; then
    echo "Running environment bootstrap: ${ENV_BOOTSTRAP}"
    echo "{\"event\": \"env_bootstrap_start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"script\": \"${ENV_BOOTSTRAP}\"}" >> events.jsonl

    # Source the bootstrap script
    set +e
    source "${SCRIPT_DIR}/${ENV_BOOTSTRAP}"
    bootstrap_exit_code=$?
    set -e

    echo "{\"event\": \"env_bootstrap_complete\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"exit_code\": ${bootstrap_exit_code}}" >> events.jsonl
    echo "source ${SCRIPT_DIR}/${ENV_BOOTSTRAP} # exit_code: ${bootstrap_exit_code}" >> commands.txt

    if [[ ${bootstrap_exit_code} -ne 0 ]]; then
        echo "Environment bootstrap failed with exit code ${bootstrap_exit_code}" >&2
        exit ${bootstrap_exit_code}
    fi
fi

# Copy input fixture if specified
if [[ -n "${INPUT_FIXTURE}" && -f "${SCRIPT_DIR}/../${INPUT_FIXTURE}" ]]; then
    echo "Copying input fixture: ${INPUT_FIXTURE}"
    cp "${SCRIPT_DIR}/../${INPUT_FIXTURE}" "./$(basename "${INPUT_FIXTURE}")"
    echo "cp ${SCRIPT_DIR}/../${INPUT_FIXTURE} ./$(basename "${INPUT_FIXTURE}")" >> commands.txt
fi

# Execute cargo command
echo "{\"event\": \"cargo_start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"command\": \"${CARGO_COMMAND}\"}" >> events.jsonl

set +e
if [[ "${NEEDS_RCH}" == "true" ]]; then
    echo "Executing via RCH (timeout ${RCH_TIMEOUT}s): ${CARGO_COMMAND}"
    echo "timeout ${RCH_TIMEOUT} rch exec \"${CARGO_COMMAND}\"" >> commands.txt

    timeout "${RCH_TIMEOUT}" rch exec "${CARGO_COMMAND}" 2>&1 | tee step_logs/cargo_execution.log
    cargo_exit_code=${PIPESTATUS[0]}
else
    echo "Executing locally: ${CARGO_COMMAND}"
    echo "${CARGO_COMMAND}" >> commands.txt

    eval "${CARGO_COMMAND}" 2>&1 | tee step_logs/cargo_execution.log
    cargo_exit_code=${PIPESTATUS[0]}
fi
set -e

echo "{\"event\": \"cargo_complete\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"exit_code\": ${cargo_exit_code}}" >> events.jsonl

# Generate gate result if configured
if [[ "${GENERATES_GATE_RESULT}" == "true" ]]; then
    if [[ ${cargo_exit_code} -eq 0 ]]; then
        verdict="Approved"
    else
        verdict="Rejected"
    fi

    cat > gate_result.json <<EOF
{
  "verdict": "${verdict}",
  "gate_id": "${GATE_NAME}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "exit_code": ${cargo_exit_code},
  "schema_version": "gate-result.v1",
  "component": "parameterized_gate_runner"
}
EOF
fi

# Update run manifest with final status
jq --arg exit_code "${cargo_exit_code}" \
   --arg end_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
   '. + {exit_code: ($exit_code | tonumber), end_timestamp: $end_time}' \
   run_manifest.json > run_manifest.json.tmp && mv run_manifest.json.tmp run_manifest.json

echo "{\"event\": \"gate_complete\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"gate_name\": \"${GATE_NAME}\", \"exit_code\": ${cargo_exit_code}}" >> events.jsonl

if [[ ${cargo_exit_code} -eq 0 ]]; then
    echo "Gate ${GATE_NAME} completed successfully"
else
    echo "Gate ${GATE_NAME} failed with exit code ${cargo_exit_code}" >&2
    exit ${cargo_exit_code}
fi