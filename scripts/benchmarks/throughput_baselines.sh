#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKLOAD_DIR="${THROUGHPUT_BASELINES_WORKLOAD_DIR:-$SCRIPT_DIR/workloads}"
OUTPUT_FILE="${THROUGHPUT_BASELINES_OUTPUT_FILE:-$PROJECT_ROOT/docs/throughput_baseline_measurements_v1.json}"
ARTIFACT_ROOT="${THROUGHPUT_BASELINES_ARTIFACT_ROOT:-$PROJECT_ROOT/artifacts/throughput_baselines}"
RUN_ID="${THROUGHPUT_BASELINES_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
GENERATED_AT="${THROUGHPUT_BASELINES_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
MEASUREMENT_DURATION_MS=1000

NODE_BIN_OVERRIDE="${THROUGHPUT_BASELINES_NODE_BIN-__AUTO__}"
BUN_BIN_OVERRIDE="${THROUGHPUT_BASELINES_BUN_BIN-__AUTO__}"
FRANKENCTL_BIN="${THROUGHPUT_BASELINES_FRANKENCTL_BIN:-$PROJECT_ROOT/target/debug/frankenctl}"
FRANKENENGINE_CMD_TEMPLATE="${THROUGHPUT_BASELINES_FRANKENENGINE_CMD:-}"

RUN_DIR="$ARTIFACT_ROOT/$RUN_ID"
MANIFEST_PATH="$RUN_DIR/throughput_baseline_measurements_v1.json"
RUN_MANIFEST_PATH="$RUN_DIR/run_manifest.json"
EVENTS_PATH="$RUN_DIR/events.jsonl"
COMMANDS_PATH="$RUN_DIR/commands.txt"
SUMMARY_PATH="$RUN_DIR/summary.md"

WORKLOADS=("fibonacci" "strings" "arrays" "objects" "functions")

mkdir -p "$RUN_DIR"
: >"$EVENTS_PATH"
: >"$COMMANDS_PATH"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi
if ! command -v bc >/dev/null 2>&1; then
  echo "ERROR: bc is required" >&2
  exit 2
fi

printf './scripts/benchmarks/throughput_baselines.sh\n' >"$COMMANDS_PATH"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.throughput-baselines.event.v1" \
    --arg event "$1" \
    --arg detail "$2" \
    --arg run_id "$RUN_ID" \
    --arg generated_at "$GENERATED_AT" \
    '{
      schema_version: $schema_version,
      event: $event,
      detail: $detail,
      run_id: $run_id,
      generated_at: $generated_at
    }' >>"$EVENTS_PATH"
}

record_command() {
  printf '%s\n' "$1" >>"$COMMANDS_PATH"
}

resolve_runtime_bin() {
  local runtime="$1"
  local override="$2"
  shift 2
  local candidates=("$@")

  if [[ "$override" != "__AUTO__" ]]; then
    if [[ -x "$override" ]]; then
      printf '%s\n' "$override"
      return 0
    fi
    if command -v "$override" >/dev/null 2>&1; then
      command -v "$override"
      return 0
    fi
    return 1
  fi

  local candidate
  for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done

  return 1
}

compute_geometric_mean() {
  local values=("$@")
  local count=0
  local log_sum=0
  local value

  for value in "${values[@]}"; do
    if [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -gt 0 ]]; then
      log_sum="$(echo "scale=10; $log_sum + l($value)" | bc -l)"
      count=$((count + 1))
    fi
  done

  if [[ "$count" -eq 0 ]]; then
    echo "0"
    return 0
  fi

  echo "scale=0; e($log_sum / $count)" | bc -l | cut -d'.' -f1
}

runtime_version() {
  local binary="$1"
  if [[ ! -x "$binary" ]] && ! command -v "$binary" >/dev/null 2>&1; then
    echo "not-available"
    return 0
  fi
  record_command "$binary --version"
  "$binary" --version 2>/dev/null | head -n 1 || echo "unknown"
}

validate_measurement_output() {
  local output_path="$1"
  local workload="$2"

  jq -e --arg workload "$workload" '
    .workload == $workload
    and (.iterations | type == "number")
    and (.iterations > 0)
    and (.duration_ms | type == "number")
    and (.duration_ms > 0)
    and (.ops_per_second | type == "number")
    and (.ops_per_second > 0)
  ' "$output_path" >/dev/null
}

run_binary_workload() {
  local runtime="$1"
  local binary="$2"
  local workload="$3"
  local workload_file="$WORKLOAD_DIR/$workload.js"
  local runtime_dir="$RUN_DIR/$runtime"
  local stdout_path="$runtime_dir/$workload.stdout.log"
  local stderr_path="$runtime_dir/$workload.stderr.log"

  mkdir -p "$runtime_dir"
  record_command "$binary $workload_file"

  if ! "$binary" "$workload_file" >"$stdout_path" 2>"$stderr_path"; then
    return 1
  fi

  if ! jq empty "$stdout_path" >/dev/null 2>&1; then
    return 1
  fi

  validate_measurement_output "$stdout_path" "$workload"
}

run_frankenengine_workload() {
  local workload="$1"
  local workload_file="$WORKLOAD_DIR/$workload.js"
  local runtime_dir="$RUN_DIR/frankenengine"
  local stdout_path="$runtime_dir/$workload.stdout.log"
  local stderr_path="$runtime_dir/$workload.stderr.log"
  local command_text="$FRANKENENGINE_CMD_TEMPLATE"

  mkdir -p "$runtime_dir"

  if [[ -z "$command_text" ]]; then
    return 2
  fi

  command_text="${command_text//\{workload\}/$workload_file}"
  command_text="${command_text//\{frankenctl_bin\}/$FRANKENCTL_BIN}"
  record_command "$command_text"

  if ! bash -lc "$command_text" >"$stdout_path" 2>"$stderr_path"; then
    return 1
  fi

  if ! jq empty "$stdout_path" >/dev/null 2>&1; then
    return 1
  fi

  validate_measurement_output "$stdout_path" "$workload"
}

runtime_blocked_json() {
  local version="$1"
  local source="$2"
  local code="$3"
  local detail="$4"
  local remediation="$5"

  jq -nc \
    --arg version "$version" \
    --arg source "$source" \
    --arg code "$code" \
    --arg detail "$detail" \
    --arg remediation "$remediation" \
    '{
      version: $version,
      baseline_ops_per_second: 0,
      workload_results: {},
      measurement_status: "blocked",
      measurement_source: $source,
      observed_workload_count: 0,
      blockers: [
        {
          code: $code,
          detail: $detail,
          remediation: $remediation
        }
      ]
    }'
}

runtime_observed_json() {
  local version="$1"
  local source="$2"
  local results_json="$3"
  shift 3
  local values=("$@")
  local baseline

  baseline="$(compute_geometric_mean "${values[@]}")"

  jq -nc \
    --arg version "$version" \
    --arg source "$source" \
    --argjson baseline "$baseline" \
    --argjson workload_results "$results_json" \
    '{
      version: $version,
      baseline_ops_per_second: $baseline,
      workload_results: $workload_results,
      measurement_status: "observed",
      measurement_source: $source,
      observed_workload_count: ($workload_results | length),
      blockers: []
    }'
}

measure_runtime_with_binary() {
  local runtime="$1"
  local binary="$2"
  local version="$3"
  local results_json='{}'
  local values=()
  local workload

  for workload in "${WORKLOADS[@]}"; do
    if ! run_binary_workload "$runtime" "$binary" "$workload"; then
      write_event "runtime_blocked" "$runtime workload failed: $workload"
      runtime_blocked_json \
        "$version" \
        "$binary" \
        "runtime_execution_failed" \
        "$runtime failed to produce a valid observed measurement for workload $workload" \
        "Fix the runtime invocation or remove the runtime from the measurement set; placeholder ops/sec rows are forbidden."
      return 0
    fi

    local stdout_path="$RUN_DIR/$runtime/$workload.stdout.log"
    local ops
    ops="$(jq -r '.ops_per_second' "$stdout_path")"
    values+=("$ops")
    results_json="$(jq -nc --argjson existing "$results_json" --arg workload "$workload" --argjson ops "$ops" '$existing + {($workload): $ops}')"
  done

  runtime_observed_json "$version" "$binary" "$results_json" "${values[@]}"
}

measure_frankenengine_runtime() {
  local version="$1"
  local results_json='{}'
  local values=()
  local workload

  if [[ -z "$FRANKENENGINE_CMD_TEMPLATE" ]]; then
    runtime_blocked_json \
      "$version" \
      "${FRANKENCTL_BIN}" \
      "runner_not_configured" \
      "FrankenEngine throughput measurement requires THROUGHPUT_BASELINES_FRANKENENGINE_CMD and refuses placeholder ops/sec rows." \
      "Provide a real benchmark runner command such as an rch-backed prebuilt frankenctl measurement surface."
    return 0
  fi

  if [[ ! -x "$FRANKENCTL_BIN" ]]; then
    runtime_blocked_json \
      "not-available" \
      "${FRANKENCTL_BIN}" \
      "prebuilt_binary_missing" \
      "Prebuilt frankenctl binary not found; the script will not run bare cargo builds." \
      "Build frankenctl separately with rch or point THROUGHPUT_BASELINES_FRANKENCTL_BIN at a prebuilt binary."
    return 0
  fi

  for workload in "${WORKLOADS[@]}"; do
    local frankenengine_rc=0
    run_frankenengine_workload "$workload" || frankenengine_rc=$?
    if [[ "$frankenengine_rc" -ne 0 ]]; then
      local code="runtime_execution_failed"
      local detail="FrankenEngine failed to produce a valid observed measurement for workload $workload."
      local remediation="Fix the benchmark runner or leave the runtime blocked until a real execution surface is available."

      if [[ "$frankenengine_rc" -eq 2 ]]; then
        code="runner_not_configured"
        detail="FrankenEngine throughput measurement requires THROUGHPUT_BASELINES_FRANKENENGINE_CMD and refuses placeholder ops/sec rows."
        remediation="Provide a real benchmark runner command such as an rch-backed prebuilt frankenctl measurement surface."
      fi

      runtime_blocked_json "$version" "${FRANKENCTL_BIN}" "$code" "$detail" "$remediation"
      return 0
    fi

    local stdout_path="$RUN_DIR/frankenengine/$workload.stdout.log"
    local ops
    ops="$(jq -r '.ops_per_second' "$stdout_path")"
    values+=("$ops")
    results_json="$(jq -nc --argjson existing "$results_json" --arg workload "$workload" --argjson ops "$ops" '$existing + {($workload): $ops}')"
  done

  runtime_observed_json "$version" "${FRANKENCTL_BIN}" "$results_json" "${values[@]}"
}

echo "=== FrankenEngine Throughput Baseline Measurement ==="
echo "Workloads: $WORKLOAD_DIR"
echo "Run directory: $RUN_DIR"
echo "Output file: $OUTPUT_FILE"

node_json=""
bun_json=""
frankenengine_json=""

if node_bin="$(resolve_runtime_bin "node" "$NODE_BIN_OVERRIDE" nodejs node)"; then
  write_event "runtime_detected" "node runtime detected: $node_bin"
  node_json="$(measure_runtime_with_binary "node" "$node_bin" "$(runtime_version "$node_bin")")"
else
  write_event "runtime_blocked" "node runtime unavailable"
  node_json="$(runtime_blocked_json \
    "not-available" \
    "nodejs/node" \
    "runtime_unavailable" \
    "Node.js runtime unavailable; refusing placeholder ops/sec rows." \
    "Install Node.js or set THROUGHPUT_BASELINES_NODE_BIN to a runnable binary.")"
fi

if bun_bin="$(resolve_runtime_bin "bun" "$BUN_BIN_OVERRIDE" bun)"; then
  write_event "runtime_detected" "bun runtime detected: $bun_bin"
  bun_json="$(measure_runtime_with_binary "bun" "$bun_bin" "$(runtime_version "$bun_bin")")"
else
  write_event "runtime_blocked" "bun runtime unavailable"
  bun_json="$(runtime_blocked_json \
    "not-available" \
    "bun" \
    "runtime_unavailable" \
    "Bun runtime unavailable; refusing placeholder ops/sec rows." \
    "Install Bun or set THROUGHPUT_BASELINES_BUN_BIN to a runnable binary.")"
fi

frankenengine_version="not-available"
if [[ -x "$FRANKENCTL_BIN" ]]; then
  frankenengine_version="$(runtime_version "$FRANKENCTL_BIN")"
fi
frankenengine_json="$(measure_frankenengine_runtime "$frankenengine_version")"

workloads_json="$(printf '%s\n' "${WORKLOADS[@]}" | jq -R . | jq -s .)"
manifest_json="$(jq -nc \
  --arg schema_version "franken-engine.throughput-baselines.v1" \
  --arg generated_at "$GENERATED_AT" \
  --argjson measurement_duration_ms "$MEASUREMENT_DURATION_MS" \
  --argjson workloads "$workloads_json" \
  --argjson node "$node_json" \
  --argjson bun "$bun_json" \
  --argjson frankenengine "$frankenengine_json" \
  --arg output_file "$OUTPUT_FILE" \
  --arg run_manifest "$RUN_MANIFEST_PATH" \
  --arg events "$EVENTS_PATH" \
  --arg commands "$COMMANDS_PATH" \
  --arg summary "$SUMMARY_PATH" \
  '
  {
    schema_version: $schema_version,
    generated_at: $generated_at,
    measurement_duration_ms: $measurement_duration_ms,
    workloads: $workloads,
    runtimes: {
      node: $node,
      bun: $bun,
      frankenengine: $frankenengine
    }
  }
  | .has_live_measurements = (.runtimes.node.measurement_status == "observed" and .runtimes.bun.measurement_status == "observed")
  | .has_complete_runtime_measurements = (.runtimes.node.measurement_status == "observed" and .runtimes.bun.measurement_status == "observed" and .runtimes.frankenengine.measurement_status == "observed")
  | .observed_runtime_count = ([.runtimes.node, .runtimes.bun, .runtimes.frankenengine] | map(select(.measurement_status == "observed")) | length)
  | .blocked_runtime_count = ([.runtimes.node, .runtimes.bun, .runtimes.frankenengine] | map(select(.measurement_status == "blocked")) | length)
  | .blocker_count = ([.runtimes.node, .runtimes.bun, .runtimes.frankenengine] | map(.blockers | length) | add)
  | .decision = (
      if .runtimes.node.measurement_status != "observed" or .runtimes.bun.measurement_status != "observed" then
        "fail_closed"
      elif .runtimes.frankenengine.measurement_status != "observed" then
        "partial_blocked"
      else
        "pass"
      end
    )
  | .artifact_paths = {
      manifest_json: $output_file,
      run_manifest_json: $run_manifest,
      events_jsonl: $events,
      commands_txt: $commands,
      summary_md: $summary
    }
  | .notes = (
      if .decision == "pass" then
        "Observed measurements only."
      elif .decision == "partial_blocked" then
        "Observed Node/Bun denominator measurements preserved; blocked runtimes are explicit blocker artifacts."
      else
        "Fail-closed blocker bundle. No placeholder throughput measurements were emitted."
      end
    )')"

printf '%s\n' "$manifest_json" >"$MANIFEST_PATH"

jq -n \
  --arg schema_version "franken-engine.throughput-baselines.run-manifest.v1" \
  --arg run_id "$RUN_ID" \
  --arg generated_at "$GENERATED_AT" \
  --arg manifest_json "$MANIFEST_PATH" \
  --arg events_jsonl "$EVENTS_PATH" \
  --arg commands_txt "$COMMANDS_PATH" \
  --arg summary_md "$SUMMARY_PATH" \
  --arg decision "$(jq -r '.decision' "$MANIFEST_PATH")" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    decision: $decision,
    artifact_paths: {
      throughput_baseline_measurements_v1_json: $manifest_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      summary_md: $summary_md
    }
  }' >"$RUN_MANIFEST_PATH"

cat >"$SUMMARY_PATH" <<EOF
# Throughput Baseline Measurement

- decision: \`$(jq -r '.decision' "$MANIFEST_PATH")\`
- observed runtimes: \`$(jq -r '.observed_runtime_count' "$MANIFEST_PATH")\`
- blocked runtimes: \`$(jq -r '.blocked_runtime_count' "$MANIFEST_PATH")\`
- blocker count: \`$(jq -r '.blocker_count' "$MANIFEST_PATH")\`
- output manifest: \`$MANIFEST_PATH\`
EOF

decision="$(jq -r '.decision' "$MANIFEST_PATH")"
if [[ "$decision" != "fail_closed" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  cp "$MANIFEST_PATH" "$OUTPUT_FILE"
  write_event "manifest_published" "published throughput baseline manifest to $OUTPUT_FILE"
else
  write_event "manifest_blocked" "fail-closed blocker bundle retained at $MANIFEST_PATH"
fi

echo "Run manifest: $RUN_MANIFEST_PATH"
echo "Measurement manifest: $MANIFEST_PATH"
echo "Decision: $decision"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
