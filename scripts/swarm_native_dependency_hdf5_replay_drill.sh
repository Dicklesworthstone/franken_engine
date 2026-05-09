#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_NATIVE_DEPENDENCY_HDF5_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-hdf5-drill}"
run_id="${SWARM_NATIVE_DEPENDENCY_HDF5_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_HDF5_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

cases_json="${root_dir}/scripts/testdata/swarm_native_dependency_hdf5_replay_drill/cases.json"
scenario_id="hdf5_fixture_selects_compatible_worker"
source_revision="${SWARM_NATIVE_DEPENDENCY_HDF5_DRILL_SOURCE_REVISION:-unknown}"

requirement_script="${root_dir}/scripts/swarm_native_dependency_requirement_infer.sh"
worker_probe_script="${root_dir}/scripts/swarm_native_dependency_worker_probe_normalizer.sh"
route_planner_script="${root_dir}/scripts/swarm_native_dependency_route_planner.sh"
abi_cache_script="${root_dir}/scripts/swarm_native_dependency_abi_cache_ledger.sh"
operator_status_script="${root_dir}/scripts/swarm_native_dependency_operator_status.sh"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_hdf5_replay_drill.sh [OPTIONS]

Runs a deterministic, fixture-fed HDF5/frankenpandas replay drill through the
native dependency requirement, worker probe, route planner, ABI cache, and
operator-status surfaces. This script does not run Cargo or RCH, mutate remote
workers, install packages, delete target directories, reroute live tasks, update
beads, or send Agent Mail.

Optional:
  --cases-json FILE
  --scenario-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  run_manifest.json
  events.jsonl
  command_trace_ids.json
  native_dependency_routing_report.md
  step_evidence.json
  commands.txt

Exit codes:
  0   compatible worker and reusable ABI evidence
  75  all candidate workers lack required native dependency evidence
  42  stale, contradictory, contaminated, or malformed evidence fails closed
  64  invalid invocation or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cases-json)
      cases_json="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the HDF5 native dependency replay drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for ABI fingerprint materialization\n' >&2
  exit 2
fi
if [[ ! -f "$cases_json" ]]; then
  printf 'missing HDF5 replay cases JSON: %s\n' "$cases_json" >&2
  exit 64
fi
if ! jq empty "$cases_json" >/dev/null 2>&1; then
  printf 'invalid HDF5 replay cases JSON: %s\n' "$cases_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
input_dir="${run_dir}/inputs"
requirement_dir="${run_dir}/requirement"
worker_dir="${run_dir}/worker_probes"
route_dir="${run_dir}/route"
abi_dir="${run_dir}/abi_cache"
operator_dir="${run_dir}/operator_status"
mkdir -p "$input_dir" "$requirement_dir" "$worker_dir" "$route_dir" "$abi_dir" "$operator_dir"

scenario_path="${run_dir}/scenario.normalized.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
run_manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/command_trace_ids.json"
report_path="${run_dir}/native_dependency_routing_report.md"
step_evidence_path="${run_dir}/step_evidence.json"
worker_probe_snapshots_path="${run_dir}/worker_probe_snapshots.json"

jq --arg scenario_id "$scenario_id" '
  .scenarios[] | select(.scenario_id == $scenario_id)
' "$cases_json" >"$scenario_path"
if [[ ! -s "$scenario_path" ]]; then
  printf 'unknown HDF5 replay scenario: %s\n' "$scenario_id" >&2
  exit 64
fi

printf './scripts/swarm_native_dependency_hdf5_replay_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  local step="$1"
  local outcome="$2"
  local error_code="$3"
  local detail="$4"
  jq -nc \
    --arg schema_version "franken-engine.native-dependency-hdf5-replay-drill.event.v1" \
    --arg trace_id "hdf5-native-drill-${scenario_id}" \
    --arg validation_id "$scenario_id" \
    --arg worker_id "not_applicable" \
    --arg dependency_id "hdf5" \
    --arg component "swarm_native_dependency_hdf5_replay_drill" \
    --arg step "$step" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,step:$step,outcome:$outcome,error_code:$error_code,detail:$detail}' \
    >>"$events_path"
}

print_command() {
  local step="$1"
  shift
  printf '%s:' "$step" >>"$commands_path"
  for arg in "$@"; do
    printf ' %q' "$arg" >>"$commands_path"
  done
  printf '\n' >>"$commands_path"
}

run_step() {
  local step="$1"
  local expected_exit="$2"
  shift 2
  local code=0
  print_command "$step" "$@"
  set +e
  "$@" >/dev/null
  code=$?
  set -e
  write_event "$step" "exit_${code}" "$code" "expected ${expected_exit}"
  if [[ "$code" -ne "$expected_exit" ]]; then
    printf '%s expected exit %s, got %s\n' "$step" "$expected_exit" "$code" >&2
    return 1
  fi
  return 0
}

write_input_json() {
  local jq_expr="$1"
  local output_path="$2"
  jq "$jq_expr" "$scenario_path" >"$output_path"
}

canonical_fingerprint_for_case() {
  local input_path="$1"
  jq -cS '{
    rust_toolchain,
    rch_worker_id,
    target_dir_id,
    requirement_bundle_version,
    native_dependencies: ((.native_dependencies // []) | sort_by(.dependency_id) | map({
      dependency_id,
      pkg_config_version,
      include_roots,
      environment_roots,
      header_paths,
      abi_fingerprint
    }))
  }' "$input_path" | sha256sum | awk '{print $1}'
}

materialize_abi_input() {
  local output_path="$1"
  jq '.inputs.abi_cache_input_json' "$scenario_path" >"$output_path"
  if jq -e '.cached_proof.abi_fingerprint == "__SELF__"' "$output_path" >/dev/null; then
    local fingerprint tmp_path
    fingerprint="$(canonical_fingerprint_for_case "$output_path")"
    tmp_path="${output_path}.tmp"
    jq --arg fingerprint "$fingerprint" '.cached_proof.abi_fingerprint = $fingerprint' "$output_path" >"$tmp_path"
    mv "$tmp_path" "$output_path"
  fi
}

write_rch_log_fixtures() {
  local log_root="${input_dir}/rch_failure_logs"
  mkdir -p "$log_root"
  local count i worker_id log_path
  count="$(jq '.inputs.rch_log_fixtures | length' "$scenario_path")"
  for ((i = 0; i < count; i++)); do
    worker_id="$(jq -r ".inputs.rch_log_fixtures[$i].worker_id" "$scenario_path")"
    log_path="${log_root}/${worker_id}.log"
    jq -r ".inputs.rch_log_fixtures[$i].log_lines[]" "$scenario_path" >"$log_path"
  done
}

validation_context_path="${input_dir}/validation_command_context.json"
cargo_lock_path="${input_dir}/cargo_lock_snapshot.json"
workspace_manifest_path="${input_dir}/workspace_manifest_snapshot.json"
path_manifests_path="${input_dir}/path_dependency_manifests.json"
diagnostics_path="${input_dir}/build_script_diagnostics.json"
abi_input_path="${input_dir}/abi_cache_input.json"

write_input_json '.inputs.requirement_inference.validation_command_context_json' "$validation_context_path"
write_input_json '.inputs.requirement_inference.cargo_lock_snapshot_json' "$cargo_lock_path"
write_input_json '.inputs.requirement_inference.workspace_manifest_snapshot_json' "$workspace_manifest_path"
write_input_json '.inputs.requirement_inference.path_dependency_manifests_json' "$path_manifests_path"
write_input_json '.inputs.requirement_inference.build_script_diagnostics_json' "$diagnostics_path"
materialize_abi_input "$abi_input_path"
write_rch_log_fixtures

validation_id="$(jq -r '.inputs.requirement_inference.validation_command_context_json.validation_id' "$scenario_path")"
expected_requirement_exit="$(jq -r '.expected_step_exit_codes.requirement_infer' "$scenario_path")"
step_mismatch=0

run_step "requirement_infer" "$expected_requirement_exit" \
  bash "$requirement_script" \
    --source-revision "$source_revision" \
    --validation-command-context-json "$validation_context_path" \
    --cargo-lock-snapshot-json "$cargo_lock_path" \
    --workspace-manifest-snapshot-json "$workspace_manifest_path" \
    --path-dependency-manifests-json "$path_manifests_path" \
    --build-script-diagnostics-json "$diagnostics_path" \
    --output-dir "$requirement_dir" || step_mismatch=1

snapshot_files=()
worker_count="$(jq '.inputs.worker_probe_inputs | length' "$scenario_path")"
for ((i = 0; i < worker_count; i++)); do
  worker_id="$(jq -r ".inputs.worker_probe_inputs[$i].worker_id" "$scenario_path")"
  raw_probe_path="${input_dir}/worker_probe_${worker_id}.json"
  probe_out_dir="${worker_dir}/${worker_id}"
  mkdir -p "$probe_out_dir"
  jq ".inputs.worker_probe_inputs[$i].raw_worker_probe_json" "$scenario_path" >"$raw_probe_path"
  expected_probe_exit="$(jq -r --arg worker_id "$worker_id" '.expected_step_exit_codes.worker_probe_normalizer[$worker_id] // .expected_step_exit_codes.worker_probe_normalizer_default // 0' "$scenario_path")"
  run_step "worker_probe_${worker_id}" "$expected_probe_exit" \
    bash "$worker_probe_script" \
      --source-revision "$source_revision" \
      --raw-worker-probe-json "$raw_probe_path" \
      --native-requirement-bundle-json "${requirement_dir}/native_dependency_requirement_bundle.json" \
      --output-dir "$probe_out_dir" || step_mismatch=1
  snapshot_files+=("${probe_out_dir}/worker_native_probe_snapshot.json")
done

jq -s '{schema_version:"franken-engine.worker-native-probe-snapshot-set.v1", snapshots:.}' "${snapshot_files[@]}" >"$worker_probe_snapshots_path"

expected_route_exit="$(jq -r '.expected_step_exit_codes.route_planner' "$scenario_path")"
run_step "route_planner" "$expected_route_exit" \
  bash "$route_planner_script" \
    --source-revision "$source_revision" \
    --native-requirement-bundle-json "${requirement_dir}/native_dependency_requirement_bundle.json" \
    --worker-probe-snapshots-json "$worker_probe_snapshots_path" \
    --output-dir "$route_dir" || step_mismatch=1

expected_abi_exit="$(jq -r '.expected_step_exit_codes.abi_cache_ledger' "$scenario_path")"
run_step "abi_cache_ledger" "$expected_abi_exit" \
  bash "$abi_cache_script" \
    --source-revision "$source_revision" \
    --abi-cache-input-json "$abi_input_path" \
    --output-dir "$abi_dir" || step_mismatch=1

expected_operator_exit="$(jq -r '.expected_step_exit_codes.operator_status' "$scenario_path")"
run_step "operator_status" "$expected_operator_exit" \
  bash "$operator_status_script" \
    --source-revision "$source_revision" \
    --route-advisory-json "${route_dir}/native_dependency_routing_advisory.json" \
    --abi-cache-ledger-json "${abi_dir}/native_dependency_abi_cache_ledger.json" \
    --output-dir "$operator_dir" || step_mismatch=1

jq -n \
  --arg schema_version "franken-engine.native-dependency-hdf5-replay-drill.command-traces.v1" \
  --arg validation_id "$validation_id" \
  --arg scenario_id "$scenario_id" \
  --arg requirement_trace_id "native-requirement-${validation_id}" \
  --arg route_trace_id "native-dependency-route-${validation_id}" \
  --arg abi_trace_id "native-abi-cache-${validation_id}" \
  --arg operator_trace_id "native-dependency-operator-status-${validation_id}" \
  --argjson workers "$(jq '[.inputs.worker_probe_inputs[].worker_id]' "$scenario_path")" \
  '{
    schema_version: $schema_version,
    scenario_id: $scenario_id,
    validation_id: $validation_id,
    traces: {
      requirement_infer: $requirement_trace_id,
      worker_probes: ($workers | map({worker_id: ., trace_id: ("worker-native-probe-" + .)})),
      route_planner: $route_trace_id,
      abi_cache_ledger: $abi_trace_id,
      operator_status: $operator_trace_id
    }
  }' >"$trace_ids_path"

jq -n \
  --arg schema_version "franken-engine.native-dependency-hdf5-replay-drill.step-evidence.v1" \
  --arg source_revision "$source_revision" \
  --arg scenario_id "$scenario_id" \
  --slurpfile requirement "${requirement_dir}/native_dependency_requirement_bundle.json" \
  --slurpfile snapshots "$worker_probe_snapshots_path" \
  --slurpfile route "${route_dir}/native_dependency_routing_advisory.json" \
  --slurpfile abi "${abi_dir}/native_dependency_abi_cache_ledger.json" \
  --slurpfile operator "${operator_dir}/native_dependency_operator_status.json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    scenario_id: $scenario_id,
    evidence: {
      requirement: $requirement[0],
      worker_probe_snapshots: $snapshots[0],
      route_advisory: $route[0],
      abi_cache_ledger: $abi[0],
      operator_status: $operator[0]
    },
    artifacts: {
      run_manifest: "run_manifest.json",
      event_log: "events.jsonl",
      command_trace_ids: "command_trace_ids.json",
      native_dependency_routing_report: "native_dependency_routing_report.md",
      requirement_bundle: "requirement/native_dependency_requirement_bundle.json",
      worker_probe_snapshots: "worker_probe_snapshots.json",
      route_advisory: "route/native_dependency_routing_advisory.json",
      abi_cache_ledger: "abi_cache/native_dependency_abi_cache_ledger.json",
      operator_status: "operator_status/native_dependency_operator_status.json"
    }
  }' >"$step_evidence_path"

expected_status="$(jq -r '.expected.status' "$scenario_path")"
expected_route_decision="$(jq -r '.expected.route_decision' "$scenario_path")"
expected_hdf5_detected="$(jq -r '.expected.hdf5_detected' "$scenario_path")"

if ! jq -e --arg expected_status "$expected_status" --arg expected_route_decision "$expected_route_decision" --argjson expected_compatible "$(jq -c '.expected.compatible_worker_ids' "$scenario_path")" --argjson expected_required "$(jq -c '.expected.required_dependency_ids' "$scenario_path")" '
  .evidence.operator_status.status == $expected_status
  and .evidence.route_advisory.decision == $expected_route_decision
  and .evidence.route_advisory.compatible_worker_ids == $expected_compatible
  and ((.evidence.requirement.dependency_requirements | map(.dependency_id)) == $expected_required)
' "$step_evidence_path" >/dev/null; then
  write_event "evidence.assertions" "mismatch" "42" "expected scenario evidence did not match"
  step_mismatch=1
fi

if [[ "$expected_hdf5_detected" == "true" ]]; then
  if ! jq -e '.evidence.requirement.dependency_requirements | any(.dependency_id == "hdf5" and .required == true)' "$step_evidence_path" >/dev/null; then
    write_event "hdf5.requirement_detected" "missing" "42" "HDF5 native prerequisite was not inferred"
    step_mismatch=1
  fi
fi

jq -n \
  --arg schema_version "franken-engine.native-dependency-hdf5-replay-drill.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg scenario_id "$scenario_id" \
  --arg validation_id "$validation_id" \
  --arg output_dir "$run_dir" \
  --slurpfile route "${route_dir}/native_dependency_routing_advisory.json" \
  --slurpfile abi "${abi_dir}/native_dependency_abi_cache_ledger.json" \
  --slurpfile operator "${operator_dir}/native_dependency_operator_status.json" \
  --slurpfile traces "$trace_ids_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    scenario_id: $scenario_id,
    validation_id: $validation_id,
    output_dir: $output_dir,
    drill_decision: $route[0].decision,
    operator_status: $operator[0].status,
    preferred_worker_id: $route[0].retry_advice.preferred_worker_id,
    compatible_worker_ids: $route[0].compatible_worker_ids,
    required_dependency_ids: $route[0].required_dependency_ids,
    route_reason_codes: $route[0].reason_codes,
    abi_cache_decision: $abi[0].decision,
    source_failure_claimed: $operator[0].source_failure_claimed,
    advisory_only: true,
    live_rch_required: false,
    live_rch_operator_proof_optional: true,
    command_trace_ids: $traces[0],
    artifact_paths: {
      event_log: "events.jsonl",
      commands: "commands.txt",
      step_evidence: "step_evidence.json",
      native_dependency_routing_report: "native_dependency_routing_report.md"
    }
  }' >"$run_manifest_path"

{
  printf '%s\n\n' '# HDF5 Native Dependency Replay Drill'
  printf '%s\n' "- scenario_id: \`${scenario_id}\`"
  printf '%s\n' "- validation_id: \`${validation_id}\`"
  printf '%s\n' "- operator_status: \`$(jq -r '.operator_status' "$run_manifest_path")\`"
  printf '%s\n' "- drill_decision: \`$(jq -r '.drill_decision' "$run_manifest_path")\`"
  printf '%s\n' "- preferred_worker_id: \`$(jq -r '.preferred_worker_id // "none"' "$run_manifest_path")\`"
  printf '%s\n' "- compatible_worker_ids: \`$(jq -c '.compatible_worker_ids' "$run_manifest_path")\`"
  printf '%s\n' "- required_dependency_ids: \`$(jq -c '.required_dependency_ids' "$run_manifest_path")\`"
  printf '%s\n' "- route_reason_codes: \`$(jq -c '.route_reason_codes' "$run_manifest_path")\`"
  printf '%s\n' "- abi_cache_decision: \`$(jq -r '.abi_cache_decision' "$run_manifest_path")\`"
  printf '\n%s\n' 'This is a deterministic replay from checked-in fixtures. Live rch execution is optional operator proof and is not required for the local smoke gate.'
  printf '%s\n' 'Validation environment blockers are not source failure claims.'
  printf '\n%s\n' '## Captured RCH Log Fixtures'
  jq -r '.inputs.rch_log_fixtures[] | "- `" + .worker_id + "`: `" + .fixture_kind + "`"' "$scenario_path"
} >"$report_path"

write_event "drill.completed" "$(jq -r '.operator_status' "$run_manifest_path")" "$expected_operator_exit" "$run_manifest_path"

if [[ "$step_mismatch" -ne 0 ]]; then
  exit 42
fi

case "$(jq -r '.operator_status' "$run_manifest_path")" in
  PASS)
    exit 0
    ;;
  BLOCKED)
    exit 75
    ;;
  FAIL-CLOSED)
    exit 42
    ;;
  *)
    exit 42
    ;;
esac
