#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_NATIVE_DEPENDENCY_ROUTE_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-route-planner}"
run_id="${SWARM_NATIVE_DEPENDENCY_ROUTE_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_ROUTE_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_NATIVE_DEPENDENCY_ROUTE_PLANNER_SOURCE_REVISION:-unknown}"
contract_json="${root_dir}/docs/swarm_native_dependency_route_planner_contract_v1.json"
native_requirement_bundle_json=""
worker_probe_snapshots_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_route_planner.sh [OPTIONS]

Builds deterministic advisory routing and retry advice from native requirement
bundles and worker native-probe snapshots. The script is fixture-fed and
advisory-only. It does not run Cargo or RCH, mutate workers, install packages,
change live queue policy, send Agent Mail, or update beads.

Required:
  --native-requirement-bundle-json FILE
  --worker-probe-snapshots-json FILE

Optional:
  --contract-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  native_dependency_routing_advisory.json
  native_dependency_routing_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  at least one compatible worker is available
  75 no compatible worker exists because required native dependencies are missing
  42 stale, contradictory, probe-unavailable, unknown, contaminated, or invalid evidence blocks advice
  64 invalid invocation or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --native-requirement-bundle-json)
      native_requirement_bundle_json="${2:-}"
      shift 2
      ;;
    --worker-probe-snapshots-json)
      worker_probe_snapshots_json="${2:-}"
      shift 2
      ;;
    --contract-json)
      contract_json="${2:-}"
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

if [[ -z "$native_requirement_bundle_json" || -z "$worker_probe_snapshots_json" ]]; then
  printf 'native requirement bundle and worker probe snapshots are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for native dependency route planning\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
advisory_path="${run_dir}/native_dependency_routing_advisory.json"
sources_path="${run_dir}/native_dependency_routing_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"

requirement_normalized="${run_dir}/native_requirement_bundle.normalized.json"
snapshots_normalized="${run_dir}/worker_probe_snapshots.normalized.json"
contract_normalized="${run_dir}/route_planner_contract.normalized.json"

printf './scripts/swarm_native_dependency_route_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
}

write_event() {
  local validation_id="$1"
  local worker_id="$2"
  local dependency_id="$3"
  local event="$4"
  local outcome="$5"
  local error_code="$6"
  local detail="$7"
  jq -nc \
    --arg schema_version "franken-engine.native-dependency-route-planner.event.v1" \
    --arg trace_id "native-dependency-route-${validation_id}" \
    --arg validation_id "$validation_id" \
    --arg worker_id "$worker_id" \
    --arg dependency_id "$dependency_id" \
    --arg component "swarm_native_dependency_route_planner" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,event:$event,outcome:$outcome,error_code:$error_code,detail:$detail}' \
    >>"$events_path"
}

normalize_required_json "$native_requirement_bundle_json" "$requirement_normalized" "native requirement bundle"
normalize_required_json "$worker_probe_snapshots_json" "$snapshots_normalized" "worker probe snapshots"
normalize_required_json "$contract_json" "$contract_normalized" "route planner contract"

validation_id="$(jq -r '.validation_id // "unknown"' "$requirement_normalized")"
write_event "$validation_id" "all" "all" "inputs.loaded" "provided" "ok" "normalized route planner inputs"

jq -n \
  --arg source_revision "$source_revision" \
  --slurpfile req "$requirement_normalized" \
  --slurpfile snapshots "$snapshots_normalized" \
  --slurpfile contract "$contract_normalized" '
  ($req[0]) as $req
  | ($snapshots[0]) as $snapshots
  | ($contract[0]) as $contract
  | ($req.dependency_requirements // [] | map(select(.required == true) | .dependency_id) | unique) as $required_deps
  | def classifications($snapshot): ($snapshot.dependency_classifications // []);
    def present_deps($snapshot): (classifications($snapshot) | map(select(.classification == "present") | .dependency_id) | unique);
    def missing_required($snapshot): ($required_deps - present_deps($snapshot));
    def fail_closed_reasons($snapshot):
      (($snapshot.reason_codes // []) | map(select(. as $code | ["stale_worker_probe","contradictory_pkg_config_header_evidence","probe_unavailable","local_fallback_contaminated","unknown_probe_state"] | index($code) != null)) | unique);
    def worker_eval($snapshot):
      (missing_required($snapshot)) as $missing
      | (fail_closed_reasons($snapshot)) as $fail_reasons
      | {
          worker_id: ($snapshot.worker_id // "unknown-worker"),
          host_class: ($snapshot.host_class // "unknown"),
          decision: ($snapshot.decision // "fail_closed"),
          truth_state: ($snapshot.truth_state // "unknown"),
          missing_required_dependency_ids: $missing,
          reason_codes: (($snapshot.reason_codes // []) + (if ($missing | length) > 0 then ["missing_required_native_evidence"] else [] end) | unique),
          route_state:
            (if (($snapshot.truth_state // "") == "contaminated") or (($fail_reasons | length) > 0) then "fail_closed"
             elif (($missing | length) > 0) or (($snapshot.decision // "") == "blocked") then "incompatible"
             elif (($snapshot.decision // "") == "pass") then "compatible"
             else "fail_closed"
             end)
        };
    (($snapshots.snapshots // []) | map(worker_eval(.))) as $workers
  | ($workers | map(select(.route_state == "compatible"))) as $compatible
  | ($workers | map(select(.route_state == "incompatible"))) as $incompatible
  | ($workers | map(select(.route_state == "fail_closed"))) as $fail_closed
  | (
      []
      + (if ($compatible | length) > 0 then ["compatible_worker_available"] else [] end)
      + (if ($incompatible | length) > 0 then ["incompatible_worker_missing_native_dependency"] else [] end)
      + (if ($incompatible | map(.reason_codes) | flatten | index("hdf5_missing") != null) then ["hdf5_missing"] else [] end)
      + (if (($compatible | length) == 0) then ["no_compatible_workers"] else [] end)
      + ($fail_closed | map(.reason_codes) | flatten)
      + (if (($req.decision // "pass") == "fail_closed") then ["requirement_bundle_fail_closed"] else [] end)
      | unique
    ) as $reason_codes
  | (
      if (($req.decision // "pass") == "fail_closed") then "fail_closed"
      elif ($compatible | length) > 0 then "pass"
      elif ($fail_closed | length) > 0 then "fail_closed"
      else "blocked"
      end
    ) as $decision
  | (
      if $decision == "pass" then "confirmed"
      elif $decision == "blocked" then "blocked"
      elif ($reason_codes | index("local_fallback_contaminated") != null) then "contaminated"
      else "unknown"
      end
    ) as $truth_state
  | {
      schema_version: $contract.output_schema_version,
      source_schema_version: $contract.source_schema_version,
      source_revision: $source_revision,
      routing_advisory_id: ("native-route-" + ($req.validation_id // "unknown")),
      validation_id: ($req.validation_id // "unknown"),
      command: ($req.command // ""),
      required_dependency_ids: $required_deps,
      compatible_worker_ids: ($compatible | map(.worker_id)),
      incompatible_workers: $incompatible,
      fail_closed_workers: $fail_closed,
      retry_advice: {
        mode: (if $decision == "pass" then "retry_on_compatible_worker" elif $decision == "blocked" then "block_until_native_dependency_available" else "fail_closed_requires_fresh_probe_evidence" end),
        preferred_worker_id: (($compatible[0].worker_id) // null),
        explanation: (if $decision == "pass" then "prefer compatible worker with present native dependency evidence" elif $decision == "blocked" then "all candidate workers lack required native dependency evidence" else "evidence is stale, contradictory, unavailable, contaminated, or invalid" end)
      },
      reason_codes: $reason_codes,
      truth_state: $truth_state,
      decision: $decision,
      mutation_policy: $contract.mutation_policy,
      source_artifacts: {
        native_requirement_bundle_json: "provided",
        worker_probe_snapshots_json: "provided"
      }
    }
' >"$advisory_path"

decision="$(jq -r '.decision' "$advisory_path")"
truth_state="$(jq -r '.truth_state' "$advisory_path")"

jq -n \
  --arg schema_version "franken-engine.native-dependency-routing-advisory-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg native_requirement_bundle_json "$native_requirement_bundle_json" \
  --arg worker_probe_snapshots_json "$worker_probe_snapshots_json" \
  --arg contract_json "$contract_json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    inputs: {
      native_requirement_bundle_json: $native_requirement_bundle_json,
      worker_probe_snapshots_json: $worker_probe_snapshots_json,
      contract_json: $contract_json
    }
  }' >"$sources_path"

{
  printf '%s\n\n' '# Native Dependency Route Planner'
  printf '%s\n' "- validation_id: \`${validation_id}\`"
  printf '%s\n' "- decision: \`${decision}\`"
  printf '%s\n' "- truth_state: \`${truth_state}\`"
  printf '%s\n' "- compatible_workers: \`$(jq -c '.compatible_worker_ids' "$advisory_path")\`"
  printf '%s\n' "- reason_codes: \`$(jq -c '.reason_codes' "$advisory_path")\`"
} >"$summary_path"

while IFS=$'\t' read -r worker_id route_state; do
  write_event "$validation_id" "$worker_id" "all" "worker.evaluated" "$route_state" "$route_state" "$advisory_path"
done < <(jq -r '(.compatible_worker_ids[]? | [., "compatible"] | @tsv), (.incompatible_workers[]? | [.worker_id, "incompatible"] | @tsv), (.fail_closed_workers[]? | [.worker_id, "fail_closed"] | @tsv)' "$advisory_path")
write_event "$validation_id" "all" "all" "routing.completed" "$decision" "$truth_state" "$advisory_path"

case "$decision" in
  pass)
    exit 0
    ;;
  blocked)
    exit 75
    ;;
  fail_closed)
    exit 42
    ;;
  *)
    exit 42
    ;;
esac
