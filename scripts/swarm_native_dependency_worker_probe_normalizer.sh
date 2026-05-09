#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_NATIVE_DEPENDENCY_WORKER_PROBE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-worker-probe}"
run_id="${SWARM_NATIVE_DEPENDENCY_WORKER_PROBE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_WORKER_PROBE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_NATIVE_DEPENDENCY_WORKER_PROBE_SOURCE_REVISION:-unknown}"
contract_json="${root_dir}/docs/swarm_native_dependency_worker_probe_contract_v1.json"
raw_worker_probe_json=""
native_requirement_bundle_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_worker_probe_normalizer.sh [OPTIONS]

Normalizes preserved native dependency worker probe evidence into deterministic
routing input. The script is fixture-fed and read-only. It does not run Cargo or
RCH, mutate remote workers, install packages, change live queue policy, send
Agent Mail, or update beads.

Required:
  --raw-worker-probe-json FILE

Optional:
  --native-requirement-bundle-json FILE
  --contract-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  worker_native_probe_snapshot.json
  worker_native_probe_sources.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  probe evidence is coherent and confirmed
  75 required native dependency evidence is missing
  42 stale, contradictory, unsupported, unknown, or contaminated evidence
  64 invalid invocation or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --raw-worker-probe-json)
      raw_worker_probe_json="${2:-}"
      shift 2
      ;;
    --native-requirement-bundle-json)
      native_requirement_bundle_json="${2:-}"
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

if [[ -z "$raw_worker_probe_json" ]]; then
  printf 'raw worker probe JSON is required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for worker native dependency probe normalization\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
snapshot_path="${run_dir}/worker_native_probe_snapshot.json"
sources_path="${run_dir}/worker_native_probe_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

raw_normalized="${run_dir}/raw_worker_probe.normalized.json"
contract_normalized="${run_dir}/worker_probe_contract.normalized.json"
requirement_normalized="${run_dir}/native_requirement_bundle.normalized.json"

printf './scripts/swarm_native_dependency_worker_probe_normalizer.sh' >"$commands_path"
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

normalize_optional_json() {
  local input="$1"
  local output="$2"
  if [[ -z "$input" ]]; then
    printf '{}\n' >"$output"
    return
  fi
  normalize_required_json "$input" "$output" "native requirement bundle"
}

write_event() {
  local worker_id="$1"
  local dependency_id="$2"
  local event="$3"
  local outcome="$4"
  local error_code="$5"
  local detail="$6"
  jq -nc \
    --arg schema_version "franken-engine.worker-native-probe-normalizer.event.v1" \
    --arg trace_id "worker-native-probe-${worker_id}" \
    --arg validation_id "not_applicable" \
    --arg worker_id "$worker_id" \
    --arg dependency_id "$dependency_id" \
    --arg component "swarm_native_dependency_worker_probe_normalizer" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,event:$event,outcome:$outcome,error_code:$error_code,detail:$detail}' \
    >>"$events_path"
}

normalize_required_json "$raw_worker_probe_json" "$raw_normalized" "raw worker probe"
normalize_required_json "$contract_json" "$contract_normalized" "worker probe contract"
normalize_optional_json "$native_requirement_bundle_json" "$requirement_normalized"

worker_id="$(jq -r '.worker_id // "unknown-worker"' "$raw_normalized")"
write_event "$worker_id" "all" "inputs.loaded" "provided" "ok" "normalized worker probe input"

jq -n \
  --arg source_revision "$source_revision" \
  --slurpfile raw "$raw_normalized" \
  --slurpfile contract "$contract_normalized" \
  --slurpfile requirements "$requirement_normalized" '
  ($raw[0]) as $raw
  | ($contract[0]) as $contract
  | ($requirements[0]) as $requirements
  | def dep_groups:
      ($raw.probes // [])
      | group_by(.dependency_id)
      | map({dependency_id: .[0].dependency_id, probes: .});
    def any_probe($probes; $expr): any($probes[]?; $expr);
    def all_header_ok($probes):
      (($probes | map(select(.probe_kind == "header_presence"))) as $headers
        | if ($headers | length) == 0 then true else all($headers[]; ((.exit_code // 1) == 0) and ((.header_present // true) == true)) end);
    def classify($probes):
      if any($probes[]?; (.contamination_state // "remote_only") != "remote_only") then "contaminated"
      elif any($probes[]?; (.freshness_state // "fresh") == "stale") then "stale"
      elif any($probes[]?; (.probe_unavailable // false) == true or (.exit_code // 0) == 255) then "unsupported"
      elif (
        any($probes[]?; .probe_kind == "pkg_config_modversion" and ((.exit_code // 1) == 0))
        and any($probes[]?; .probe_kind == "header_presence" and (((.exit_code // 0) != 0) or ((.header_present // true) == false)))
      ) then "contradictory"
      elif any($probes[]?; .probe_kind == "pkg_config_modversion" and ((.exit_code // 1) == 0)) and all_header_ok($probes) then "present"
      elif any($probes[]?; .probe_kind == "pkg_config_modversion" and ((.exit_code // 0) != 0)) then "missing"
      else "unknown"
      end;
    def reason_codes_for($dependency_id; $classification):
      (
        if $classification == "present" then ["native_dependency_present"] else [] end
        + if $classification == "missing" then ["native_dependency_missing"] else [] end
        + if $classification == "stale" then ["stale_worker_probe"] else [] end
        + if $classification == "contradictory" then ["contradictory_pkg_config_header_evidence"] else [] end
        + if $classification == "unsupported" then ["probe_unavailable"] else [] end
        + if $classification == "contaminated" then ["local_fallback_contaminated"] else [] end
        + if $classification == "unknown" then ["unknown_probe_state"] else [] end
        + if $dependency_id == "hdf5" and $classification == "present" then ["hdf5_present"] else [] end
        + if $dependency_id == "hdf5" and $classification == "missing" then ["hdf5_missing"] else [] end
      ) | unique;
    (dep_groups | map(
      . as $group
      | (classify($group.probes)) as $classification
      | {
          dependency_id: $group.dependency_id,
          native_package_name: (($group.probes[0].native_package_name // $group.dependency_id)),
          worker_id: ($raw.worker_id // "unknown-worker"),
          host_class: ($raw.host_class // "unknown"),
          classification: $classification,
          probe_status: $classification,
          observed_version: (($group.probes | map(select(.observed_version != null) | .observed_version))[0] // null),
          abi_fingerprint: (($group.probes | map(select(.abi_fingerprint != null) | .abi_fingerprint))[0] // null),
          probe_timestamp: (($group.probes | map(select(.probe_timestamp != null) | .probe_timestamp))[0] // ($raw.captured_at // null)),
          freshness_state: (if any($group.probes[]?; (.freshness_state // "fresh") == "stale") then "stale" else "fresh" end),
          contamination_state: (if any($group.probes[]?; (.contamination_state // "remote_only") != "remote_only") then "local_fallback" else "remote_only" end),
          probe_commands: ($group.probes | map(.probe_command // .command // "")),
          probe_kinds: ($group.probes | map(.probe_kind) | unique),
          reason_codes: reason_codes_for($group.dependency_id; $classification)
        }
    )) as $classifications
  | ($classifications | map(.reason_codes) | flatten | unique) as $reason_codes
  | (
      if any($classifications[]?; .classification == "contaminated") then "contaminated"
      elif any($classifications[]?; .classification == "missing") then "blocked"
      elif any($classifications[]?; (.classification | IN("stale","contradictory","unsupported","unknown"))) then "unknown"
      else "confirmed"
      end
    ) as $truth_state
  | (
      if $truth_state == "confirmed" then "pass"
      elif $truth_state == "blocked" then "blocked"
      else "fail_closed"
      end
    ) as $decision
  | {
      schema_version: $contract.output_schema_version,
      source_schema_version: $contract.source_schema_version,
      source_revision: $source_revision,
      worker_id: ($raw.worker_id // "unknown-worker"),
      host_class: ($raw.host_class // "unknown"),
      captured_at: ($raw.captured_at // null),
      requirement_bundle_id: ($requirements.validation_id // null),
      dependency_classifications: $classifications,
      reason_codes: $reason_codes,
      truth_state: $truth_state,
      decision: $decision,
      mutation_policy: $contract.mutation_policy
    }
' >"$snapshot_path"

decision="$(jq -r '.decision' "$snapshot_path")"
truth_state="$(jq -r '.truth_state' "$snapshot_path")"

jq -n \
  --arg schema_version "franken-engine.worker-native-probe-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg raw_worker_probe_json "$raw_worker_probe_json" \
  --arg native_requirement_bundle_json "$native_requirement_bundle_json" \
  --arg contract_json "$contract_json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    inputs: {
      raw_worker_probe_json: $raw_worker_probe_json,
      native_requirement_bundle_json: $native_requirement_bundle_json,
      contract_json: $contract_json
    }
  }' >"$sources_path"

{
  printf '%s\n\n' '# Worker Native Dependency Probe Normalization'
  printf '%s\n' "- worker_id: \`${worker_id}\`"
  printf '%s\n' "- decision: \`${decision}\`"
  printf '%s\n' "- truth_state: \`${truth_state}\`"
  printf '%s\n' "- classifications: \`$(jq -r '.dependency_classifications | length' "$snapshot_path")\`"
  printf '%s\n' "- reason_codes: \`$(jq -c '.reason_codes' "$snapshot_path")\`"
} >"$report_path"

while IFS=$'\t' read -r dependency_id classification; do
  write_event "$worker_id" "$dependency_id" "probe.normalized" "$classification" "$classification" "$snapshot_path"
done < <(jq -r '.dependency_classifications[] | [.dependency_id, .classification] | @tsv' "$snapshot_path")
write_event "$worker_id" "all" "normalization.completed" "$decision" "$truth_state" "$snapshot_path"

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
