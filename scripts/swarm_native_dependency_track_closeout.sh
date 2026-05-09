#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
artifact_root="${SWARM_NATIVE_DEPENDENCY_TRACK_CLOSEOUT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-track-closeout}"
run_id="${SWARM_NATIVE_DEPENDENCY_TRACK_CLOSEOUT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_TRACK_CLOSEOUT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

cases_json="${root_dir}/scripts/testdata/swarm_native_dependency_track_closeout/cases.json"
source_revision="${SWARM_NATIVE_DEPENDENCY_TRACK_CLOSEOUT_SOURCE_REVISION:-unknown}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_track_closeout.sh [OPTIONS]

Verifies the native dependency routing track closeout: child artifact inventory,
bead dependency ordering, bv cycle proof, and focused fixture/golden smoke
commands. This script does not run Cargo or RCH, mutate workers, install
packages, delete target directories, update beads, or send Agent Mail.

Optional:
  --cases-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  native_dependency_track_closeout_manifest.json
  native_dependency_track_closeout_report.md
  graph_insights.json
  proof_results.jsonl
  events.jsonl
  commands.txt
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cases-json)
      cases_json="${2:-}"
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
  printf 'jq is required for native dependency track closeout\n' >&2
  exit 2
fi
if ! command -v br >/dev/null 2>&1; then
  printf 'br is required for native dependency track closeout\n' >&2
  exit 2
fi
if ! command -v bv >/dev/null 2>&1; then
  printf 'bv is required for native dependency track closeout\n' >&2
  exit 2
fi
if [[ ! -f "$cases_json" ]]; then
  printf 'missing native dependency track closeout cases JSON: %s\n' "$cases_json" >&2
  exit 64
fi
if ! jq empty "$cases_json" >/dev/null 2>&1; then
  printf 'invalid native dependency track closeout cases JSON: %s\n' "$cases_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
proof_dir="${run_dir}/proof"
bead_dir="${run_dir}/beads"
mkdir -p "$proof_dir" "$bead_dir"

manifest_path="${run_dir}/native_dependency_track_closeout_manifest.json"
report_path="${run_dir}/native_dependency_track_closeout_report.md"
graph_path="${run_dir}/graph_insights.json"
proof_results_path="${run_dir}/proof_results.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
artifact_results_path="${run_dir}/artifact_results.jsonl"
bead_results_path="${run_dir}/bead_results.jsonl"
dependency_results_path="${run_dir}/dependency_results.jsonl"

printf './scripts/swarm_native_dependency_track_closeout.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$proof_results_path"
: >"$artifact_results_path"
: >"$bead_results_path"
: >"$dependency_results_path"

write_event() {
  local step="$1"
  local outcome="$2"
  local error_code="$3"
  local detail="$4"
  jq -nc \
    --arg schema_version "franken-engine.native-dependency-track-closeout.event.v1" \
    --arg trace_id "native-dependency-track-closeout" \
    --arg validation_id "bd-sqm14" \
    --arg worker_id "not_applicable" \
    --arg dependency_id "all" \
    --arg component "swarm_native_dependency_track_closeout" \
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

record_artifact() {
  local bead_id="$1"
  local path="$2"
  local exists="$3"
  jq -nc \
    --arg bead_id "$bead_id" \
    --arg path "$path" \
    --argjson exists "$exists" \
    '{bead_id:$bead_id,path:$path,exists:$exists}' >>"$artifact_results_path"
}

record_bead() {
  local bead_id="$1"
  local status="$2"
  local ok="$3"
  jq -nc \
    --arg bead_id "$bead_id" \
    --arg status "$status" \
    --argjson ok "$ok" \
    '{bead_id:$bead_id,status:$status,ok:$ok}' >>"$bead_results_path"
}

record_dependency() {
  local child="$1"
  local parent="$2"
  local ok="$3"
  jq -nc \
    --arg child "$child" \
    --arg parent "$parent" \
    --argjson ok "$ok" \
    '{child:$child,parent:$parent,ok:$ok}' >>"$dependency_results_path"
}

record_proof() {
  local proof_id="$1"
  local exit_code="$2"
  local expected_exit="$3"
  local stdout_path="$4"
  local stderr_path="$5"
  local ok=false
  if [[ "$exit_code" -eq "$expected_exit" ]]; then
    ok=true
  fi
  jq -nc \
    --arg proof_id "$proof_id" \
    --arg stdout_path "${stdout_path#"$run_dir"/}" \
    --arg stderr_path "${stderr_path#"$run_dir"/}" \
    --argjson exit_code "$exit_code" \
    --argjson expected_exit "$expected_exit" \
    --argjson ok "$ok" \
    '{proof_id:$proof_id,exit_code:$exit_code,expected_exit:$expected_exit,stdout:$stdout_path,stderr:$stderr_path,ok:$ok}' >>"$proof_results_path"
}

artifact_failures=0
while IFS=$'\t' read -r bead_id artifact_path; do
  if [[ -f "${root_dir}/${artifact_path}" ]]; then
    record_artifact "$bead_id" "$artifact_path" true
  else
    record_artifact "$bead_id" "$artifact_path" false
    artifact_failures=$((artifact_failures + 1))
  fi
done < <(jq -r '.child_beads[] as $bead | $bead.artifacts[] | [$bead.bead_id, .] | @tsv' "$cases_json")
write_event "artifacts.checked" "checked" "$artifact_failures" "${artifact_failures} missing artifacts"

bead_failures=0
while IFS= read -r bead_id; do
  bead_json="${bead_dir}/${bead_id}.json"
  if ! br show "$bead_id" --json >"$bead_json"; then
    record_bead "$bead_id" "missing" false
    bead_failures=$((bead_failures + 1))
    continue
  fi
  status="$(jq -r '.[0].status // "missing"' "$bead_json")"
  if jq -e --arg bead_id "$bead_id" --arg status "$status" '.child_beads[] | select(.bead_id == $bead_id) | .allowed_statuses | index($status) != null' "$cases_json" >/dev/null; then
    record_bead "$bead_id" "$status" true
  else
    record_bead "$bead_id" "$status" false
    bead_failures=$((bead_failures + 1))
  fi
done < <(jq -r '.child_beads[].bead_id' "$cases_json")
write_event "beads.checked" "checked" "$bead_failures" "${bead_failures} bead status mismatches"

dependency_failures=0
while IFS=$'\t' read -r child parent; do
  child_json="${bead_dir}/${child}.json"
  if [[ ! -f "$child_json" ]]; then
    record_dependency "$child" "$parent" false
    dependency_failures=$((dependency_failures + 1))
    continue
  fi
  if jq -e --arg parent "$parent" '.[0].dependencies[]? | select(.id == $parent)' "$child_json" >/dev/null; then
    record_dependency "$child" "$parent" true
  else
    record_dependency "$child" "$parent" false
    dependency_failures=$((dependency_failures + 1))
  fi
done < <(jq -r '.expected_dependency_edges[] | [.child, .parent] | @tsv' "$cases_json")
write_event "dependencies.checked" "checked" "$dependency_failures" "${dependency_failures} dependency mismatches"

parent_id="$(jq -r '.parent_bead_id' "$cases_json")"
parent_json="${bead_dir}/${parent_id}.json"
if [[ ! -f "$parent_json" ]]; then
  br show "$parent_id" --json >"$parent_json"
fi
parent_child_failures=0
while IFS= read -r child_id; do
  if jq -e --arg child_id "$child_id" '.[0].dependents[]? | select(.id == $child_id and .dependency_type == "parent-child")' "$parent_json" >/dev/null; then
    :
  else
    parent_child_failures=$((parent_child_failures + 1))
  fi
done < <(jq -r '.child_beads[] | select(.parent_child == true) | .bead_id' "$cases_json")
write_event "parent_children.checked" "checked" "$parent_child_failures" "${parent_child_failures} parent-child mismatches"

graph_exit=0
mapfile -t graph_argv < <(jq -r '.graph_check.argv[]' "$cases_json")
print_command "graph_check" "${graph_argv[@]}"
set +e
"${graph_argv[@]}" >"$graph_path"
graph_exit=$?
set -e
graph_cycle_count="$(jq -r '.advanced_insights.cycle_break.cycle_count // -1' "$graph_path" 2>/dev/null || printf -- '-1')"
graph_ok=false
if [[ "$graph_exit" -eq 0 && "$graph_cycle_count" == "0" ]]; then
  graph_ok=true
fi
write_event "graph.checked" "$graph_ok" "$graph_exit" "cycle_count=${graph_cycle_count}"

proof_failures=0
proof_count="$(jq '.proof_commands | length' "$cases_json")"
for ((i = 0; i < proof_count; i++)); do
  proof_id="$(jq -r ".proof_commands[$i].id" "$cases_json")"
  expected_exit="$(jq -r ".proof_commands[$i].expected_exit_code" "$cases_json")"
  stdout_path="${proof_dir}/${proof_id}.stdout"
  stderr_path="${proof_dir}/${proof_id}.stderr"
  mapfile -t proof_argv < <(jq -r ".proof_commands[$i].argv[]" "$cases_json")
  print_command "$proof_id" "${proof_argv[@]}"
  code=0
  set +e
  "${proof_argv[@]}" >"$stdout_path" 2>"$stderr_path"
  code=$?
  set -e
  record_proof "$proof_id" "$code" "$expected_exit" "$stdout_path" "$stderr_path"
  if [[ "$code" -ne "$expected_exit" ]]; then
    proof_failures=$((proof_failures + 1))
  fi
done
write_event "proofs.checked" "checked" "$proof_failures" "${proof_failures} proof command failures"

jq -n \
  --arg schema_version "franken-engine.native-dependency-track-closeout-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg parent_bead_id "$parent_id" \
  --arg graph_cycle_count "$graph_cycle_count" \
  --argjson artifact_failures "$artifact_failures" \
  --argjson bead_failures "$bead_failures" \
  --argjson dependency_failures "$dependency_failures" \
  --argjson parent_child_failures "$parent_child_failures" \
  --argjson proof_failures "$proof_failures" \
  --argjson graph_ok "$graph_ok" \
  --slurpfile cases "$cases_json" \
  --slurpfile artifacts "$artifact_results_path" \
  --slurpfile beads "$bead_results_path" \
  --slurpfile dependencies "$dependency_results_path" \
  --slurpfile proofs "$proof_results_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    parent_bead_id: $parent_bead_id,
    deterministic_fixture_proof: true,
    live_rch_required: false,
    live_rch_operator_proof_optional: true,
    graph: {
      tool: "bv --robot-insights",
      cycle_count: ($graph_cycle_count | tonumber),
      ok: $graph_ok
    },
    artifacts: $artifacts,
    beads: $beads,
    dependencies: $dependencies,
    proof_commands: $proofs,
    failures: {
      artifacts: $artifact_failures,
      bead_statuses: $bead_failures,
      dependencies: $dependency_failures,
      parent_children: $parent_child_failures,
      proof_commands: $proof_failures,
      graph: (if $graph_ok then 0 else 1 end)
    },
    child_beads: $cases[0].child_beads,
    unverified_live_worker_assumptions: [
      "fixture evidence preserves observed HDF5 worker differences; live worker package state may drift after the fixture timestamp",
      "optional live rch proof must be rerun by an operator before treating current worker availability as fresh"
    ],
    complete: (
      $artifact_failures == 0
      and $bead_failures == 0
      and $dependency_failures == 0
      and $parent_child_failures == 0
      and $proof_failures == 0
      and $graph_ok
    )
  }' >"$manifest_path"

{
  printf '%s\n\n' '# Native Dependency Routing Track Closeout'
  printf '%s\n' "- parent_bead_id: \`${parent_id}\`"
  printf '%s\n' "- complete: \`$(jq -r '.complete' "$manifest_path")\`"
  printf '%s\n' "- graph_cycle_count: \`${graph_cycle_count}\`"
  printf '%s\n' "- artifact_failures: \`${artifact_failures}\`"
  printf '%s\n' "- bead_status_failures: \`${bead_failures}\`"
  printf '%s\n' "- dependency_failures: \`${dependency_failures}\`"
  printf '%s\n' "- proof_command_failures: \`${proof_failures}\`"
  printf '\n%s\n' 'Deterministic fixture proof covers all native dependency routing children and does not require live rch execution.'
  printf '%s\n' 'Live rch proof remains optional operator proof because worker native package state can drift.'
  printf '\n%s\n' '## Child Artifacts'
  jq -r '.child_beads[] | "- `" + .bead_id + "` " + .title + ": " + (.artifacts | map("`" + . + "`") | join(", "))' "$cases_json"
  printf '\n%s\n' '## Proof Commands'
  jq -r '.proof_commands[] | "- `" + .id + "`: `" + (.argv | join(" ")) + "`"' "$cases_json"
  printf '\n%s\n' '## Unverified Live Assumptions'
  jq -r '.unverified_live_worker_assumptions[] | "- " + .' "$manifest_path"
} >"$report_path"

if jq -e '.complete == true' "$manifest_path" >/dev/null; then
  exit 0
fi
exit 42
