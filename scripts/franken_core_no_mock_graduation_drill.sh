#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${FRANKEN_CORE_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-core-no-mock-graduation-drill}"
run_id="${FRANKEN_CORE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FRANKEN_CORE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
root_cargo="${root_dir}/Cargo.toml"
core_cargo="${root_dir}/crates/franken-core/Cargo.toml"
core_lib="${root_dir}/crates/franken-core/src/lib.rs"
engine_lib="${root_dir}/crates/franken-engine/src/lib.rs"
source_revision="${FRANKEN_CORE_NO_MOCK_DRILL_SOURCE_REVISION:-}"
declare -a claim_files=()
declare -a proof_commands=()
original_args=("$@")

selected_modules=(
  "object_model"
  "promise_model"
  "profiling"
  "control_plane"
  "capability"
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/franken_core_no_mock_graduation_drill.sh [OPTIONS]

Options:
  --root-cargo PATH
  --core-cargo PATH
  --core-lib PATH
  --engine-lib PATH
  --claim-file PATH              May be repeated.
  --required-proof-command CMD   May be repeated.
  --source-revision REV
  --output-dir DIR

The drill is read-only. It writes graduation_drill_report.json, events.jsonl,
commands.txt, and report.md. It exits 42 on fail-closed contradictions.
EOF
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$root_dir" "$path" 2>/dev/null || printf '%s\n' "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --root-cargo)
      root_cargo="${2:-}"
      shift 2
      ;;
    --core-cargo)
      core_cargo="${2:-}"
      shift 2
      ;;
    --core-lib)
      core_lib="${2:-}"
      shift 2
      ;;
    --engine-lib)
      engine_lib="${2:-}"
      shift 2
      ;;
    --claim-file)
      claim_files+=("${2:-}")
      shift 2
      ;;
    --required-proof-command)
      proof_commands+=("${2:-}")
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

if [[ "${#claim_files[@]}" -eq 0 ]]; then
  claim_files=(
    "${root_dir}/Cargo.toml"
    "${root_dir}/crates/franken-core/README.md"
    "${root_dir}/docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md"
    "${root_dir}/docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md"
    "${root_dir}/docs/FRANKEN_CORE_VALIDATION_IMPACT_PLANNER_V1.md"
    "${root_dir}/docs/FRANKEN_CORE_STATUS_TRUTH_GATE_V1.md"
    "${root_dir}/docs/FRANKEN_CORE_NO_MOCK_GRADUATION_DRILL_V1.md"
    "${root_dir}/docs/franken_core_no_mock_graduation_drill_v1.json"
  )
fi

if [[ "${#proof_commands[@]}" -eq 0 ]]; then
  proof_commands=(
    "bash scripts/e2e/franken_core_validation_impact_planner_smoke.sh check"
    "bash scripts/e2e/franken_core_status_truth_gate_smoke.sh check"
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_drill CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --manifest-path crates/franken-core/Cargo.toml --all-targets"
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_final CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets"
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_final CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings"
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_final CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test"
  )
fi

mkdir -p "$run_dir"
report_json="${run_dir}/graduation_drill_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
violations_jsonl="${run_dir}/violations.jsonl"
module_evidence_jsonl="${run_dir}/module_evidence.jsonl"
claim_files_json="${run_dir}/claim_files.json"
proof_commands_json="${run_dir}/proof_commands.json"

: >"$events_path"
: >"$violations_jsonl"
: >"$module_evidence_jsonl"

printf './scripts/franken_core_no_mock_graduation_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

printf '%s\n' "${claim_files[@]}" | jq -R . | jq -s 'map(select(length > 0))' >"$claim_files_json"
printf '%s\n' "${proof_commands[@]}" | jq -R . | jq -s 'map(select(length > 0))' >"$proof_commands_json"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.franken-core-no-mock-graduation-drill.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

append_violation() {
  local code="$1"
  local path="$2"
  local detail="$3"
  local remediation="$4"
  jq -nc \
    --arg code "$code" \
    --arg path "$(repo_relative_path "$path")" \
    --arg detail "$detail" \
    --arg remediation "$remediation" \
    '{code:$code,path:$path,detail:$detail,remediation:$remediation}' >>"$violations_jsonl"
}

toml_array_contains() {
  local file="$1"
  local key="$2"
  local value="$3"
  awk -v key="$key" -v value="$value" '
    BEGIN { state = 0; found = 0; closed = 0 }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (state == 0 && line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        state = 1
      }
      if (state == 1) {
        if (index(line, "\"" value "\"") > 0) {
          found = 1
        }
        if (index(line, "]") > 0) {
          closed = 1
          exit
        }
      }
    }
    END {
      if (state == 0) {
        print "missing"
      } else if (closed == 0) {
        print "malformed"
      } else if (found == 1) {
        print "true"
      } else {
        print "false"
      }
    }
  ' "$file"
}

core_package_state() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf 'missing\n'
    return
  fi
  if awk '
    BEGIN { in_package = 0; found = 0 }
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ && in_package == 1 { in_package = 0 }
    in_package == 1 && /^[[:space:]]*name[[:space:]]*=[[:space:]]*"frankenengine-core"[[:space:]]*$/ { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$file"; then
    printf 'present\n'
  else
    printf 'malformed\n'
  fi
}

extract_pub_mods() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi
  awk '
    /^[[:space:]]*pub[[:space:]]+mod[[:space:]]+[A-Za-z0-9_]+[[:space:]]*;/ {
      value = $0
      sub(/^[[:space:]]*pub[[:space:]]+mod[[:space:]]+/, "", value)
      sub(/[[:space:]]*;.*/, "", value)
      print value
    }
  ' "$file" | sort -u
}

module_export_present() {
  local module="$1"
  local mods_file="$2"
  grep -Fxq "$module" "$mods_file"
}

module_source_path() {
  local src_dir="$1"
  local module="$2"
  if [[ -f "${src_dir}/${module}.rs" ]]; then
    printf '%s\n' "${src_dir}/${module}.rs"
  elif [[ -f "${src_dir}/${module}/mod.rs" ]]; then
    printf '%s\n' "${src_dir}/${module}/mod.rs"
  else
    printf '\n'
  fi
}

line_mentions_core() {
  local lower="$1"
  [[ "$lower" == *"franken-core"* || "$lower" == *"franken_core"* || "$lower" == *"frankenengine-core"* ]]
}

line_has_overclaim() {
  local lower="$1"
  [[ "$lower" == *"workspace-ready"* ||
     "$lower" == *"workspace ready"* ||
     "$lower" == *"included in the workspace"* ||
     "$lower" == *"included in workspace"* ||
     "$lower" == *"workspace member"* ||
     "$lower" == *"workspace inclusion complete"* ||
     "$lower" == *"workspace inclusion is complete"* ||
     "$lower" == *"graduation complete"* ||
     "$lower" == *"ready for workspace inclusion"* ]]
}

line_negates_overclaim() {
  local lower="$1"
  [[ "$lower" == *"not "* ||
     "$lower" == *"must not"* ||
     "$lower" == *"false"* ||
     "$lower" == *"blocked"* ||
     "$lower" == *"unapproved"* ||
     "$lower" == *"until"* ||
     "$lower" == *"do not"* ||
     "$lower" == *"does not"* ||
     "$lower" == *"read-only"* ||
     "$lower" == *"over-eager"* ||
     "$lower" == *"remains excluded"* ||
     "$lower" == *"separate topology"* ]]
}

is_heavy_cargo_command() {
  local command="$1"
  [[ "$command" == *"cargo check"* ||
     "$command" == *"cargo clippy"* ||
     "$command" == *"cargo test"* ||
     "$command" == *"cargo build"* ]]
}

write_event "graduation_drill_start" "started" "checking real franken-core graduation surfaces"

for required_path in "$root_cargo" "$core_cargo" "$core_lib" "$engine_lib"; do
  if [[ ! -f "$required_path" ]]; then
    append_violation \
      "missing_required_manifest_or_source" \
      "$required_path" \
      "required manifest/source path is missing" \
      "Restore the required real manifest or source file before claiming graduation readiness."
  fi
done

members_contains_core="missing"
exclude_contains_core="missing"
if [[ -f "$root_cargo" ]]; then
  members_contains_core="$(toml_array_contains "$root_cargo" "members" "crates/franken-core")"
  exclude_contains_core="$(toml_array_contains "$root_cargo" "exclude" "crates/franken-core")"
fi

root_workspace_state="unknown"
if [[ "$exclude_contains_core" == "true" && "$members_contains_core" == "false" ]]; then
  root_workspace_state="excluded_standalone"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "false" ]]; then
  root_workspace_state="included"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "true" ]]; then
  root_workspace_state="contradictory_member_and_exclude"
else
  root_workspace_state="unclassified"
fi

if [[ "$root_workspace_state" != "excluded_standalone" ]]; then
  append_violation \
    "root_manifest_state_contradicts_excluded_drill" \
    "$root_cargo" \
    "members contains crates/franken-core: ${members_contains_core}; exclude contains crates/franken-core: ${exclude_contains_core}" \
    "Keep crates/franken-core excluded until the staged rehearsal and bd-4w7h9.8 acceptance suite approve a separate topology change."
fi

core_manifest_state="$(core_package_state "$core_cargo")"
if [[ "$core_manifest_state" != "present" ]]; then
  append_violation \
    "missing_required_manifest_or_source" \
    "$core_cargo" \
    "core package manifest state: ${core_manifest_state}" \
    "Keep crates/franken-core/Cargo.toml present with package name frankenengine-core."
fi

core_mods_file="${run_dir}/core_pub_mods.txt"
engine_mods_file="${run_dir}/engine_pub_mods.txt"
extract_pub_mods "$core_lib" >"$core_mods_file"
extract_pub_mods "$engine_lib" >"$engine_mods_file"

core_src_dir="$(dirname "$core_lib")"
engine_src_dir="$(dirname "$engine_lib")"
for module in "${selected_modules[@]}"; do
  core_export=false
  engine_export=false
  if module_export_present "$module" "$core_mods_file"; then
    core_export=true
  fi
  if module_export_present "$module" "$engine_mods_file"; then
    engine_export=true
  fi
  core_source="$(module_source_path "$core_src_dir" "$module")"
  engine_source="$(module_source_path "$engine_src_dir" "$module")"

  if [[ "$core_export" != "true" || "$engine_export" != "true" || -z "$core_source" || -z "$engine_source" ]]; then
    append_violation \
      "missing_required_manifest_or_source" \
      "$core_lib" \
      "selected module ${module}: core_export=${core_export}; engine_export=${engine_export}; core_source=$(repo_relative_path "${core_source:-missing}"); engine_source=$(repo_relative_path "${engine_source:-missing}")" \
      "Keep selected franken-core and franken-engine module exports and source files readable before claiming graduation readiness."
  fi

  jq -nc \
    --arg module "$module" \
    --arg core_source "$(repo_relative_path "${core_source:-}")" \
    --arg engine_source "$(repo_relative_path "${engine_source:-}")" \
    --arg core_export "$core_export" \
    --arg engine_export "$engine_export" \
    '{
      module:$module,
      core_export_present:($core_export == "true"),
      engine_export_present:($engine_export == "true"),
      core_source_path:$core_source,
      engine_source_path:$engine_source
    }' >>"$module_evidence_jsonl"
done

while IFS= read -r claim_file; do
  if [[ ! -f "$claim_file" ]]; then
    append_violation \
      "missing_required_manifest_or_source" \
      "$claim_file" \
      "claim file is missing" \
      "Restore the real claim file or remove it from the drill input set."
    continue
  fi
  previous_lower=""
  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    lower="${line,,}"
    combined_lower="${previous_lower} ${lower}"
    if [[ "$root_workspace_state" == "excluded_standalone" ]] && line_mentions_core "$lower" && line_has_overclaim "$lower" && ! line_negates_overclaim "$combined_lower"; then
      append_violation \
        "doc_manifest_contradiction" \
        "$claim_file" \
        "line ${line_number}: ${line}" \
        "Replace included/workspace-ready wording with excluded-but-standalone-compileable wording until bd-4w7h9.8 passes."
    fi
    previous_lower="$lower"
  done <"$claim_file"
done < <(jq -r '.[]' "$claim_files_json")

while IFS= read -r command; do
  if is_heavy_cargo_command "$command" && [[ "$command" != rch\ exec\ --\ env\ CARGO_TARGET_DIR=* ]]; then
    append_violation \
      "bare_heavy_cargo_proof" \
      "$commands_path" \
      "$command" \
      "Wrap heavy Rust proof commands as: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_<purpose> ..."
  fi
done < <(jq -r '.[]' "$proof_commands_json")

violations_json="$(jq -s 'sort_by(.code, .path, .detail)' "$violations_jsonl")"
reason_codes_json="$(jq -s '[.[].code] | unique | sort' "$violations_jsonl")"
module_evidence_json="$(jq -s 'sort_by(.module)' "$module_evidence_jsonl")"
violation_count="$(jq -s 'length' "$violations_jsonl")"
decision="pass"
if [[ "$violation_count" -ne 0 ]]; then
  decision="fail_closed"
fi

proofs_still_needed_json="$(jq -n '[
  "bd-4w7h9.3 validation impact planner remains green for changed paths",
  "bd-4w7h9.5 status truth gate remains green against live docs and manifests",
  "bd-4w7h9.6 staged-inclusion rehearsal models topology blast radius without mutating root Cargo.toml",
  "bd-4w7h9.7 golden artifacts cover graduation reports",
  "bd-4w7h9.8 final acceptance suite passes",
  "final Cargo check, clippy, and test gates run through rch with explicit CARGO_TARGET_DIR"
]')"

jq -n \
  --arg schema_version "franken-engine.franken-core-no-mock-graduation-drill-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg root_workspace_state "$root_workspace_state" \
  --arg members_contains_core "$members_contains_core" \
  --arg exclude_contains_core "$exclude_contains_core" \
  --arg core_manifest_state "$core_manifest_state" \
  --argjson selected_modules "$(printf '%s\n' "${selected_modules[@]}" | jq -R . | jq -s '.')" \
  --argjson module_evidence "$module_evidence_json" \
  --argjson claim_files "$(cat "$claim_files_json")" \
  --argjson proof_commands "$(cat "$proof_commands_json")" \
  --argjson proofs_still_needed "$proofs_still_needed_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson violation_count "$violation_count" \
  --argjson violations "$violations_json" \
  --arg report_json "$report_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    decision:$decision,
    root_workspace_state:$root_workspace_state,
    manifest_state:{
      members_contains_crates_franken_core:$members_contains_core,
      exclude_contains_crates_franken_core:$exclude_contains_core,
      core_manifest_state:$core_manifest_state
    },
    workspace_membership_mutated:false,
    workspace_inclusion_ready:false,
    selected_modules:$selected_modules,
    module_evidence:$module_evidence,
    claim_files:$claim_files,
    proof_commands:$proof_commands,
    proofs_still_needed:$proofs_still_needed,
    reason_codes:$reason_codes,
    violation_count:$violation_count,
    violations:$violations,
    non_mutation_attestation:{
      rewrites_docs:false,
      edits_manifests:false,
      runs_cargo:false,
      runs_rch:false,
      changes_workspace_membership:false
    },
    artifact_paths:{
      graduation_drill_report_json:$report_json,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_md
    }
  }' >"$report_json"

jq -nc \
  --arg schema_version "franken-engine.franken-core-no-mock-graduation-drill.event.v1" \
  --arg event "graduation_drill_complete" \
  --arg outcome "$decision" \
  --arg detail "franken-core no-mock graduation drill report emitted" \
  --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"

{
  printf '# Franken-Core No-Mock Graduation Drill\n\n'
  printf -- '- decision: `%s`\n' "$decision"
  printf -- '- root_workspace_state: `%s`\n' "$root_workspace_state"
  printf -- '- workspace_inclusion_ready: `false`\n'
  printf -- '- violation_count: `%s`\n' "$violation_count"
  printf '\n## Proofs Still Needed\n\n'
  jq -r '.proofs_still_needed[] | "- " + .' "$report_json"
  if [[ "$violation_count" -ne 0 ]]; then
    printf '\n## Fail-Closed Violations\n\n'
    jq -r '.violations[] | "- " + .code + " at " + .path + " - " + .remediation' "$report_json"
  fi
} >"$report_md"

{
  printf '\nrecommended proof commands:\n'
  jq -r '.[] | "- " + .' "$proof_commands_json"
} >>"$commands_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
