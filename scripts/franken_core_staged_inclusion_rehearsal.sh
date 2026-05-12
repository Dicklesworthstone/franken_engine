#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${FRANKEN_CORE_STAGED_INCLUSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-core-staged-inclusion-rehearsal}"
run_id="${FRANKEN_CORE_STAGED_INCLUSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FRANKEN_CORE_STAGED_INCLUSION_RUN_DIR:-${artifact_root}/${run_id}}"
root_cargo="${root_dir}/Cargo.toml"
core_cargo="${root_dir}/crates/franken-core/Cargo.toml"
simulation_mode="${FRANKEN_CORE_STAGED_INCLUSION_MODE:-current}"
source_revision="${FRANKEN_CORE_STAGED_INCLUSION_SOURCE_REVISION:-}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/franken_core_staged_inclusion_rehearsal.sh [OPTIONS]

Options:
  --root-cargo PATH
  --core-cargo PATH
  --simulation-mode current|included_artifact
  --source-revision REV
  --output-dir DIR

The rehearsal is artifact-only. It does not edit Cargo.toml or run Cargo/RCH.
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
    --simulation-mode)
      simulation_mode="${2:-}"
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

case "$simulation_mode" in
  current|included_artifact)
    ;;
  *)
    printf 'unknown simulation mode: %s\n' "$simulation_mode" >&2
    exit 64
    ;;
esac

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/staged_inclusion_rehearsal.json"
patch_json="${run_dir}/simulated_workspace_patch.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
violations_jsonl="${run_dir}/violations.jsonl"
member_paths_json="${run_dir}/member_paths.json"
member_packages_jsonl="${run_dir}/member_packages.jsonl"

: >"$events_path"
: >"$violations_jsonl"
: >"$member_packages_jsonl"

printf './scripts/franken_core_staged_inclusion_rehearsal.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.franken-core-staged-inclusion-rehearsal.event.v1" \
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

toml_array_values() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    BEGIN { state = 0 }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (state == 0 && line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        state = 1
      }
      if (state == 1) {
        while (match(line, /"[^"]+"/)) {
          value = substr(line, RSTART + 1, RLENGTH - 2)
          print value
          line = substr(line, RSTART + RLENGTH)
        }
        if (index($0, "]") > 0) {
          exit
        }
      }
    }
  ' "$file"
}

toml_array_contains() {
  local file="$1"
  local key="$2"
  local value="$3"
  if toml_array_values "$file" "$key" | grep -Fxq "$value"; then
    printf 'true\n'
  else
    printf 'false\n'
  fi
}

package_name() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf '\n'
    return
  fi
  awk '
    BEGIN { in_package = 0 }
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ && in_package == 1 { in_package = 0 }
    in_package == 1 && /^[[:space:]]*name[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*name[[:space:]]*=[[:space:]]*"/, "", value)
      sub(/".*/, "", value)
      print value
      exit
    }
  ' "$file"
}

feature_keys() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi
  awk '
    BEGIN { in_features = 0 }
    /^\[features\][[:space:]]*$/ { in_features = 1; next }
    /^\[/ && in_features == 1 { in_features = 0 }
    in_features == 1 && /^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*/, "", value)
      sub(/[[:space:]]*=.*/, "", value)
      print value
    }
  ' "$file" | sort -u
}

write_event "staged_inclusion_start" "started" "modeling optional franken-core workspace inclusion"

for required_manifest in "$root_cargo" "$core_cargo"; do
  if [[ ! -f "$required_manifest" ]]; then
    append_violation \
      "missing_required_manifest" \
      "$required_manifest" \
      "required manifest missing" \
      "Restore the manifest before modeling workspace inclusion."
  fi
done

members_contains_core="missing"
exclude_contains_core="missing"
if [[ -f "$root_cargo" ]]; then
  toml_array_values "$root_cargo" "members" | jq -R . | jq -s 'map(select(length > 0))' >"$member_paths_json"
  members_contains_core="$(toml_array_contains "$root_cargo" "members" "crates/franken-core")"
  exclude_contains_core="$(toml_array_contains "$root_cargo" "exclude" "crates/franken-core")"
else
  jq -n '[]' >"$member_paths_json"
fi

root_workspace_state="unknown"
if [[ "$exclude_contains_core" == "true" && "$members_contains_core" == "false" ]]; then
  root_workspace_state="excluded_standalone"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "false" ]]; then
  root_workspace_state="included"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "true" ]]; then
  root_workspace_state="ambiguous_member_and_exclude"
else
  root_workspace_state="ambiguous_missing_member_and_exclude"
fi

if [[ "$simulation_mode" == "current" && "$root_workspace_state" != "excluded_standalone" ]]; then
  append_violation \
    "ambiguous_workspace_topology" \
    "$root_cargo" \
    "current mode expected excluded_standalone, got ${root_workspace_state}" \
    "Keep live root Cargo.toml excluded until a separate approved topology bead changes membership."
fi

if [[ "$simulation_mode" == "included_artifact" && "$root_workspace_state" != "included" ]]; then
  append_violation \
    "artifact_mode_state_mismatch" \
    "$root_cargo" \
    "included_artifact mode expected an included generated manifest, got ${root_workspace_state}" \
    "Use included_artifact mode only with a controlled generated manifest artifact that includes crates/franken-core and removes it from exclude."
fi

core_package_name="$(package_name "$core_cargo")"
if [[ -z "$core_package_name" ]]; then
  append_violation \
    "missing_required_manifest" \
    "$core_cargo" \
    "could not read franken-core package name" \
    "Keep crates/franken-core/Cargo.toml readable and named frankenengine-core."
fi

while IFS= read -r member_path; do
  member_manifest="$(dirname "$root_cargo")/${member_path}/Cargo.toml"
  member_name="$(package_name "$member_manifest")"
  if [[ -n "$member_name" ]]; then
    jq -nc \
      --arg member_path "$member_path" \
      --arg package_name "$member_name" \
      '{member_path:$member_path,package_name:$package_name}' >>"$member_packages_jsonl"
  fi
done < <(jq -r '.[]' "$member_paths_json")

if [[ -n "$core_package_name" ]] && jq -s -e --arg name "$core_package_name" 'any(.[]; .package_name == $name and .member_path != "crates/franken-core")' "$member_packages_jsonl" >/dev/null; then
  append_violation \
    "package_name_conflict" \
    "$core_cargo" \
    "package name ${core_package_name} already appears in current workspace members" \
    "Resolve package-name conflicts before workspace inclusion."
fi

core_features_json="$(feature_keys "$core_cargo" | jq -R . | jq -s 'map(select(length > 0))')"
member_packages_json="$(jq -s 'sort_by(.member_path)' "$member_packages_jsonl")"
risks_json="$(jq -n --argjson core_features "$core_features_json" '[
  {risk_id:"workspace_membership_blast_radius", severity:"high", detail:"Adding crates/franken-core makes it part of all workspace all-target checks."},
  {risk_id:"feature_propagation", severity:(if ($core_features | length) > 0 then "medium" else "low" end), detail:"Core feature keys must not unexpectedly propagate into workspace default feature expectations.", observed_features:$core_features},
  {risk_id:"package_name_conflict", severity:"medium", detail:"Package names must remain unique across workspace members."},
  {risk_id:"validation_runtime_cost", severity:"high", detail:"Final proof requires workspace cargo check, clippy, and tests through rch."},
  {risk_id:"rollback_required", severity:"high", detail:"Rollback must restore root exclude and remove crates/franken-core from workspace members."}
]')"
validation_gates_json="$(jq -n '[
  "bash scripts/e2e/franken_core_validation_impact_planner_smoke.sh check",
  "bash scripts/e2e/franken_core_status_truth_gate_smoke.sh check",
  "bash scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh check",
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_inclusion CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets",
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_inclusion CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings",
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_inclusion CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test"
]')"
rollback_steps_json="$(jq -n '[
  "remove crates/franken-core from root workspace members",
  "restore crates/franken-core in root workspace exclude",
  "rerun status truth gate and no-mock drill",
  "rerun final rch-wrapped workspace validation gates"
]')"

if [[ "$simulation_mode" == "included_artifact" ]]; then
  patch_action="modeled_generated_included_manifest"
else
  patch_action="model_optional_inclusion_from_current_excluded_state"
fi

jq -n \
  --arg schema_version "franken-engine.franken-core-simulated-workspace-patch.v1" \
  --arg patch_action "$patch_action" \
  --arg from_state "$root_workspace_state" \
  --arg mode "$simulation_mode" \
  '{
    schema_version:$schema_version,
    patch_action:$patch_action,
    simulation_mode:$mode,
    mutates_root_cargo_toml:false,
    from:{root_workspace_state:$from_state},
    simulated_to:{
      add_members:["crates/franken-core"],
      remove_exclude:["crates/franken-core"],
      expected_root_workspace_state:"included"
    }
  }' >"$patch_json"

violations_json="$(jq -s 'sort_by(.code, .path, .detail)' "$violations_jsonl")"
reason_codes_json="$(jq -s '[.[].code] | unique | sort' "$violations_jsonl")"
violation_count="$(jq -s 'length' "$violations_jsonl")"
decision="pass"
if [[ "$violation_count" -ne 0 ]]; then
  decision="fail_closed"
fi

jq -n \
  --arg schema_version "franken-engine.franken-core-staged-inclusion-rehearsal-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg simulation_mode "$simulation_mode" \
  --arg root_workspace_state "$root_workspace_state" \
  --arg members_contains_core "$members_contains_core" \
  --arg exclude_contains_core "$exclude_contains_core" \
  --arg core_package_name "$core_package_name" \
  --argjson core_features "$core_features_json" \
  --argjson member_paths "$(cat "$member_paths_json")" \
  --argjson member_packages "$member_packages_json" \
  --argjson risks "$risks_json" \
  --argjson validation_gates "$validation_gates_json" \
  --argjson rollback_steps "$rollback_steps_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson violation_count "$violation_count" \
  --argjson violations "$violations_json" \
  --arg report_json "$report_json" \
  --arg patch_json "$patch_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    decision:$decision,
    simulation_mode:$simulation_mode,
    root_workspace_state:$root_workspace_state,
    mutates_root_cargo_toml:false,
    creates_generated_manifest_file:false,
    manifest_state:{
      members_contains_crates_franken_core:$members_contains_core,
      exclude_contains_crates_franken_core:$exclude_contains_core,
      current_workspace_members:$member_paths,
      current_workspace_member_packages:$member_packages,
      core_package_name:$core_package_name,
      core_feature_keys:$core_features
    },
    simulated_workspace_patch:{
      add_members:["crates/franken-core"],
      remove_exclude:["crates/franken-core"],
      expected_root_workspace_state:"included"
    },
    risks:$risks,
    validation_gates:$validation_gates,
    rollback_steps:$rollback_steps,
    reason_codes:$reason_codes,
    violation_count:$violation_count,
    violations:$violations,
    final_acceptance_inputs:[
      "docs/franken_core_graduation_contract_v1.json",
      "docs/franken_core_api_parity_ledger_v1.json",
      "docs/franken_core_validation_impact_planner_v1.json",
      "docs/franken_core_status_truth_gate_v1.json",
      "docs/franken_core_no_mock_graduation_drill_v1.json",
      "docs/franken_core_staged_inclusion_rehearsal_v1.json"
    ],
    non_mutation_attestation:{
      mutates_root_cargo_toml:false,
      creates_generated_manifest_file:false,
      runs_cargo:false,
      runs_rch:false
    },
    artifact_paths:{
      staged_inclusion_rehearsal_json:$report_json,
      simulated_workspace_patch_json:$patch_json,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_md
    }
  }' >"$report_json"

jq -nc \
  --arg schema_version "franken-engine.franken-core-staged-inclusion-rehearsal.event.v1" \
  --arg event "staged_inclusion_complete" \
  --arg outcome "$decision" \
  --arg detail "franken-core staged inclusion rehearsal report emitted" \
  --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"

{
  printf '# Franken-Core Staged Inclusion Rehearsal\n\n'
  printf -- '- decision: `%s`\n' "$decision"
  printf -- '- simulation_mode: `%s`\n' "$simulation_mode"
  printf -- '- root_workspace_state: `%s`\n' "$root_workspace_state"
  printf -- '- mutates_root_cargo_toml: `false`\n'
  printf '\n## Validation Gates\n\n'
  jq -r '.validation_gates[] | "- " + .' "$report_json"
  printf '\n## Rollback Steps\n\n'
  jq -r '.rollback_steps[] | "- " + .' "$report_json"
  if [[ "$violation_count" -ne 0 ]]; then
    printf '\n## Fail-Closed Violations\n\n'
    jq -r '.violations[] | "- " + .code + " at " + .path + " - " + .remediation' "$report_json"
  fi
} >"$report_md"

{
  printf '\nvalidation gates:\n'
  jq -r '.validation_gates[] | "- " + .' "$report_json"
} >>"$commands_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
