#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${FRANKEN_CORE_VALIDATION_IMPACT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-core-validation-impact}"
run_id="${FRANKEN_CORE_VALIDATION_IMPACT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FRANKEN_CORE_VALIDATION_IMPACT_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${FRANKEN_CORE_VALIDATION_IMPACT_BEAD_ID:-bd-4w7h9.3}"
source_revision="${FRANKEN_CORE_VALIDATION_IMPACT_SOURCE_REVISION:-}"
original_args=("$@")
declare -a changed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/franken_core_validation_impact_planner.sh --changed-path PATH [OPTIONS]

Options:
  --bead-id ID
  --source-revision REV
  --output-dir DIR
  --changed-path PATH   May be repeated.

The planner is advisory only. It writes validation_impact_plan.json,
run_manifest.json, events.jsonl, commands.txt, and report.md.
EOF
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath -m --relative-to="$root_dir" "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      bead_id="${2:-}"
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
    --changed-path)
      changed_paths+=("$(repo_relative_path "${2:-}")")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      changed_paths+=("$(repo_relative_path "$1")")
      shift
      ;;
  esac
done

if [[ "${#changed_paths[@]}" -eq 0 ]]; then
  printf 'franken-core validation impact planner requires at least one --changed-path\n' >&2
  usage
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/validation_impact_plan.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
classes_jsonl="${run_dir}/change_classes.jsonl"
commands_jsonl="${run_dir}/recommended_commands.jsonl"
reasons_jsonl="${run_dir}/reason_codes.jsonl"
paths_json="${run_dir}/changed_paths.json"

: >"$events_path"
: >"$classes_jsonl"
: >"$commands_jsonl"
: >"$reasons_jsonl"

printf '%s\n' "${changed_paths[@]}" | jq -R . | jq -s 'map(select(length > 0)) | sort | unique' >"$paths_json"

printf './scripts/franken_core_validation_impact_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.franken-core-validation-impact.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg bead_id "$bead_id" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,bead_id:$bead_id,source_revision:$source_revision}' >>"$events_path"
}

add_class() {
  jq -nc --arg value "$1" '$value' >>"$classes_jsonl"
}

add_reason() {
  jq -nc --arg value "$1" '$value' >>"$reasons_jsonl"
}

add_command() {
  local command_id="$1"
  local display="$2"
  local command_kind="$3"
  local change_class="$4"
  local rationale="$5"

  jq -nc \
    --arg command_id "$command_id" \
    --arg display "$display" \
    --arg command_kind "$command_kind" \
    --arg change_class "$change_class" \
    --arg rationale "$rationale" \
    '{
      command_id: $command_id,
      display: $display,
      command_kind: $command_kind,
      change_class: $change_class,
      rationale: $rationale,
      rch_wrapped: (
        if ($command_kind | startswith("rch_cargo")) then
          ($display | startswith("rch exec -- env CARGO_TARGET_DIR="))
        else
          true
        end
      )
    }' >>"$commands_jsonl"
}

add_source_checks() {
  add_command "json-contracts" "jq empty docs/franken_core_graduation_contract_v1.json docs/franken_core_api_parity_ledger_v1.json docs/franken_core_validation_impact_planner_v1.json" "source_check" "docs_only" "Validate graduation JSON contracts."
  add_command "graduation-contract-smoke" "bash scripts/e2e/franken_core_graduation_contract_smoke.sh check" "source_check" "docs_only" "Validate the graduation contract surface."
  add_command "api-parity-smoke" "bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh check" "source_check" "docs_only" "Validate the API parity ledger surface."
}

add_script_checks() {
  add_command "shell-syntax" "bash -n scripts/franken_core_validation_impact_planner.sh scripts/e2e/franken_core_validation_impact_planner_smoke.sh" "source_check" "script_only" "Validate shell syntax for planner scripts."
}

add_diff_check() {
  add_command "diff-check" "git diff --check -- ${changed_paths[*]}" "source_check" "docs_only" "Reject whitespace errors in changed files."
}

add_core_rch() {
  add_command "franken-core-check" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_core CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --manifest-path crates/franken-core/Cargo.toml --all-targets" "rch_cargo_check" "franken_core_only" "Standalone franken-core all-target check."
  add_command "franken-core-clippy" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_core CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --manifest-path crates/franken-core/Cargo.toml --all-targets -- -D warnings" "rch_cargo_clippy" "franken_core_only" "Standalone franken-core lint gate."
  add_command "franken-core-test" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_core CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test --manifest-path crates/franken-core/Cargo.toml" "rch_cargo_test" "franken_core_only" "Standalone franken-core test gate."
  add_reason "standalone_core_validation_not_workspace_inclusion"
}

add_engine_rch() {
  add_command "engine-check" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_engine CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-engine --all-targets" "rch_cargo_check" "franken_engine_api_adjacent" "Engine package all-target check for API-adjacent changes."
  add_command "engine-clippy" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_engine CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy -p frankenengine-engine --all-targets -- -D warnings" "rch_cargo_clippy" "franken_engine_api_adjacent" "Engine package lint gate for API-adjacent changes."
}

add_extension_rch() {
  add_command "extension-host-check" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_extension_host CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-extension-host --all-targets" "rch_cargo_check" "extension_host_adjacent" "Extension-host package all-target check."
  add_command "extension-host-clippy" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_extension_host CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy -p frankenengine-extension-host --all-targets -- -D warnings" "rch_cargo_clippy" "extension_host_adjacent" "Extension-host package lint gate."
}

add_full_workspace_rch() {
  add_command "workspace-check" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_workspace CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets" "rch_cargo_check" "cargo_topology" "Full workspace check for unknown or topology-sensitive changes."
  add_command "workspace-clippy" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_workspace CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings" "rch_cargo_clippy" "cargo_topology" "Full workspace lint gate for unknown or topology-sensitive changes."
  add_command "workspace-test" "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_validation_workspace CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test" "rch_cargo_test" "cargo_topology" "Full workspace test gate for unknown or topology-sensitive changes."
}

classify_path() {
  local path="$1"
  case "$path" in
    docs/*|README.md|AGENTS.md|.beads/*)
      printf 'docs_only\n'
      ;;
    scripts/*)
      printf 'script_only\n'
      ;;
    Cargo.toml|crates/franken-core/Cargo.toml|crates/franken-engine/Cargo.toml|crates/franken-extension-host/Cargo.toml)
      printf 'cargo_topology\n'
      ;;
    crates/franken-core/*)
      printf 'franken_core_only\n'
      ;;
    crates/franken-engine/*)
      printf 'franken_engine_api_adjacent\n'
      ;;
    crates/franken-extension-host/*)
      printf 'extension_host_adjacent\n'
      ;;
    *)
      printf 'unknown_path\n'
      ;;
  esac
}

write_event "planner_start" "started" "classifying changed paths"

while IFS= read -r path; do
  change_class="$(classify_path "$path")"
  add_class "$change_class"
done < <(jq -r '.[]' "$paths_json")

classes_json="$(jq -s 'unique | sort' "$classes_jsonl")"
decision="green"
proof_sufficiency="sufficient_focused"

if jq -e 'index("unknown_path")' <<<"$classes_json" >/dev/null; then
  decision="fail_closed"
  proof_sufficiency="insufficient"
  add_reason "unknown_path_requires_full_agents_gate"
fi

if jq -e 'index("cargo_topology")' <<<"$classes_json" >/dev/null; then
  decision="fail_closed"
  proof_sufficiency="insufficient"
  add_reason "cargo_topology_requires_separate_membership_bead"
fi

if jq -e 'index("docs_only")' <<<"$classes_json" >/dev/null; then
  add_source_checks
fi
if jq -e 'index("script_only")' <<<"$classes_json" >/dev/null; then
  add_script_checks
fi
if jq -e 'index("franken_core_only")' <<<"$classes_json" >/dev/null; then
  add_core_rch
fi
if jq -e 'index("franken_engine_api_adjacent")' <<<"$classes_json" >/dev/null; then
  add_engine_rch
fi
if jq -e 'index("extension_host_adjacent")' <<<"$classes_json" >/dev/null; then
  add_extension_rch
fi
if [[ "$decision" == "fail_closed" ]]; then
  add_full_workspace_rch
fi
add_diff_check

unsafe_heavy_count="$(jq -s '[.[] | select((.command_kind | startswith("rch_cargo")) and (.rch_wrapped != true))] | length' "$commands_jsonl")"
if [[ "$unsafe_heavy_count" -ne 0 ]]; then
  decision="fail_closed"
  proof_sufficiency="insufficient"
  add_reason "bare_heavy_cargo_recommendation"
fi

recommended_commands_json="$(jq -s 'unique_by(.command_id) | sort_by(.command_id)' "$commands_jsonl")"
reason_codes_json="$(jq -s 'unique | sort' "$reasons_jsonl")"

jq -n \
  --arg schema_version "franken-engine.franken-core-validation-impact-plan.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg proof_sufficiency "$proof_sufficiency" \
  --argjson changed_paths "$(cat "$paths_json")" \
  --argjson change_classes "$classes_json" \
  --argjson recommended_commands "$recommended_commands_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson unsafe_heavy_count "$unsafe_heavy_count" \
  --arg run_dir "$run_dir" \
  --arg plan_path "$plan_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    source_revision: $source_revision,
    decision: $decision,
    proof_sufficiency: $proof_sufficiency,
    changed_paths: $changed_paths,
    change_classes: $change_classes,
    recommended_commands: $recommended_commands,
    reason_codes: $reason_codes,
    rch_policy: {
      advisory_only: true,
      executes_recommended_commands: false,
      required_heavy_cargo_prefix: "rch exec -- env CARGO_TARGET_DIR=",
      unsafe_heavy_command_count: $unsafe_heavy_count
    },
    workspace_inclusion_policy: {
      standalone_core_validation_sufficient_for_workspace_inclusion: false,
      acceptance_suite_required: "bd-4w7h9.8",
      separate_topology_change_required: true,
      workspace_inclusion_claim_supported: false
    },
    artifact_paths: {
      run_dir: $run_dir,
      validation_impact_plan_json: $plan_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$plan_path"

jq -n \
  --arg schema_version "franken-engine.franken-core-validation-impact.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg run_dir "$run_dir" \
  --arg decision "$decision" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    source_revision: $source_revision,
    run_dir: $run_dir,
    decision: $decision,
    artifacts: {
      validation_impact_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$manifest_path"

jq -nc \
  --arg schema_version "franken-engine.franken-core-validation-impact.event.v1" \
  --arg event "planner_complete" \
  --arg outcome "$decision" \
  --arg detail "validation impact plan emitted" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,bead_id:$bead_id,source_revision:$source_revision}' >>"$events_path"

{
  printf '# Franken-Core Validation Impact Plan\n\n'
  printf -- '- decision: `%s`\n' "$decision"
  printf -- '- proof_sufficiency: `%s`\n' "$proof_sufficiency"
  printf -- '- changed_paths: `%s`\n' "$(jq -r 'join(", ")' "$paths_json")"
  printf -- '- change_classes: `%s`\n' "$(jq -r 'join(", ")' <<<"$classes_json")"
  printf '\nRecommended commands are advisory only and were not executed.\n'
} >"$report_path"

printf 'recommended validation commands:\n' >>"$commands_path"
jq -r '.[] | "- " + .display' <<<"$recommended_commands_json" >>"$commands_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
