#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_VALIDATION_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-validation-planner}"
run_id="${SWARM_VALIDATION_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_VALIDATION_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_VALIDATION_PLANNER_BEAD_ID:-}"
source_revision="${SWARM_VALIDATION_PLANNER_SOURCE_REVISION:-}"
package_override=""
test_target_override=""
allow_broad="false"
declare -a changed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_validation_planner.sh --bead-id ID [OPTIONS] --changed-path PATH [...]

Options:
  --output-dir DIR          Write plan artifacts to DIR
  --source-revision REV     Source revision to record. Defaults to git rev-parse --short HEAD.
  --package PACKAGE         Optional package override for Rust path fallback.
  --test-target TARGET      Optional exact integration test target.
  --allow-broad             Permit broad all-targets planning. Default is fail-closed/no broad commands.
  --changed-path PATH       Path changed by the bead. May be repeated.

By default, artifacts are written outside the repository under TMPDIR.
The planner does not execute validation. It writes:
  plan.json
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --package)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      package_override="$2"
      shift 2
      ;;
    --test-target)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      test_target_override="$2"
      shift 2
      ;;
    --allow-broad)
      allow_broad="true"
      shift
      ;;
    --changed-path)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      changed_paths+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        changed_paths+=("$1")
        shift
      done
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      changed_paths+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$bead_id" ]]; then
  printf 'swarm-validation-planner requires --bead-id\n' >&2
  usage
  exit 64
fi

if [[ "${#changed_paths[@]}" -eq 0 ]]; then
  printf 'swarm-validation-planner requires at least one changed path\n' >&2
  usage
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/plan.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
commands_jsonl="${run_dir}/commands.jsonl"
budgets_jsonl="${run_dir}/proof_cost_budgets.jsonl"
mappings_jsonl="${run_dir}/path_mappings.jsonl"
warnings_jsonl="${run_dir}/warnings.jsonl"
omitted_jsonl="${run_dir}/omitted_commands.jsonl"
reasons_jsonl="${run_dir}/reason_codes.jsonl"
: >"$commands_jsonl"
: >"$budgets_jsonl"
: >"$mappings_jsonl"
: >"$warnings_jsonl"
: >"$omitted_jsonl"
: >"$reasons_jsonl"

safe_token() {
  tr -c '[:alnum:]_' '_' <<<"$1" | sed 's/_$//'
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$root_dir" "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

json_string_line() {
  jq -nc --arg value "$1" '$value'
}

add_reason() {
  json_string_line "$1" >>"$reasons_jsonl"
}

emit_warning() {
  local kind="$1"
  local detail="$2"

  jq -nc \
    --arg kind "$kind" \
    --arg detail "$detail" \
    '{kind: $kind, detail: $detail}' >>"$warnings_jsonl"
}

emit_omitted() {
  local kind="$1"
  local path="$2"
  local reason="$3"

  jq -nc \
    --arg kind "$kind" \
    --arg path "$path" \
    --arg reason "$reason" \
    '{kind: $kind, path: $path, reason: $reason}' >>"$omitted_jsonl"
}

emit_mapping() {
  local path="$1"
  local kind="$2"
  local package="$3"
  local target="$4"
  local rationale="$5"

  jq -nc \
    --arg path "$path" \
    --arg kind "$kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rationale "$rationale" \
    '{path: $path, kind: $kind, package: (if $package == "" then null else $package end), target: (if $target == "" then null else $target end), rationale: $rationale}' >>"$mappings_jsonl"
}

emit_command() {
  local command_id="$1"
  local display="$2"
  local command_kind="$3"
  local package="$4"
  local target="$5"
  local rationale="$6"

  jq -nc \
    --arg command_id "$command_id" \
    --arg display "$display" \
    --arg command_kind "$command_kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rationale "$rationale" \
    '{
      command_id: $command_id,
      display: $display,
      command_kind: $command_kind,
      package: (if $package == "" then null else $package end),
      target: (if $target == "" then null else $target end),
      rationale: $rationale
    }' >>"$commands_jsonl"
}

emit_budget() {
  local suite="$1"
  local package="$2"
  local max_compiled="$3"
  local max_linked="$4"
  local max_tests="$5"
  local max_libs="$6"

  jq -nc \
    --arg schema_version "franken-engine.focused-proof-cost-budget.v1" \
    --arg suite "$suite" \
    --arg package "$package" \
    --argjson max_compiled "$max_compiled" \
    --argjson max_linked "$max_linked" \
    --argjson max_tests "$max_tests" \
    --argjson max_libs "$max_libs" \
    '{
      schema_version: $schema_version,
      suite: $suite,
      package: $package,
      max_total_compiled_targets: $max_compiled,
      max_total_linked_targets: $max_linked,
      max_unexpected_targets: 0,
      max_targets_by_kind: {
        test: $max_tests,
        lib: $max_libs
      }
    }' >>"$budgets_jsonl"
}

package_for_path() {
  local path="$1"
  if [[ -n "$package_override" ]]; then
    printf '%s\n' "$package_override"
  elif [[ "$path" == crates/franken-engine/* ]]; then
    printf 'frankenengine-engine\n'
  elif [[ "$path" == crates/franken-extension-host/* ]]; then
    printf 'frankenengine-extension-host\n'
  else
    printf '\n'
  fi
}

target_from_test_path() {
  basename "$1" .rs
}

target_dir_for() {
  local suffix="$1"
  printf '/tmp/rch_target_franken_engine_%s_%s\n' "$(safe_token "$bead_id")" "$(safe_token "$suffix")"
}

plan_exact_test() {
  local path="$1"
  local package="$2"
  local target="$3"
  local suffix target_dir command_id command

  suffix="${package}_${target}"
  target_dir="$(target_dir_for "$suffix")"
  command_id="cargo-test-$(safe_token "$target")"
  command="rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p ${package} --test ${target}"
  emit_command "$command_id" "$command" "rch_cargo_test" "$package" "$target" "exact test target inferred from changed integration test path"
  emit_budget "$target" "$package" 2 1 1 1
  emit_mapping "$path" "exact_test_target" "$package" "$target" "changed integration test maps to its exact test target"
  add_reason "exact_test_target"
}

plan_package_fallback() {
  local path="$1"
  local package="$2"
  local suffix target_dir command_id command

  suffix="${package}_lib"
  target_dir="$(target_dir_for "$suffix")"
  command_id="cargo-check-$(safe_token "$package")-lib"
  command="rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo check -p ${package} --lib"
  emit_command "$command_id" "$command" "rch_cargo_check_lib" "$package" "lib" "package lib fallback for source changes without an exact test target"
  emit_budget "${package}_lib" "$package" 1 0 0 1
  emit_mapping "$path" "package_lib_fallback" "$package" "lib" "source path maps to package-level lib check without broad all-targets fanout"
  add_reason "package_lib_fallback"
}

plan_script() {
  local path="$1"
  local command_id

  command_id="bash-n-$(safe_token "$path")"
  emit_command "$command_id" "bash -n ${path}" "shell_syntax" "" "" "script syntax validation"
  emit_command "shellcheck-$(safe_token "$path")" "shellcheck -x ${path}" "shellcheck" "" "" "script static analysis"
  emit_mapping "$path" "script_only" "" "" "shell script changes need syntax/static checks, not Cargo"
  add_reason "script_only"
}

plan_docs() {
  local path="$1"

  if [[ "$path" == *.json ]]; then
    emit_command "jq-empty-$(safe_token "$path")" "jq empty ${path}" "json_syntax" "" "" "JSON contract syntax validation"
  fi
  emit_command "diff-check-$(safe_token "$path")" "git diff --check -- ${path}" "diff_check" "" "" "docs whitespace validation"
  emit_mapping "$path" "docs_only" "" "" "docs changes do not require Cargo"
  add_reason "docs_only"
}

for raw_path in "${changed_paths[@]}"; do
  path="$(repo_relative_path "$raw_path")"
  package="$(package_for_path "$path")"

  case "$path" in
    crates/franken-engine/tests/*.rs|crates/franken-extension-host/tests/*.rs)
      target="${test_target_override:-$(target_from_test_path "$path")}"
      plan_exact_test "$path" "$package" "$target"
      ;;
    crates/franken-engine/src/*.rs|crates/franken-extension-host/src/*.rs)
      if [[ -n "$test_target_override" ]]; then
        plan_exact_test "$path" "$package" "$test_target_override"
        emit_mapping "$path" "source_with_operator_test_target" "$package" "$test_target_override" "operator supplied exact test target for source change"
        add_reason "operator_test_target"
      elif [[ -n "$package" ]]; then
        plan_package_fallback "$path" "$package"
      else
        emit_omitted "unknown_path_mapping" "$path" "Rust path does not map to a known workspace package"
        add_reason "unknown_path_mapping"
      fi
      ;;
    scripts/*.sh)
      plan_script "$path"
      ;;
    docs/*.json|docs/*.md|README.md|AGENTS.md)
      plan_docs "$path"
      ;;
    .beads/issues.jsonl)
      emit_command "jq-empty-beads" "jq empty .beads/issues.jsonl" "jsonl_syntax" "" "" "beads JSONL validation"
      emit_mapping "$path" "tracker_only" "" "" "tracker updates validate with JSONL parse only"
      add_reason "tracker_only"
      ;;
    *)
      emit_omitted "unknown_path_mapping" "$path" "No focused validation mapping exists for this path"
      add_reason "unknown_path_mapping"
      ;;
  esac
done

if [[ "$allow_broad" == "true" ]]; then
  emit_warning "broad_validation_allowed" "operator passed --allow-broad, but this planner still prefers focused commands"
else
  emit_omitted "broad_all_targets" "*" "Broad all-targets checks are intentionally omitted unless a later artifact justifies them"
fi

dirty_status="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE-__unset__}"
if [[ "$dirty_status" == "__unset__" ]]; then
  dirty_status="$(git -C "$root_dir" status --short --untracked-files=normal 2>/dev/null || true)"
fi

if [[ -n "$dirty_status" ]]; then
  while IFS= read -r status_line; do
    [[ -z "$status_line" ]] && continue
    dirty_path="${status_line:3}"
    dirty_path="${dirty_path# }"
    dirty_path="${dirty_path#\"}"
    dirty_path="${dirty_path%\"}"
    matched="false"
    for raw_path in "${changed_paths[@]}"; do
      rel_changed="$(repo_relative_path "$raw_path")"
      if [[ "$dirty_path" == "$rel_changed" ]]; then
        matched="true"
      fi
    done
    if [[ "$matched" == "true" ]]; then
      emit_warning "dirty_changed_path" "$dirty_path is dirty and part of the requested validation plan"
    else
      emit_warning "unrelated_dirty_worktree" "$dirty_path is dirty but outside the requested validation plan"
    fi
  done <<<"$dirty_status"
fi

command_count="$(jq -s 'length' "$commands_jsonl")"
unknown_count="$(jq -s '[.[] | select(.kind == "unknown_path_mapping" or .kind == "missing_file")] | length' "$omitted_jsonl")"
fallback_count="$(jq -s '[.[] | select(.kind == "package_lib_fallback")] | length' "$mappings_jsonl")"
decision="admit"
if [[ "$unknown_count" -ne 0 || "$command_count" -eq 0 ]]; then
  decision="fail_closed"
elif [[ "$fallback_count" -ne 0 ]]; then
  decision="admit_narrow"
fi

jq -s 'sort_by(.command_id) | unique_by(.command_id)' "$commands_jsonl" >"${commands_jsonl}.tmp"
mv "${commands_jsonl}.tmp" "$commands_jsonl"
jq -r '.[].display' "$commands_jsonl" >"$commands_path"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-validation-plan.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg run_dir "$run_dir" \
  --arg plan_path "$plan_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson allow_broad "$allow_broad" \
  --argjson changed_paths "$(printf '%s\n' "${changed_paths[@]}" | while IFS= read -r p; do repo_relative_path "$p"; done | jq -R . | jq -s 'sort | unique')" \
  --slurpfile mappings "$mappings_jsonl" \
  --slurpfile commands "$commands_jsonl" \
  --slurpfile budgets "$budgets_jsonl" \
  --slurpfile warnings "$warnings_jsonl" \
  --slurpfile omitted "$omitted_jsonl" \
  --slurpfile reasons "$reasons_jsonl" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    source_revision: $source_revision,
    decision: $decision,
    allow_broad: $allow_broad,
    reason_codes: ($reasons | sort | unique),
    changed_paths: $changed_paths,
    path_mappings: ($mappings | sort_by(.path, .kind)),
    commands: $commands[0],
    omitted_commands: ($omitted | sort_by(.kind, .path)),
    warnings: $warnings,
    proof_cost_budgets: ($budgets | sort_by(.suite, .package) | unique_by(.suite, .package)),
    expected_artifacts: [
      {path: $plan_path, role: "validation_plan"},
      {path: $commands_path, role: "command_transcript"},
      {path: $report_path, role: "operator_report"}
    ],
    artifact_paths: {
      run_dir: $run_dir,
      plan_json: $plan_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$plan_path"

{
  printf '# Swarm Validation Plan\n\n'
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Commands: \`%s\`\n" "$(jq '.commands | length' "$plan_path")"
  printf -- "- Omitted: \`%s\`\n" "$(jq '.omitted_commands | length' "$plan_path")"
  printf -- "- Warnings: \`%s\`\n\n" "$(jq '.warnings | length' "$plan_path")"
  jq -r '.commands[]? | "- `" + .command_id + "`: " + .display' "$plan_path"
  if [[ "$(jq '.omitted_commands | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Omitted\n\n'
    jq -r '.omitted_commands[] | "- `" + .kind + "` for `" + .path + "`: " + .reason' "$plan_path"
  fi
} >"$report_path"

printf 'swarm_validation_plan=%s\n' "$plan_path"
printf 'swarm_validation_commands=%s\n' "$commands_path"
printf 'swarm_validation_report=%s\n' "$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
