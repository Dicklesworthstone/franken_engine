#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_VALIDATION_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-validation-planner}"
run_id="${SWARM_VALIDATION_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_VALIDATION_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_VALIDATION_PLANNER_BEAD_ID:-}"
source_revision="${SWARM_VALIDATION_PLANNER_SOURCE_REVISION:-}"
proof_cost_history_json="${SWARM_VALIDATION_PLANNER_PROOF_COST_HISTORY_JSON:-}"
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
  --proof-cost-history-json PATH
                            Optional franken-engine.proof-cost-history.v1 artifact for cost prediction.
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
    --proof-cost-history-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      proof_cost_history_json="$2"
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
cost_rows_json="${run_dir}/proof_cost_history_rows.json"
: >"$commands_jsonl"
: >"$budgets_jsonl"
: >"$mappings_jsonl"
: >"$warnings_jsonl"
: >"$omitted_jsonl"
: >"$reasons_jsonl"
printf '[]\n' >"$cost_rows_json"

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

normalize_cost_history() {
  if [[ -z "$proof_cost_history_json" ]]; then
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  if [[ ! -f "$proof_cost_history_json" ]]; then
    emit_omitted "missing_cost_history" "$proof_cost_history_json" "Proof-cost history file does not exist"
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  if ! jq -e \
    --arg schema_version "franken-engine.proof-cost-history.v1" \
    '.schema_version == $schema_version and (.rows | type == "array")' \
    "$proof_cost_history_json" >/dev/null; then
    emit_omitted "invalid_cost_history" "$proof_cost_history_json" "Proof-cost history must use franken-engine.proof-cost-history.v1 with rows[]"
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  jq \
    --arg evidence_source "$proof_cost_history_json" \
    '[
      . as $doc
      | ($doc.rows // [])[]
      | {
          command_id: (.command_id // ""),
          package: (.package // ""),
          target: (.target // ""),
          source_revision: (.source_revision // $doc.source_revision // ""),
          elapsed_ms: (.elapsed_ms // 0),
          compiled_target_count: (.compiled_target_count // 0),
          linked_target_count: (.linked_target_count // 0),
          rch_worker: (.rch_worker // ""),
          rch_status: (.rch_status // ""),
          fallback_detected: (.fallback_detected // false),
          content_hash: (.content_hash // ""),
          artifact_paths: (.artifact_paths // []),
          evidence_source: $evidence_source
        }
    ]' "$proof_cost_history_json" >"$cost_rows_json"
}

cost_prediction_for_command() {
  local command_id="$1"
  local command_kind="$2"
  local package="$3"
  local target="$4"
  local recommended_target_dir="$5"
  local max_compiled="$6"
  local max_linked="$7"
  local max_elapsed_ms="$8"

  jq -nc \
    --slurpfile rows "$cost_rows_json" \
    --arg schema_version "franken-engine.swarm-validation-predicted-cost.v1" \
    --arg source_revision "$source_revision" \
    --arg command_id "$command_id" \
    --arg command_kind "$command_kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg target_dir "$recommended_target_dir" \
    --arg evidence_source "$proof_cost_history_json" \
    --argjson max_compiled "$max_compiled" \
    --argjson max_linked "$max_linked" \
    --argjson max_elapsed_ms "$max_elapsed_ms" '
      def heavy: ($command_kind | startswith("rch_"));
      def failed_status:
        (.fallback_detected == true)
        or ((.rch_status | ascii_downcase) | test("fail|error|timeout|local"));
      def success_status:
        (.fallback_detected != true)
        and ((.rch_status | ascii_downcase) | test("pass|ok|remote|planned:admit|planned:admit_narrow"));
      def nums($field): map(.[$field] // 0);
      def max_or_zero($field): if length == 0 then 0 else (nums($field) | max) end;
      def median_or_zero($field):
        if length == 0 then 0
        else (nums($field) | sort | .[(length / 2 | floor)])
        end;
      def revisions: map(.source_revision) | unique | sort;
      def hashes: map(.content_hash) | map(select(. != "")) | unique | sort;
      def base_prediction($state; $class; $sample_count; $fresh_rows; $stale_rows; $matched_rows; $risk_flags; $status; $evidence_rows):
        {
          predicted_cost: {
            schema_version: $schema_version,
            state: $state,
            cost_class: $class,
            sample_count: $sample_count,
            elapsed_ms_p50: ($evidence_rows | median_or_zero("elapsed_ms")),
            elapsed_ms_max: ($evidence_rows | max_or_zero("elapsed_ms")),
            compiled_target_count_max: ($evidence_rows | max_or_zero("compiled_target_count")),
            linked_target_count_max: ($evidence_rows | max_or_zero("linked_target_count"))
          },
          recommended_target_dir: (if $target_dir == "" then null else $target_dir end),
          risk_flags: $risk_flags,
          cost_evidence: {
            status: $status,
            source: (if $evidence_source == "" then null else $evidence_source end),
            matched_rows: $matched_rows,
            fresh_rows: $fresh_rows,
            stale_rows: $stale_rows,
            source_revisions: ($evidence_rows | revisions),
            content_hashes: ($evidence_rows | hashes)
          }
        };
      if (heavy | not) then
        base_prediction("static"; "low"; 0; 0; 0; 0; []; "not_required"; [])
      else
        ($rows[0] // []) as $all
        | [$all[] | select(.command_id == $command_id)] as $same_id
        | [$same_id[] | select(.package != $package or .target != $target)] as $mismatched
        | [$all[] | select(.command_id == $command_id and .package == $package and .target == $target)] as $matched
        | [$matched[] | select(.source_revision == $source_revision)] as $fresh
        | [$matched[] | select(.source_revision != $source_revision)] as $stale
        | if ($mismatched | length) > 0 then
            base_prediction("mismatched"; "unknown"; 0; 0; ($stale | length); ($matched | length); ["mismatched_cost_evidence"]; "mismatched"; ($mismatched + $matched))
          elif ($matched | length) == 0 then
            base_prediction("unknown"; "unknown"; 0; 0; 0; 0; ["unknown_cost_evidence"]; "unknown"; [])
          elif ($fresh | length) == 0 then
            base_prediction("stale"; "unknown"; 0; 0; ($stale | length); ($matched | length); ["stale_cost_evidence"]; "stale"; $stale)
          else
            ($fresh | max_or_zero("elapsed_ms")) as $elapsed_max
            | ($fresh | max_or_zero("compiled_target_count")) as $compiled_max
            | ($fresh | max_or_zero("linked_target_count")) as $linked_max
            | ([$fresh[] | select(failed_status)] | length) as $failed_count
            | ([$fresh[] | select(success_status)] | length) as $success_count
            | ([$fresh[] | select(.fallback_detected == true)] | length) as $fallback_count
            | if ($failed_count > 0 and $success_count > 0) then
                base_prediction("contradictory"; "unknown"; ($fresh | length); ($fresh | length); ($stale | length); ($matched | length); ["contradictory_cost_evidence"]; "contradictory"; $fresh)
              else
                ([
                  (if $failed_count > 0 then "failed_cost_history" else empty end),
                  (if $fallback_count > 0 then "fallback_cost_history" else empty end),
                  (if ($elapsed_max > $max_elapsed_ms or $compiled_max > $max_compiled or $linked_max > $max_linked) then "high_cost_history" else empty end)
                ]) as $risks
                | (if ($failed_count > 0 or $fallback_count > 0 or $elapsed_max > $max_elapsed_ms or $compiled_max > $max_compiled or $linked_max > $max_linked) then "high"
                   elif ($elapsed_max > ($max_elapsed_ms / 2 | floor)) then "medium"
                   else "low"
                   end) as $class
                | base_prediction("matched"; $class; ($fresh | length); ($fresh | length); ($stale | length); ($matched | length); $risks; "matched"; $fresh)
              end
          end
      end'
}

emit_command() {
  local command_id="$1"
  local display="$2"
  local command_kind="$3"
  local package="$4"
  local target="$5"
  local rationale="$6"
  local recommended_target_dir="${7:-}"
  local max_compiled="${8:-0}"
  local max_linked="${9:-0}"
  local max_elapsed_ms="${10:-0}"
  local prediction

  prediction="$(cost_prediction_for_command "$command_id" "$command_kind" "$package" "$target" "$recommended_target_dir" "$max_compiled" "$max_linked" "$max_elapsed_ms")"
  jq -nc \
    --arg command_id "$command_id" \
    --arg display "$display" \
    --arg command_kind "$command_kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rationale "$rationale" \
    --argjson prediction "$prediction" \
    '{
      command_id: $command_id,
      display: $display,
      command_kind: $command_kind,
      package: (if $package == "" then null else $package end),
      target: (if $target == "" then null else $target end),
      rationale: $rationale,
      predicted_cost: $prediction.predicted_cost,
      recommended_target_dir: $prediction.recommended_target_dir,
      risk_flags: $prediction.risk_flags,
      cost_evidence: $prediction.cost_evidence
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
  emit_command "$command_id" "$command" "rch_cargo_test" "$package" "$target" "exact test target inferred from changed integration test path" "$target_dir" 2 1 120000
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
  emit_command "$command_id" "$command" "rch_cargo_check_lib" "$package" "lib" "package lib fallback for source changes without an exact test target" "$target_dir" 1 0 90000
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

normalize_cost_history

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

jq -s 'sort_by(.command_id) | unique_by(.command_id)' "$commands_jsonl" >"${commands_jsonl}.tmp"
mv "${commands_jsonl}.tmp" "$commands_jsonl"
jq -r '.[].display' "$commands_jsonl" >"$commands_path"

command_count="$(jq 'length' "$commands_jsonl")"
unknown_count="$(jq -s '[.[] | select(.kind == "unknown_path_mapping" or .kind == "missing_file")] | length' "$omitted_jsonl")"
cost_failure_count="$(jq -s '[.[] | select(.kind == "missing_cost_history" or .kind == "invalid_cost_history")] | length' "$omitted_jsonl")"
fallback_count="$(jq -s '[.[] | select(.kind == "package_lib_fallback")] | length' "$mappings_jsonl")"
risk_flags_json="$(jq '[.[].risk_flags[]?] | sort | unique' "$commands_jsonl")"
cost_fail_closed_count="$(jq '[.[].risk_flags[]? | select(. == "mismatched_cost_evidence" or . == "contradictory_cost_evidence")] | length' "$commands_jsonl")"
decision="admit"
if [[ "$unknown_count" -ne 0 || "$cost_failure_count" -ne 0 || "$cost_fail_closed_count" -ne 0 || "$command_count" -eq 0 ]]; then
  decision="fail_closed"
elif [[ "$fallback_count" -ne 0 ]]; then
  decision="admit_narrow"
fi

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
  --argjson risk_flags "$risk_flags_json" \
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
    risk_flags: $risk_flags,
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
  jq -r '.commands[]? | "- `" + .command_id + "`: " + .display + " (cost: `" + .predicted_cost.cost_class + "`, evidence: `" + .cost_evidence.status + "`)"' "$plan_path"
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
