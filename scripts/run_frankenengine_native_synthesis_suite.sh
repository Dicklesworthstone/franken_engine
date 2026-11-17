#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
component="frankenengine_native_synthesis"
bead_id="bd-2xe"
doc_path="docs/architecture/frankenengine_native_synthesis.md"
plan_path="docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md"
readme_path="README.md"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/frankenengine_native_synthesis/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/frankenengine_native_synthesis_events.jsonl"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
failed_error_code=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    if [[ -z "$failed_error_code" ]]; then
      failed_error_code="FE-NATIVE-SYNTH-0006"
    fi
    return 1
  fi
}

require_literal() {
  local literal="$1"
  local file="$2"
  local code="$3"
  if ! rg -nFi -- "$literal" "$file" >/dev/null; then
    echo "missing required literal in ${file}: ${literal}" >&2
    failed_error_code="$code"
    return 1
  fi
}

extract_section() {
  local heading="$1"
  awk -v heading="$heading" '
    $0 == heading {in_section=1; next}
    /^## / && in_section {exit}
    in_section {print}
  ' "$doc_path"
}

section_word_count() {
  local heading="$1"
  extract_section "$heading" | wc -w | tr -d ' '
}

validate_no_donor_source_refs() {
  local file="$1"
  if rg -n -- '(legacy_v8/|legacy_quickjs/|v8/src/|quickjs/)' "$file" >/dev/null; then
    echo "forbidden donor source path reference found in ${file}" >&2
    return 1
  fi
}

check_structure() {
  local section_headings=(
    "## 1. Executive Summary"
    "## 2. Parser Strategy"
    "## 3. IR Pipeline Design"
    "## 4. Memory Model"
    "## 5. Execution Model"
    "## 6. Optimization Strategy"
    "## 7. Non-Goals (Explicit Donor Architecture Exclusions)"
    "## 8. Thesis Justification Matrix"
  )

  local heading
  for heading in "${section_headings[@]}"; do
    require_literal "$heading" "$doc_path" "FE-NATIVE-SYNTH-0001" || return 1
  done

  for heading in "${section_headings[@]}"; do
    local words
    words="$(section_word_count "$heading")"
    if [[ "$words" -lt 200 ]]; then
      echo "section too short (${words} words): ${heading}" >&2
      failed_error_code="FE-NATIVE-SYNTH-0002"
      return 1
    fi
  done

  local non_goal_count
  non_goal_count="$(rg -n -- '^[0-9]+\. `NG-[0-9]{3}`' "$doc_path" | wc -l | tr -d ' ')"
  if [[ "$non_goal_count" -lt 15 ]]; then
    echo "non-goal count too low (${non_goal_count}); expected >= 15" >&2
    failed_error_code="FE-NATIVE-SYNTH-0002"
    return 1
  fi

  require_literal 'docs/SEMANTIC_DONOR_SPEC.md' "$doc_path" "FE-NATIVE-SYNTH-0004" || return 1
  validate_no_donor_source_refs "$doc_path" || {
    failed_error_code="FE-NATIVE-SYNTH-0004"
    return 1
  }

  local traced_sections=(
    "## 2. Parser Strategy"
    "## 3. IR Pipeline Design"
    "## 4. Memory Model"
    "## 5. Execution Model"
    "## 6. Optimization Strategy"
  )

  for heading in "${traced_sections[@]}"; do
    local section_text
    section_text="$(extract_section "$heading")"
    if ! grep -Eq '(Plan section|Plan sections|§10\.|§9|§5)' <<<"$section_text"; then
      echo "missing plan/thesis traceability markers in ${heading}" >&2
      failed_error_code="FE-NATIVE-SYNTH-0004"
      return 1
    fi
  done

  require_literal '- [x] Add FrankenEngine-native architecture synthesis document derived from donor spec (no donor-architecture mirroring) (`docs/architecture/frankenengine_native_synthesis.md`).' "$plan_path" "FE-NATIVE-SYNTH-0003" || return 1
  require_literal 'docs/architecture/frankenengine_native_synthesis.md' "$readme_path" "FE-NATIVE-SYNTH-0003" || return 1

  require_literal '`trace_id`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`decision_id`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`policy_id`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`component`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`event`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`outcome`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
  require_literal '`error_code`' "$doc_path" "FE-NATIVE-SYNTH-0005" || return 1
}

run_guardrail_fixtures() {
  local pass_fixture="${run_dir}/fixture_no_source_refs.md"
  local fail_fixture="${run_dir}/fixture_with_source_ref.md"

  cat >"$pass_fixture" <<'PASS'
This fixture references semantic requirements and plan sections only.
No donor source tree paths are present.
PASS

  cat >"$fail_fixture" <<'FAIL'
This fixture intentionally contains a forbidden source path: legacy_v8/v8/src/runtime/runtime.cc
FAIL

  validate_no_donor_source_refs "$pass_fixture" || {
    failed_error_code="FE-NATIVE-SYNTH-0004"
    return 1
  }

  if ( validate_no_donor_source_refs "$fail_fixture" >/dev/null 2>&1 ); then
    echo "expected donor-source fixture to fail guardrail" >&2
    failed_error_code="FE-NATIVE-SYNTH-0004"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "native synthesis structure checks" check_structure
      ;;
    test)
      run_step "native synthesis guardrail fixtures" run_guardrail_fixtures
      ;;
    ci)
      run_step "native synthesis structure checks" check_structure
      run_step "native synthesis guardrail fixtures" run_guardrail_fixtures
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${run_dir}/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.native-synthesis.run-manifest.v1",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"bead_id\": \"${bead_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\"," 
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\"," 
    fi
    if [[ -n "$failed_error_code" ]]; then
      echo "  \"error_code\": \"${failed_error_code}\"," 
    else
      echo '  "error_code": null,'
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${run_dir}/commands.txt\"," 
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"architecture_doc\": \"${doc_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${run_dir}/commands.txt\"," 
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    if [[ -n "$failed_error_code" ]]; then
      echo "{\"trace_id\":\"trace-native-synth-${timestamp}\",\"decision_id\":\"decision-native-synth-${timestamp}\",\"policy_id\":\"policy-native-synth-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":\"${failed_error_code}\"}"
    else
      echo "{\"trace_id\":\"trace-native-synth-${timestamp}\",\"decision_id\":\"decision-native-synth-${timestamp}\",\"policy_id\":\"policy-native-synth-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":null}"
    fi
  } >"${events_path}"

  echo "native synthesis run manifest: ${manifest_path}"
  echo "native synthesis events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
