#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wrapper_path="${root_dir}/scripts/validation_hygiene_wrapper.sh"
classifier_path="${root_dir}/scripts/validation_hygiene_classifier.sh"
mode="${1:-check}"
output_root="${2:-${VALIDATION_HYGIENE_WRAPPER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-wrapper-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS validation-hygiene-wrapper %s\n' "$1"
}

record_failure() {
  printf 'FAIL validation-hygiene-wrapper %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/validation_hygiene_wrapper_smoke.sh [check|selftest] [output_root]
EOF
}

script_static_ok() {
  bash -n "$wrapper_path" "$classifier_path" "${BASH_SOURCE[0]}"
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "validation-hygiene@example.invalid"
  git -C "$repo" config user.name "Validation Hygiene"
  mkdir -p "$repo/src" "$repo/docs" "$repo/tools"
  printf 'fn main() {}\n' >"$repo/src/main.rs"
  printf '# Contract\n' >"$repo/docs/contract.md"
  git -C "$repo" add src/main.rs docs/contract.md
  git -C "$repo" commit -q -m "initial fixture"
}

write_tool() {
  local path="$1"
  local body="$2"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$body" >"$path"
  chmod +x "$path"
}

run_wrapper() {
  local repo="$1"
  local case_id="$2"
  local scope="$3"
  local expected_exit="$4"
  shift 4
  local out_dir="${output_root}/${case_id}/out"
  local actual_exit

  set +e
  "$wrapper_path" \
    --repo-root "$repo" \
    --case-id "$case_id" \
    --bead-id "bd-u9sp4.3" \
    --scope "$scope" \
    --output-dir "$out_dir" \
    -- "$@" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return 1
  fi
  return 0
}

assert_report() {
  local case_id="$1"
  local expected_command_exit="$2"
  local expected_classifier_status="$3"
  local expected_blocker_class="$4"
  local report="${output_root}/${case_id}/out/wrapper_report.json"

  jq empty "$report" >/dev/null || {
    record_failure "${case_id} invalid wrapper json"
    return
  }

  jq -e \
    --argjson expected_command_exit "$expected_command_exit" \
    --arg expected_classifier_status "$expected_classifier_status" \
    --arg expected_blocker_class "$expected_blocker_class" '
      .schema_version == "franken-engine.validation-hygiene-wrapper-report.v1"
      and .bead_id == "bd-u9sp4.3"
      and .command.mode == "argv"
      and .command.exit_code == $expected_command_exit
      and .command.wrapper_exit_code == $expected_command_exit
      and .command.preserves_original_command == true
      and .no_masking_attestation.exits_with_original_command_status == true
      and .classifier_report.outcome.status == $expected_classifier_status
      and (if $expected_blocker_class == "null" then .classifier_report.outcome.first_blocker == null else .classifier_report.outcome.first_blocker.class == $expected_blocker_class end)
      and .non_mutation_attestation.rewrites_command == false
      and .non_mutation_attestation.deletes_files == false
      and .non_mutation_attestation.moves_files == false
      and .non_mutation_attestation.formats_unrelated_files == false
      and .non_mutation_attestation.stages_files == false
    ' "$report" >/dev/null || record_failure "${case_id} report mismatch"

  test -s "${output_root}/${case_id}/out/stdout.txt" || true
  test -s "${output_root}/${case_id}/out/transcript.txt" || record_failure "${case_id} missing transcript"
  test -s "${output_root}/${case_id}/out/events.jsonl" || record_failure "${case_id} missing events"
  test -s "${output_root}/${case_id}/out/commands.txt" || record_failure "${case_id} missing commands"
  test -s "${output_root}/${case_id}/out/classifier/hygiene_report.json" || record_failure "${case_id} missing classifier report"
}

run_argv_pass() {
  local repo="${output_root}/argv-pass/repo"
  init_repo "$repo"
  write_tool "$repo/tools/argv_echo.sh" 'printf "arg1=%s\narg2=%s\n" "$1" "$2"'
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  run_wrapper "$repo" "argv-pass" "docs/contract.md" 0 "$repo/tools/argv_echo.sh" "hello world" "pipe|arg"
  assert_report "argv-pass" 0 "pass" "null"
  jq -e '.command.argv[-2:] == ["hello world", "pipe|arg"]' \
    "${output_root}/argv-pass/out/wrapper_report.json" >/dev/null || record_failure "argv-pass argv order"
  record_pass "argv-pass"
}

run_unrelated_failure() {
  local repo="${output_root}/unrelated-failure/repo"
  init_repo "$repo"
  write_tool "$repo/tools/fail_unrelated.sh" 'printf "format drift in src/main.rs\n" >&2; exit 5'
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'fn main(){println!("bad fmt");}\n' >"$repo/src/main.rs"
  run_wrapper "$repo" "unrelated-failure" "docs/contract.md" 5 "$repo/tools/fail_unrelated.sh"
  assert_report "unrelated-failure" 5 "blocked_by_unrelated_context" "tracked_unrelated_dirty"
  record_pass "unrelated-failure"
}

run_scoped_failure() {
  local repo="${output_root}/scoped-failure/repo"
  init_repo "$repo"
  write_tool "$repo/tools/fail_scoped.sh" 'printf "format drift in docs/contract.md\n" >&2; exit 7'
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  run_wrapper "$repo" "scoped-failure" "docs/contract.md" 7 "$repo/tools/fail_scoped.sh"
  assert_report "scoped-failure" 7 "fail_scoped_files" "scoped_file"
  record_pass "scoped-failure"
}

run_check() {
  script_static_ok
  rg -n 'wrapper_exit_code|preserves_original_command|classifier_report|stdout.txt|stderr.txt|transcript.txt|no_masking_attestation' "$wrapper_path" >/dev/null
  record_pass "check"
}

run_selftest() {
  mkdir -p "$output_root"
  run_check
  run_argv_pass
  run_unrelated_failure
  run_scoped_failure
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
