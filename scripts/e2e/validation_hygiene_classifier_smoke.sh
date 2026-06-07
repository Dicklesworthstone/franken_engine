#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/validation_hygiene_classifier.sh"
mode="${1:-check}"
output_root="${2:-${VALIDATION_HYGIENE_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS validation-hygiene-classifier %s\n' "$1"
}

record_failure() {
  printf 'FAIL validation-hygiene-classifier %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/validation_hygiene_classifier_smoke.sh [check|selftest] [output_root]
EOF
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "validation-hygiene@example.invalid"
  git -C "$repo" config user.name "Validation Hygiene"
  mkdir -p "$repo/src" "$repo/tests" "$repo/docs"
  printf 'fn main() {}\n' >"$repo/src/main.rs"
  printf '# Contract\n' >"$repo/docs/contract.md"
  git -C "$repo" add src/main.rs docs/contract.md
  git -C "$repo" commit -q -m "initial fixture"
}

run_classifier() {
  local repo="$1"
  local case_id="$2"
  local scope="$3"
  local transcript="$4"
  local command_text="$5"
  local exit_code="$6"
  local expected_tool_exit="$7"
  local out_dir="${output_root}/${case_id}/out"
  local actual_exit

  set +e
  "$script_path" \
    --repo-root "$repo" \
    --case-id "$case_id" \
    --bead-id "bd-u9sp4.2" \
    --scope "$scope" \
    --command "$command_text" \
    --transcript "$transcript" \
    --exit-code "$exit_code" \
    --output-dir "$out_dir" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_tool_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_tool_exit}"
    return 1
  fi
  return 0
}

assert_report() {
  local case_id="$1"
  local expected_status="$2"
  local expected_class="$3"
  local expected_path="$4"
  local report="${output_root}/${case_id}/out/hygiene_report.json"

  jq empty "$report" >/dev/null || {
    record_failure "${case_id} invalid json"
    return
  }

  jq -e \
    --arg expected_status "$expected_status" \
    --arg expected_class "$expected_class" \
    --arg expected_path "$expected_path" '
      .schema_version == "franken-engine.validation-hygiene-report.v1"
      and .bead_id == "bd-u9sp4.2"
      and .outcome.status == $expected_status
      and .command.preserves_original_command == true
      and .no_delete_guarantee.performed_deletions == false
      and .no_delete_guarantee.performed_reverts == false
      and .no_delete_guarantee.performed_moves == false
      and .no_delete_guarantee.performed_unrelated_formatting == false
      and .no_delete_guarantee.performed_unrelated_staging == false
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_git_index == false
      and (if $expected_class == "null" then .outcome.first_blocker == null else .outcome.first_blocker.class == $expected_class end)
      and (if $expected_path == "null" then true else .outcome.first_blocker.path == $expected_path end)
    ' "$report" >/dev/null || record_failure "${case_id} report mismatch"

  test -s "${output_root}/${case_id}/out/events.jsonl" || record_failure "${case_id} missing events"
  test -s "${output_root}/${case_id}/out/commands.txt" || record_failure "${case_id} missing commands"
  test -s "${output_root}/${case_id}/out/report.md" || record_failure "${case_id} missing report"
}

run_clean_scoped() {
  local repo="${output_root}/clean-scoped/repo"
  local transcript="${output_root}/clean-scoped/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'validation passed\n' >"$transcript"
  run_classifier "$repo" "clean-scoped" "docs/contract.md" "$transcript" "git diff --check -- docs/contract.md" 0 0
  assert_report "clean-scoped" "pass" "null" "null"
  record_pass "clean-scoped"
}

run_tracked_unrelated() {
  local repo="${output_root}/tracked-unrelated/repo"
  local transcript="${output_root}/tracked-unrelated/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'fn main(){println!(\"bad fmt\");}\n' >"$repo/src/main.rs"
  printf 'Diff in /tmp/repo/src/main.rs at line 1\nsrc/main.rs\n' >"$transcript"
  run_classifier "$repo" "tracked-unrelated" "docs/contract.md" "$transcript" "cargo fmt -p frankenengine-engine --check" 1 0
  assert_report "tracked-unrelated" "blocked_by_unrelated_context" "tracked_unrelated_dirty" "src/main.rs"
  jq -e '.tracked_unrelated_dirty | any(.path == "src/main.rs")' \
    "${output_root}/tracked-unrelated/out/hygiene_report.json" >/dev/null || record_failure "tracked-unrelated missing tracked classification"
  record_pass "tracked-unrelated"
}

run_untracked_probe() {
  local repo="${output_root}/untracked-probe/repo"
  local transcript="${output_root}/untracked-probe/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf '#[test]\nfn probe() {}\n' >"$repo/tests/gl_parser_gap_probe.rs"
  printf 'error: expected formatted file tests/gl_parser_gap_probe.rs\n' >"$transcript"
  run_classifier "$repo" "untracked-probe" "docs/contract.md" "$transcript" "cargo fmt -p frankenengine-engine --check" 1 0
  assert_report "untracked-probe" "blocked_by_unrelated_context" "untracked_ephemeral_candidate" "tests/gl_parser_gap_probe.rs"
  jq -e '.untracked_ephemeral_candidates | any(.path == "tests/gl_parser_gap_probe.rs")' \
    "${output_root}/untracked-probe/out/hygiene_report.json" >/dev/null || record_failure "untracked-probe missing ephemeral classification"
  record_pass "untracked-probe"
}

run_untracked_source() {
  local repo="${output_root}/untracked-source/repo"
  local transcript="${output_root}/untracked-source/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'pub fn durable() {}\n' >"$repo/src/new_module.rs"
  printf 'error: compile failed in src/new_module.rs\n' >"$transcript"
  run_classifier "$repo" "untracked-source" "docs/contract.md" "$transcript" "cargo check -p frankenengine-engine" 101 0
  assert_report "untracked-source" "blocked_by_unrelated_context" "untracked_source_candidate" "src/new_module.rs"
  jq -e '.untracked_source_candidates | any(.path == "src/new_module.rs")' \
    "${output_root}/untracked-source/out/hygiene_report.json" >/dev/null || record_failure "untracked-source missing source classification"
  record_pass "untracked-source"
}

run_unknown_blocker() {
  local repo="${output_root}/unknown-blocker/repo"
  local transcript="${output_root}/unknown-blocker/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'unexpected validator failure without a path\n' >"$transcript"
  run_classifier "$repo" "unknown-blocker" "docs/contract.md" "$transcript" "cargo test -p frankenengine-engine" 101 42
  assert_report "unknown-blocker" "inconclusive" "null" "null"
  record_pass "unknown-blocker"
}

run_environment_blocker() {
  local repo="${output_root}/environment-blocker/repo"
  local transcript="${output_root}/environment-blocker/transcript.txt"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  printf 'collect2: fatal error: ld terminated with signal 7 [Bus error]\n' >"$transcript"
  run_classifier "$repo" "environment-blocker" "docs/contract.md" "$transcript" "rch exec -- env CARGO_INCREMENTAL=0 cargo test" 101 0
  assert_report "environment-blocker" "blocked_by_environment" "external_environment_blocker" "null"
  jq -e '(.external_environment_blockers | length == 1) and (.rch_context.used == true)' \
    "${output_root}/environment-blocker/out/hygiene_report.json" >/dev/null || record_failure "environment-blocker missing external context"
  record_pass "environment-blocker"
}

run_check() {
  script_static_ok
  rg -n 'no_delete_guarantee|tracked_unrelated_dirty|untracked_ephemeral_candidate|untracked_source_candidate|first_blocker' "$script_path" >/dev/null
  record_pass "check"
}

run_selftest() {
  mkdir -p "$output_root"
  run_check
  run_clean_scoped
  run_tracked_unrelated
  run_untracked_probe
  run_untracked_source
  run_unknown_blocker
  run_environment_blocker
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
