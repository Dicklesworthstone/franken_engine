#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
classifier_path="${root_dir}/scripts/validation_hygiene_classifier.sh"
wrapper_path="${root_dir}/scripts/validation_hygiene_wrapper.sh"
preflight_path="${root_dir}/scripts/validation_hygiene_preflight.sh"
mode="${1:-check}"
output_root="${2:-${VALIDATION_HYGIENE_NO_DELETE_E2E_DIR:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-no-delete-e2e-$$}}"
failures=0

record_pass() {
  printf 'PASS validation-hygiene-no-delete-e2e %s\n' "$1"
}

record_failure() {
  printf 'FAIL validation-hygiene-no-delete-e2e %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/validation_hygiene_no_delete_e2e.sh [check|selftest] [output_root]

Runs deterministic temp-repo E2E fixtures for the validation hygiene classifier,
wrapper, and preflight scripts. The harness asserts that fixture files are not
deleted, moved, rewritten, formatted, or staged by the hygiene tools.

Heavy Cargo commands under test must be supplied to validation_hygiene_wrapper.sh
with the repository RCH shape, for example:

  env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS \
    CARGO_TARGET_DIR=/data/tmp/franken_engine-validation \
    CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc -Clinker-features=-lld' cargo test -p frankenengine-engine

This E2E harness itself uses shell fixtures only; it does not invoke Cargo or RCH.
EOF
}

require_tools() {
  local missing=0
  local tool
  for tool in git jq rg sha256sum stat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      record_failure "missing tool: ${tool}"
      missing=1
    fi
  done
  [[ "$missing" -eq 0 ]]
}

script_static_ok() {
  bash -n "$classifier_path" "$wrapper_path" "$preflight_path" "${BASH_SOURCE[0]}"
  rg -n 'no-delete|fingerprint|wrapper_exit_code|first_blocker|CARGO_TARGET_DIR|RUSTFLAGS|ignored_artifact|unknown-output' "${BASH_SOURCE[0]}" >/dev/null
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo/src" "$repo/tests" "$repo/docs" "$repo/scripts"
  git -C "$repo" init -q
  git -C "$repo" config user.email "validation-hygiene@example.invalid"
  git -C "$repo" config user.name "Validation Hygiene"
  printf 'target/\n' >"$repo/.gitignore"
  printf 'fn main() {}\n' >"$repo/src/main.rs"
  printf '# Contract\n' >"$repo/docs/contract.md"
  printf '#!/usr/bin/env bash\nset -euo pipefail\n' >"$repo/scripts/check.sh"
  git -C "$repo" add .gitignore src/main.rs docs/contract.md scripts/check.sh
  git -C "$repo" commit -q -m "initial fixture"
}

fingerprint_repo() {
  local repo="$1"
  local output="$2"
  local path rel sha size mtime
  : >"$output"
  while IFS= read -r path; do
    rel="${path#"$repo"/}"
    sha="$(sha256sum "$path" | awk '{print $1}')"
    size="$(stat -c '%s' "$path")"
    mtime="$(stat -c '%Y' "$path")"
    jq -nc \
      --arg path "$rel" \
      --arg sha256 "$sha" \
      --argjson size "$size" \
      --argjson mtime "$mtime" \
      '{path:$path,sha256:$sha256,size:$size,mtime_epoch:$mtime}' >>"$output"
  done < <(find "$repo" -path "$repo/.git" -prune -o -type f -print | sort)
}

staged_snapshot() {
  local repo="$1"
  local output="$2"
  git -C "$repo" diff --cached --name-status | sort >"$output"
}

assert_no_mutation() {
  local case_id="$1"
  local before="$2"
  local after="$3"
  local staged_before="$4"
  local staged_after="$5"

  if ! cmp -s "$before" "$after"; then
    record_failure "${case_id} fixture fingerprint changed"
    diff -u "$before" "$after" >&2 || true
  fi
  if ! cmp -s "$staged_before" "$staged_after"; then
    record_failure "${case_id} git index changed"
    diff -u "$staged_before" "$staged_after" >&2 || true
  fi
}

write_case_summary() {
  local case_id="$1"
  local case_dir="$2"
  local wrapper_report="${case_dir}/out/wrapper_report.json"
  local preflight_report="${case_dir}/preflight/preflight_report.json"
  local case_report="${case_dir}/case_report.json"
  local case_md="${case_dir}/case_report.md"

  jq -n \
    --arg schema_version "franken-engine.validation-hygiene-no-delete-e2e.case.v1" \
    --arg case_id "$case_id" \
    --slurpfile wrapper "$wrapper_report" \
    --slurpfile preflight "$preflight_report" \
    '{
      schema_version:$schema_version,
      case_id:$case_id,
      command:{
        text:$wrapper[0].command.text,
        exit_code:$wrapper[0].command.exit_code,
        wrapper_exit_code:$wrapper[0].command.wrapper_exit_code,
        elapsed_ms:$wrapper[0].command.elapsed_ms
      },
      classifier:{
        status:$wrapper[0].classifier_report.outcome.status,
        first_blocker:$wrapper[0].classifier_report.outcome.first_blocker,
        tracked_unrelated_dirty:$wrapper[0].classifier_report.tracked_unrelated_dirty,
        untracked_ephemeral_candidates:$wrapper[0].classifier_report.untracked_ephemeral_candidates,
        untracked_source_candidates:$wrapper[0].classifier_report.untracked_source_candidates,
        ignored_artifacts:$wrapper[0].classifier_report.ignored_artifacts
      },
      no_delete_attestation:{
        wrapper_non_mutation:$wrapper[0].non_mutation_attestation,
        classifier_no_delete:$wrapper[0].classifier_report.no_delete_guarantee,
        preflight_non_mutation:$preflight[0].non_mutation_attestation
      },
      artifact_paths:{
        wrapper_report_json:"out/wrapper_report.json",
        classifier_report_json:"out/classifier/hygiene_report.json",
        wrapper_report_md:"out/report.md",
        preflight_report_json:"preflight/preflight_report.json",
        preflight_report_md:"preflight/report.md",
        case_report_md:"case_report.md"
      }
    }' >"$case_report"

  {
    printf '# Validation Hygiene No-Delete E2E Case\n\n'
    printf -- '- case_id: `%s`\n' "$case_id"
    printf -- '- command_exit: `%s`\n' "$(jq -r '.command.exit_code' "$case_report")"
    printf -- '- wrapper_exit: `%s`\n' "$(jq -r '.command.wrapper_exit_code' "$case_report")"
    printf -- '- elapsed_ms: `%s`\n' "$(jq -r '.command.elapsed_ms' "$case_report")"
    printf -- '- classifier_status: `%s`\n' "$(jq -r '.classifier.status' "$case_report")"
    printf -- '- first_blocker: `%s`\n' "$(jq -r '.classifier.first_blocker.class // "none"' "$case_report")"
  } >"$case_md"
}

run_preflight_for_case() {
  local repo="$1"
  local case_id="$2"
  local scope="$3"
  local out_dir="${output_root}/${case_id}/preflight"
  "$preflight_path" \
    --repo-root "$repo" \
    --case-id "$case_id" \
    --bead-id "bd-u9sp4.6" \
    --agent "SilverPeak" \
    --scope "$scope" \
    --output-dir "$out_dir" \
    --format none
}

run_wrapper_case() {
  local case_id="$1"
  local expected_exit="$2"
  local expected_status="$3"
  local expected_class="$4"
  local expected_path="$5"
  local scope="$6"
  shift 6
  local repo="${output_root}/${case_id}/repo"
  local case_dir="${output_root}/${case_id}"
  local out_dir="${case_dir}/out"
  local before="${case_dir}/fingerprint.before.jsonl"
  local after="${case_dir}/fingerprint.after.jsonl"
  local staged_before="${case_dir}/staged.before.txt"
  local staged_after="${case_dir}/staged.after.txt"
  local actual_exit

  fingerprint_repo "$repo" "$before"
  staged_snapshot "$repo" "$staged_before"
  run_preflight_for_case "$repo" "$case_id" "$scope"

  set +e
  "$wrapper_path" \
    --repo-root "$repo" \
    --case-id "$case_id" \
    --bead-id "bd-u9sp4.6" \
    --scope "$scope" \
    --output-dir "$out_dir" \
    -- "$@" >/dev/null 2>&1
  actual_exit=$?
  set -e

  fingerprint_repo "$repo" "$after"
  staged_snapshot "$repo" "$staged_after"
  assert_no_mutation "$case_id" "$before" "$after" "$staged_before" "$staged_after"

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} wrapper exit ${actual_exit}, expected ${expected_exit}"
  fi

  local report="${out_dir}/wrapper_report.json"
  jq empty "$report" >/dev/null || {
    record_failure "${case_id} invalid wrapper JSON"
    return
  }
  jq -e \
    --argjson expected_exit "$expected_exit" \
    --arg expected_status "$expected_status" \
    --arg expected_class "$expected_class" \
    --arg expected_path "$expected_path" '
      .schema_version == "franken-engine.validation-hygiene-wrapper-report.v1"
      and .bead_id == "bd-u9sp4.6"
      and .command.exit_code == $expected_exit
      and .command.wrapper_exit_code == $expected_exit
      and (.command.elapsed_ms | type == "number")
      and .command.preserves_original_command == true
      and .no_masking_attestation.exits_with_original_command_status == true
      and .classifier_report.outcome.status == $expected_status
      and (if $expected_class == "null" then .classifier_report.outcome.first_blocker == null else .classifier_report.outcome.first_blocker.class == $expected_class end)
      and (if $expected_path == "null" then true else .classifier_report.outcome.first_blocker.path == $expected_path end)
      and .non_mutation_attestation.rewrites_command == false
      and .non_mutation_attestation.deletes_files == false
      and .non_mutation_attestation.moves_files == false
      and .non_mutation_attestation.formats_unrelated_files == false
      and .non_mutation_attestation.stages_files == false
      and .classifier_report.no_delete_guarantee.performed_deletions == false
      and .classifier_report.no_delete_guarantee.performed_reverts == false
      and .classifier_report.no_delete_guarantee.performed_moves == false
      and .classifier_report.no_delete_guarantee.performed_unrelated_formatting == false
      and .classifier_report.no_delete_guarantee.performed_unrelated_staging == false
    ' "$report" >/dev/null || record_failure "${case_id} wrapper/classifier report mismatch"

  test -s "${out_dir}/transcript.txt" || record_failure "${case_id} missing transcript"
  test -s "${out_dir}/commands.txt" || record_failure "${case_id} missing commands"
  test -s "${out_dir}/events.jsonl" || record_failure "${case_id} missing events"
  test -s "${out_dir}/report.md" || record_failure "${case_id} missing wrapper report md"
  test -s "${out_dir}/classifier/hygiene_report.json" || record_failure "${case_id} missing classifier report"
  test -s "${case_dir}/preflight/preflight_report.json" || record_failure "${case_id} missing preflight report"
  write_case_summary "$case_id" "$case_dir"
}

run_tracked_unrelated() {
  local case_id="tracked-unrelated-fmt"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  printf 'fn main(){println!("dirty");}\n' >"$repo/src/main.rs"
  run_wrapper_case "$case_id" 5 "blocked_by_unrelated_context" "tracked_unrelated_dirty" "src/main.rs" \
    "docs/contract.md" bash -lc 'printf "fmt failure: src/main.rs\n" >&2; exit 5'
  jq -e '.classifier.tracked_unrelated_dirty | any(.path == "src/main.rs")' \
    "${output_root}/${case_id}/case_report.json" >/dev/null || record_failure "${case_id} missing tracked row"
  record_pass "$case_id"
}

run_untracked_probe() {
  local case_id="untracked-probe-fmt"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  printf '#[test]\nfn probe() {}\n' >"$repo/tests/gl_parser_gap_probe.rs"
  run_wrapper_case "$case_id" 5 "blocked_by_unrelated_context" "untracked_ephemeral_candidate" "tests/gl_parser_gap_probe.rs" \
    "docs/contract.md" bash -lc 'printf "fmt failure: tests/gl_parser_gap_probe.rs\n" >&2; exit 5'
  jq -e '.classifier.untracked_ephemeral_candidates | any(.path == "tests/gl_parser_gap_probe.rs")' \
    "${output_root}/${case_id}/case_report.json" >/dev/null || record_failure "${case_id} missing probe row"
  record_pass "$case_id"
}

run_in_scope_failure() {
  local case_id="in-scope-failure"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  printf '# Contract\n\nbad trailing spaces  \n' >"$repo/docs/contract.md"
  run_wrapper_case "$case_id" 5 "fail_scoped_files" "scoped_file" "docs/contract.md" \
    "docs/contract.md" bash -lc 'printf "diff check failure: docs/contract.md\n" >&2; exit 5'
  record_pass "$case_id"
}

run_ignored_artifact() {
  local case_id="ignored-artifact"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  mkdir -p "$repo/target/debug/deps"
  printf 'object bytes\n' >"$repo/target/debug/deps/example.o"
  run_wrapper_case "$case_id" 5 "blocked_by_unrelated_context" "ignored_artifact" "target/debug/deps/example.o" \
    "docs/contract.md" bash -lc 'printf "artifact contaminates closeout: target/debug/deps/example.o\n" >&2; exit 5'
  jq -e '.classifier.ignored_artifacts | any(.path == "target/debug/deps/example.o")' \
    "${output_root}/${case_id}/case_report.json" >/dev/null || record_failure "${case_id} missing ignored artifact row"
  record_pass "$case_id"
}

run_mixed_blockers() {
  local case_id="mixed-blockers"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  printf 'fn main(){println!("dirty");}\n' >"$repo/src/main.rs"
  printf 'patch scratch\n' >"$repo/.jh_case.patch"
  printf '#[test]\nfn probe() {}\n' >"$repo/tests/gl_parser_gap_probe.rs"
  printf 'pub fn durable() {}\n' >"$repo/src/new_module.rs"
  run_wrapper_case "$case_id" 5 "blocked_by_unrelated_context" "tracked_unrelated_dirty" "src/main.rs" \
    "docs/contract.md" bash -lc 'printf "first blocker src/main.rs\nthen .jh_case.patch\nthen src/new_module.rs\n" >&2; exit 5'
  jq -e '
    (.classifier.tracked_unrelated_dirty | any(.path == "src/main.rs"))
    and (.classifier.untracked_ephemeral_candidates | any(.path == ".jh_case.patch"))
    and (.classifier.untracked_ephemeral_candidates | any(.path == "tests/gl_parser_gap_probe.rs"))
    and (.classifier.untracked_source_candidates | any(.path == "src/new_module.rs"))
  ' "${output_root}/${case_id}/case_report.json" >/dev/null || record_failure "${case_id} mixed classifications"
  record_pass "$case_id"
}

run_unknown_output() {
  local case_id="unknown-output"
  local repo="${output_root}/${case_id}/repo"
  init_repo "$repo"
  run_wrapper_case "$case_id" 5 "inconclusive" "null" "null" \
    "docs/contract.md" bash -lc 'printf "validator failed without a path marker\n" >&2; exit 5'
  record_pass "$case_id"
}

write_aggregate_report() {
  local aggregate_json="${output_root}/validation_hygiene_no_delete_e2e_report.json"
  local aggregate_md="${output_root}/validation_hygiene_no_delete_e2e_report.md"
  jq -n \
    --arg schema_version "franken-engine.validation-hygiene-no-delete-e2e.v1" \
    --arg bead_id "bd-u9sp4.6" \
    --arg output_root "$output_root" \
    --slurpfile cases <(find "$output_root" -name case_report.json -print | sort | xargs -r jq -c '.') \
    '{
      schema_version:$schema_version,
      bead_id:$bead_id,
      output_root:$output_root,
      case_count:($cases | length),
      cases:$cases,
      no_delete_contract:{
        fixture_repos_are_temporary:true,
        compares_path_content_mtime:true,
        compares_git_index:true,
        deletes_fixture_files:false,
        moves_fixture_files:false,
        rewrites_fixture_files:false,
        stages_fixture_files:false
      },
      rch_heavy_command_guidance:"Run heavy Cargo validation through validation_hygiene_wrapper.sh with env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/data/tmp/franken_engine-validation CARGO_INCREMENTAL=0 RUSTFLAGS='\''-C linker=cc -Clinker-features=-lld'\'' cargo ..."
    }' >"$aggregate_json"

  {
    printf '# Validation Hygiene No-Delete E2E\n\n'
    printf -- '- bead_id: `bd-u9sp4.6`\n'
    printf -- '- cases: `%s`\n' "$(jq -r '.case_count' "$aggregate_json")"
    printf -- '- output_root: `%s`\n\n' "$output_root"
    jq -r '.cases[] | "- `" + .case_id + "`: " + .classifier.status + " / " + (.classifier.first_blocker.class // "none")' "$aggregate_json"
    printf '\nHeavy Cargo commands under test must use `env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=... CARGO_INCREMENTAL=0 RUSTFLAGS='
    printf "'-C linker=cc -Clinker-features=-lld'"
    printf ' cargo ...` through the wrapper.\n'
  } >"$aggregate_md"
}

run_check() {
  require_tools
  script_static_ok
  record_pass "check"
}

run_selftest() {
  mkdir -p "$output_root"
  run_check
  run_tracked_unrelated
  run_untracked_probe
  run_in_scope_failure
  run_ignored_artifact
  run_mixed_blockers
  run_unknown_output
  write_aggregate_report
  jq -e '.schema_version == "franken-engine.validation-hygiene-no-delete-e2e.v1" and .case_count == 6' \
    "${output_root}/validation_hygiene_no_delete_e2e_report.json" >/dev/null || record_failure "aggregate report"
  record_pass "selftest"
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
