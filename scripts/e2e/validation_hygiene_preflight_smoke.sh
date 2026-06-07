#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
preflight_path="${root_dir}/scripts/validation_hygiene_preflight.sh"
mode="${1:-check}"
output_root="${2:-${VALIDATION_HYGIENE_PREFLIGHT_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-preflight-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS validation-hygiene-preflight %s\n' "$1"
}

record_failure() {
  printf 'FAIL validation-hygiene-preflight %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/validation_hygiene_preflight_smoke.sh [check|selftest] [output_root]
EOF
}

script_static_ok() {
  bash -n "$preflight_path" "${BASH_SOURCE[0]}"
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "validation-hygiene@example.invalid"
  git -C "$repo" config user.name "Validation Hygiene"
  mkdir -p "$repo/src" "$repo/tests" "$repo/docs" "$repo/scripts"
  printf 'fn main() {}\n' >"$repo/src/main.rs"
  printf '# Contract\n' >"$repo/docs/contract.md"
  printf '#!/usr/bin/env bash\nset -euo pipefail\n' >"$repo/scripts/check.sh"
  git -C "$repo" add src/main.rs docs/contract.md scripts/check.sh
  git -C "$repo" commit -q -m "initial fixture"
}

run_preflight() {
  local repo="$1"
  local case_id="$2"
  local scope="$3"
  local out_dir="${output_root}/${case_id}/out"

  "$preflight_path" \
    --repo-root "$repo" \
    --case-id "$case_id" \
    --bead-id "bd-u9sp4.5" \
    --agent "SilverPeak" \
    --scope "$scope" \
    --output-dir "$out_dir" \
    --format none
}

assert_common() {
  local case_id="$1"
  local report="${output_root}/${case_id}/out/preflight_report.json"
  jq empty "$report" >/dev/null || {
    record_failure "${case_id} invalid json"
    return
  }
  jq -e '
    .schema_version == "franken-engine.validation-hygiene-preflight.v1"
    and .bead_id == "bd-u9sp4.5"
    and .agent_name == "SilverPeak"
    and .claim_limits.scoped_validation_proves_full_workspace_gate == false
    and .claim_limits.full_gate_blockers_must_remain_visible == true
    and (.no_delete_no_revert_disclaimer | contains("Do not delete"))
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
    and .non_mutation_attestation.mutates_git_index == false
    and .non_mutation_attestation.deletes_files == false
  ' "$report" >/dev/null || record_failure "${case_id} common report mismatch"
  test -s "${output_root}/${case_id}/out/events.jsonl" || record_failure "${case_id} missing events"
  test -s "${output_root}/${case_id}/out/commands.txt" || record_failure "${case_id} missing commands"
  test -s "${output_root}/${case_id}/out/report.md" || record_failure "${case_id} missing report"
}

run_clean_tree() {
  local repo="${output_root}/clean-tree/repo"
  init_repo "$repo"
  run_preflight "$repo" "clean-tree" "docs/contract.md"
  assert_common "clean-tree"
  jq -e '(.risks | length == 0) and (.validation_suggestions | any(.claim_scope == "docs_only"))' \
    "${output_root}/clean-tree/out/preflight_report.json" >/dev/null || record_failure "clean-tree risks/suggestions"
  record_pass "clean-tree"
}

run_unrelated_tracked() {
  local repo="${output_root}/unrelated-tracked/repo"
  init_repo "$repo"
  printf 'fn main(){println!("dirty");}\n' >"$repo/src/main.rs"
  run_preflight "$repo" "unrelated-tracked" "docs/contract.md"
  assert_common "unrelated-tracked"
  jq -e '.risks | any(.risk_type == "tracked_unrelated_dirty" and .path == "src/main.rs")' \
    "${output_root}/unrelated-tracked/out/preflight_report.json" >/dev/null || record_failure "unrelated-tracked risk"
  record_pass "unrelated-tracked"
}

run_untracked_probe() {
  local repo="${output_root}/untracked-probe/repo"
  init_repo "$repo"
  printf '#[test]\nfn probe() {}\n' >"$repo/tests/gl_parser_gap_probe.rs"
  run_preflight "$repo" "untracked-probe" "docs/contract.md"
  assert_common "untracked-probe"
  jq -e '.dirty_context.untracked_files | any(.classification == "untracked_ephemeral_candidate" and .path == "tests/gl_parser_gap_probe.rs")' \
    "${output_root}/untracked-probe/out/preflight_report.json" >/dev/null || record_failure "untracked-probe classification"
  record_pass "untracked-probe"
}

run_in_scope_dirty() {
  local repo="${output_root}/in-scope-dirty/repo"
  init_repo "$repo"
  printf '# Contract\n\nupdated\n' >"$repo/docs/contract.md"
  run_preflight "$repo" "in-scope-dirty" "docs/contract.md"
  assert_common "in-scope-dirty"
  jq -e '.risks | any(.risk_type == "in_scope_dirty" and .path == "docs/contract.md")' \
    "${output_root}/in-scope-dirty/out/preflight_report.json" >/dev/null || record_failure "in-scope-dirty risk"
  record_pass "in-scope-dirty"
}

run_shell_scope() {
  local repo="${output_root}/shell-scope/repo"
  init_repo "$repo"
  printf '#!/usr/bin/env bash\nset -euo pipefail\necho ok\n' >"$repo/scripts/check.sh"
  run_preflight "$repo" "shell-scope" "scripts/check.sh"
  assert_common "shell-scope"
  jq -e '(.validation_suggestions | any(.command | startswith("bash -n"))) and (.validation_suggestions | any(.command | startswith("shellcheck -x")))' \
    "${output_root}/shell-scope/out/preflight_report.json" >/dev/null || record_failure "shell-scope suggestions"
  record_pass "shell-scope"
}

run_output_modes() {
  local repo="${output_root}/output-modes/repo"
  local json_out text_out
  init_repo "$repo"
  json_out="$(
    "$preflight_path" \
      --repo-root "$repo" \
      --case-id "output-json" \
      --bead-id "bd-u9sp4.5" \
      --agent "SilverPeak" \
      --scope "docs/contract.md" \
      --output-dir "${output_root}/output-modes/json-out" \
      --format json
  )"
  printf '%s\n' "$json_out" | jq -e '.schema_version == "franken-engine.validation-hygiene-preflight.v1" and .output_format == "json"' >/dev/null \
    || record_failure "output-modes json"

  text_out="$(
    "$preflight_path" \
      --repo-root "$repo" \
      --case-id "output-text" \
      --bead-id "bd-u9sp4.5" \
      --agent "SilverPeak" \
      --scope "docs/contract.md" \
      --output-dir "${output_root}/output-modes/text-out" \
      --format text
  )"
  printf '%s\n' "$text_out" | rg -q '^# Validation Hygiene Preflight$' \
    || record_failure "output-modes text"
  record_pass "output-modes"
}

run_check() {
  script_static_ok
  rg -n 'scoped_validation_proves_full_workspace_gate|no_delete_no_revert_disclaimer|tracked_unrelated_dirty|untracked_ephemeral_candidate|validation_suggestions' "$preflight_path" >/dev/null
  record_pass "check"
}

run_selftest() {
  mkdir -p "$output_root"
  run_check
  run_clean_tree
  run_unrelated_tracked
  run_untracked_probe
  run_in_scope_dirty
  run_shell_scope
  run_output_modes
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
