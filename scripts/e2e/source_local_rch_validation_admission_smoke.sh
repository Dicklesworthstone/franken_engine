#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_path="${SOURCE_LOCAL_RCH_ADMISSION_FIXTURE_PATH:-${repo_root}/scripts/testdata/source_local_rch_validation_admission/cases.json}"
composer="${repo_root}/scripts/source_local_rch_validation_admission.sh"
mode="${1:-check}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/source_local_rch_validation_admission_smoke.sh [check|selftest]

Runs shell/JQ-only fixtures for source_local_rch_validation_admission.sh.
This smoke harness does not run Cargo or rch.
EOF
}

case "$mode" in
  check|selftest)
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 64
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for source-local rch admission smoke\n' >&2
  exit 2
fi
if [[ ! -x "$composer" ]]; then
  printf 'composer is not executable: %s\n' "$composer" >&2
  exit 64
fi
if [[ ! -f "$fixture_path" ]]; then
  printf 'fixture not found: %s\n' "$fixture_path" >&2
  exit 64
fi
jq empty "$fixture_path" >/dev/null

tmp_root="${SOURCE_LOCAL_RCH_ADMISSION_SMOKE_TMPDIR:-$(mktemp -d "${TMPDIR:-/tmp}/source-local-rch-admission-smoke.XXXXXX")}"
base_case_json="${tmp_root}/base_case.json"
jq -c '.cases[] | select(.case_id == "exact_reusable")' "$fixture_path" >"$base_case_json"

merge_case_field() {
  local case_json="$1"
  local field="$2"
  local patch_field="$3"
  local output_path="$4"

  jq -c \
    --slurpfile base "$base_case_json" \
    --arg field "$field" \
    --arg patch_field "$patch_field" '
      if (.inherit // "") == "exact_reusable" then
        ($base[0][$field] // {}) as $base_value
        | (.[$field] // {}) as $override
        | (.[$patch_field] // {}) as $patch
        | ($base_value * $override * $patch)
      else
        .[$field]
      end
    ' "$case_json" >"$output_path"
}

run_case() {
  local case_id="$1"
  local case_json="${tmp_root}/${case_id}.case.json"
  local request_file="${tmp_root}/${case_id}.request.json"
  local preflight_file="${tmp_root}/${case_id}.preflight.json"
  local proof_file="${tmp_root}/${case_id}.proof.json"
  local sticky_file="${tmp_root}/${case_id}.sticky.json"
  local out_dir="${tmp_root}/${case_id}.out"
  local stdout_file="${tmp_root}/${case_id}.stdout"
  local stderr_file="${tmp_root}/${case_id}.stderr"

  jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixture_path" >"$case_json"
  merge_case_field "$case_json" request request_patch "$request_file"
  merge_case_field "$case_json" preflight preflight_patch "$preflight_file"
  merge_case_field "$case_json" proof_admission proof_patch "$proof_file"
  merge_case_field "$case_json" sticky_plan sticky_patch "$sticky_file"
  mkdir -p "$out_dir"

  local expected_exit expected_decision expected_reason
  expected_exit="$(jq -r '.expected_exit' "$case_json")"
  expected_decision="$(jq -r '.expected_decision' "$case_json")"
  expected_reason="$(jq -r '.expected_reason // ""' "$case_json")"

  set +e
  "$composer" \
    --case-id "$case_id" \
    --request-json "$request_file" \
    --preflight-json "$preflight_file" \
    --proof-admission-json "$proof_file" \
    --sticky-plan-json "$sticky_file" \
    --output-dir "$out_dir" \
    >"$stdout_file" 2>"$stderr_file"
  local exit_code=$?
  set -e

  if [[ "$exit_code" != "$expected_exit" ]]; then
    printf 'case %s expected exit %s got %s\n' "$case_id" "$expected_exit" "$exit_code" >&2
    cat "$stderr_file" >&2
    exit 1
  fi

  local admission_json="${out_dir}/source_local_rch_validation_admission.json"
  local decision
  decision="$(jq -r '.admission_decision' "$admission_json")"
  if [[ "$decision" != "$expected_decision" ]]; then
    printf 'case %s expected decision %s got %s\n' "$case_id" "$expected_decision" "$decision" >&2
    exit 1
  fi

  if [[ -n "$expected_reason" ]]; then
    if ! jq -e --arg reason "$expected_reason" '.reason_codes | index($reason)' "$admission_json" >/dev/null; then
      printf 'case %s missing expected reason %s\n' "$case_id" "$expected_reason" >&2
      jq '.reason_codes' "$admission_json" >&2
      exit 1
    fi
  fi
}

mapfile -t case_ids < <(jq -r '.cases[].case_id' "$fixture_path")
for case_id in "${case_ids[@]}"; do
  run_case "$case_id"
done

printf 'source_local_rch_validation_admission_smoke=pass cases=%s tmp=%s\n' "${#case_ids[@]}" "$tmp_root"
