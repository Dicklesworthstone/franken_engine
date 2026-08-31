#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT:-artifacts/red_team_compromise_rate_metric}"
run_id="${RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RED_TEAM_COMPROMISE_RATE_METRIC_RUN_DIR:-${artifact_root}/${run_id}}"
scenario_dir="${RED_TEAM_COMPROMISE_RATE_METRIC_SCENARIO_DIR:-${root_dir}/crates/franken-engine/tests/red_team_scenarios}"
code_revision="${RED_TEAM_COMPROMISE_RATE_METRIC_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
helper="${root_dir}/scripts/red_team_compromise_rate_metric.py"
verification_command="./scripts/run_red_team_compromise_rate_metric_gate.sh ${mode}"

run_bundle() {
  local bundle_dir="$1"
  local variant="$2"
  local force_franken_compromise="$3"
  local helper_rc=0
  local status_path="${bundle_dir}/bundle_status.json"
  local helper_args=(
    python3 "$helper"
    --root "$root_dir"
    --bundle-dir "$bundle_dir"
    --scenario-dir "$scenario_dir"
    --variant "$variant"
    --code-revision "$code_revision"
    --verification-command "$verification_command"
  )

  if [[ "$force_franken_compromise" == "true" ]]; then
    helper_args+=(--force-franken-compromise)
  fi

  "${helper_args[@]}" || helper_rc=$?
  if [[ ! -f "$status_path" ]]; then
    echo "red-team comparator failed without bundle_status.json: ${bundle_dir}" >&2
    return 1
  fi

  local status
  local failure_count
  status="$(jq -er '.status | select(. == "pass" or . == "fail" or . == "blocked")' "$status_path")"
  failure_count="$(jq -er '.failure_count | numbers' "$status_path")"

  proof_contract_write_standard_bundle \
    "$bundle_dir" \
    "red_team_compromise_rate_metric_gate" \
    "$status" \
    "$verification_command" \
    "${bundle_dir}/metric_report.json" \
    "${bundle_dir}/events.jsonl" \
    "${bundle_dir}/commands.txt" \
    "bd-0lim8,bd-1vwza,bd-x7nod,bd-35tcu" \
    "FE-CLAIM-011,disruptive_floor.red_team_compromise_rate_10x" \
    "$failure_count"

  echo "red_team_compromise_rate_metric_artifact=${bundle_dir}/metric_artifact.json"
  echo "red_team_compromise_rate_proof_manifest=${bundle_dir}/manifest.json"
  return "$helper_rc"
}

case "$mode" in
  ci)
    pass_rc=0
    run_bundle "${run_dir}/pass" "pass" "false" || pass_rc=$?
    if [[ "$pass_rc" -ne 0 ]]; then
      exit "$pass_rc"
    fi

    negative_rc=0
    run_bundle "${run_dir}/fail_closed" "fail_closed" "true" || negative_rc=$?
    if [[ "$negative_rc" -eq 0 ]]; then
      echo "negative fixture unexpectedly passed" >&2
      exit 1
    fi
    jq -e '.status == "fail" and .failure_count == 1' "${run_dir}/fail_closed/report.json" >/dev/null
    ;;
  pass)
    run_bundle "$run_dir" "pass" "false"
    ;;
  fail_closed)
    run_bundle "$run_dir" "fail_closed" "true"
    ;;
  *)
    echo "usage: $0 [ci|pass|fail_closed]" >&2
    exit 2
    ;;
esac
