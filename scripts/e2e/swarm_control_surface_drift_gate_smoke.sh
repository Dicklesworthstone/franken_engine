#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/swarm_control_surface_drift_gate.sh"
docs_path="${root_dir}/docs/SWARM_CONTROL_SURFACE_DRIFT_GATE.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_control_surface_drift_gate/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-control-surface-drift-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-surface-drift-gate %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_control_surface_drift_gate_smoke.sh [check|selftest]
EOF
}

write_workspace_file() {
  local workspace="$1"
  local path="$2"
  local kind="$3"
  local full_path="${workspace}/${path}"

  mkdir -p "$(dirname "$full_path")"
  case "$kind" in
    contract)
      jq -n --arg schema_version "franken-engine.test-contract.v1" '{schema_version:$schema_version}' >"$full_path"
      ;;
    malformed_contract)
      printf '{not-json\n' >"$full_path"
      ;;
    smoke)
      {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf '%s\n' "case \"\${1:-check}\" in"
        printf '%s\n' '  check) ;;'
        printf '%s\n' '  selftest) ;;'
        printf '%s\n' 'esac'
      } >"$full_path"
      ;;
    bad_smoke)
      {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf '%s\n' "case \"\${1:-check}\" in"
        printf '%s\n' '  check) ;;'
        printf '%s\n' 'esac'
      } >"$full_path"
      ;;
    shell)
      printf '#!/usr/bin/env bash\nset -euo pipefail\n' >"$full_path"
      ;;
    *)
      printf 'fixture\n' >"$full_path"
      ;;
  esac
}

materialize_workspace() {
  local case_json="$1"
  local workspace="$2"
  local file_json

  mkdir -p "$workspace"
  while IFS= read -r file_json; do
    local path kind
    path="$(jq -r '.path' <<<"$file_json")"
    kind="$(jq -r '.kind' <<<"$file_json")"
    write_workspace_file "$workspace" "$path" "$kind"
  done < <(jq -c '.workspace_files[]' <<<"$case_json")
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root workspace catalog script_inventory bead_status output_dir expected_decision expected_exit expected_reason status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-drift-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  workspace="${tmp_root}/workspace"
  catalog="${tmp_root}/catalog.json"
  script_inventory="${tmp_root}/script_inventory.json"
  bead_status="${tmp_root}/bead_status.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  materialize_workspace "$case_json" "$workspace"
  jq '.catalog' <<<"$case_json" >"$catalog"
  jq '.script_inventory' <<<"$case_json" >"$script_inventory"
  jq '.bead_status' <<<"$case_json" >"$bead_status"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  "$gate" \
    --catalog-json "$catalog" \
    --script-inventory-json "$script_inventory" \
    --bead-status-json "$bead_status" \
    --workspace-root "$workspace" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/control_surface_drift_report.json" >/dev/null \
    || record_failure "${case_id} decision mismatch"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any(.findings[]; .code == $code)' "${output_dir}/control_surface_drift_report.json" >/dev/null \
      || record_failure "${case_id} missing reason ${expected_reason}"
  fi

  jq empty "${output_dir}/control_surface_drift_report.json"
  [[ -s "${output_dir}/events.jsonl" ]] || record_failure "${case_id} missing events"
  grep -Fq './scripts/swarm_control_surface_drift_gate.sh' "${output_dir}/commands.txt" \
    || record_failure "${case_id} missing commands invocation"
  grep -Fq 'decision:' "${output_dir}/report.md" || record_failure "${case_id} missing report decision"
  record_pass "$case_id"
}

run_check() {
  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"
  jq -e '.cases | length == 12' "$fixtures_path" >/dev/null
  grep -Fq 'The gate is artifact-fed and advisory only.' "$docs_path" \
    || record_failure "missing advisory-only docs wording"
  record_pass "check"
}

run_selftest() {
  local case_id
  run_check
  while IFS= read -r case_id; do
    run_fixture_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
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
    ;;
esac
