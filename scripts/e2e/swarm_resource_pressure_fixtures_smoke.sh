#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures="${root_dir}/scripts/swarm_resource_pressure_fixtures.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS swarm-resource-pressure-fixtures %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-pressure-fixtures %s\n' "$1" >&2
}

canonicalize_fixtures() {
  local fixtures_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
    | del(.artifact_paths)
    | .generated_artifacts |= map(.sha256 = "[SHA256]")
  ' "$fixtures_path"
}

compare_golden() {
  local actual_path="$1"
  local golden_path="$2"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches"
}

run_selftest() {
  local tmp_parent tmp_root output_dir actual_path golden_path

  tmp_parent="${SWARM_RESOURCE_PRESSURE_FIXTURE_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-resource-pressure-fixtures.XXXXXX")"
  output_dir="${tmp_root}/fixtures"
  actual_path="${tmp_root}/swarm_resource_pressure_fixtures.actual.golden"
  golden_path="${golden_dir}/swarm_resource_pressure_fixtures.golden"

  "$fixtures" --bead-id bd-aq8nn --output-dir "$output_dir" >/dev/null
  jq -e '
    .schema_version == "franken-engine.swarm-resource-pressure-fixtures.v1"
    and .status == "pass"
    and .case_count == 12
    and .failure_count == 0
    and ([.cases[].case_id] | index("governor_cpu_pressure") != null)
    and ([.cases[].case_id] | index("planner_unknown_path_mapping") != null)
  ' "${output_dir}/fixtures.json" >/dev/null
  record_pass "fixture bundle validates"

  canonicalize_fixtures "${output_dir}/fixtures.json" "$tmp_root" >"$actual_path"
  compare_golden "$actual_path" "$golden_path"
  printf 'swarm_resource_pressure_fixture_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
