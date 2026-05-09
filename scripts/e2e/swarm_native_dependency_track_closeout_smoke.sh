#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
closeout_script="${root_dir}/scripts/swarm_native_dependency_track_closeout.sh"
docs_path="${root_dir}/docs/SWARM_NATIVE_DEPENDENCY_ROUTING_TRACK_CLOSEOUT.md"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_track_closeout/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-track-closeout %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-track-closeout %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_track_closeout_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq '(^|[^a-z])master([^a-z]|$)|apt(-get)? install|dnf install|yum install|rm -rf|mutates remote workers|repairs workers automatically|reroutes live tasks automatically|updates beads automatically|sends Agent Mail automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden operator wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,360p' "$path")
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-track-closeout-cases.v1"
    and .parent_bead_id == "bd-sqm14"
    and ([.child_beads[].bead_id] | sort == [
      "bd-sqm14.1",
      "bd-sqm14.2",
      "bd-sqm14.3",
      "bd-sqm14.4",
      "bd-sqm14.5",
      "bd-sqm14.6",
      "bd-sqm14.7",
      "bd-sqm14.8",
      "bd-sqm14.9"
    ])
    and all(.child_beads[]; (.artifacts | length > 0) and (.allowed_statuses | length > 0))
    and (.expected_dependency_edges | length >= 20)
    and (.graph_check.argv | join(" ") | contains("bv --robot-insights"))
    and (.proof_commands | length == 8)
    and all(.proof_commands[]; .expected_exit_code == 0)
  ' "$cases_path" >/dev/null
}

run_check() {
  bash -n "$closeout_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$cases_path"
  if cases_shape_ok; then
    record_pass "fixture cases"
  else
    record_failure "fixture cases mismatch"
  fi

  grep -Fq 'Live worker proof is optional operator proof' "$docs_path" || record_failure "docs must mark live proof optional"
  grep -Fq 'bd-sqm14.9' "$docs_path" || record_failure "docs must include planner integration child"
  grep -Fq 'No broad Rust gates are required' "$docs_path" || record_failure "docs must document cargo-free closeout"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$closeout_script"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$closeout_script"
  check_no_bare_heavy_cargo "$cases_path"
}

run_selftest() {
  local tmp_root output_dir code
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-track-closeout-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"
  code=0
  set +e
  bash "$closeout_script" \
    --source-revision fixture-rev \
    --cases-json "$cases_path" \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne 0 ]]; then
    record_failure "closeout verifier expected exit 0, got ${code}"
    return
  fi
  jq -e '
    .complete == true
    and .graph.cycle_count == 0
    and .live_rch_required == false
    and .live_rch_operator_proof_optional == true
    and .failures.artifacts == 0
    and .failures.dependencies == 0
    and .failures.proof_commands == 0
    and (.proof_commands | all(.ok == true))
    and (.artifacts | all(.exists == true))
  ' "${output_dir}/native_dependency_track_closeout_manifest.json" >/dev/null || {
    record_failure "manifest did not prove closeout completeness"
    return
  }
  grep -Fq 'Deterministic fixture proof covers all native dependency routing children' "${output_dir}/native_dependency_track_closeout_report.md" || {
    record_failure "report missing deterministic proof wording"
    return
  }
  [[ -s "${output_dir}/events.jsonl" ]] || {
    record_failure "event log missing"
    return
  }
  [[ -s "${output_dir}/proof_results.jsonl" ]] || {
    record_failure "proof results missing"
    return
  }
  record_pass "selftest closeout verifier"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
