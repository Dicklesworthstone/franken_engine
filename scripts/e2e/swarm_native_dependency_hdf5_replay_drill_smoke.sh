#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill_script="${root_dir}/scripts/swarm_native_dependency_hdf5_replay_drill.sh"
docs_path="${root_dir}/docs/SWARM_NATIVE_DEPENDENCY_HDF5_REPLAY_DRILL.md"
cases_path="${root_dir}/scripts/testdata/swarm_native_dependency_hdf5_replay_drill/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-native-dependency-hdf5-replay-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-native-dependency-hdf5-replay-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_native_dependency_hdf5_replay_drill_smoke.sh [check|selftest]
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
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,320p' "$path")
}

cases_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-native-dependency-hdf5-replay-drill-cases.v1"
    and (.scenarios | length == 3)
    and ([.scenarios[].scenario_id] | sort == [
      "hdf5_fixture_all_workers_missing_blocked",
      "hdf5_fixture_selects_compatible_worker",
      "hdf5_fixture_stale_probe_fail_closed"
    ])
    and all(.scenarios[];
      (.expected.required_dependency_ids == ["hdf5"])
      and (.expected.hdf5_detected == true)
      and (.inputs.requirement_inference.validation_command_context_json.command | contains("rch exec -- env CARGO_TARGET_DIR="))
      and (.inputs.requirement_inference.path_dependency_manifests_json.packages | map(.name) | index("hdf5-metno-sys") != null)
      and (.inputs.rch_log_fixtures | length > 0)
      and all(.inputs.worker_probe_inputs[]; .raw_worker_probe_json.schema_version == "franken-engine.raw-worker-native-probe.v1")
      and (.expected_step_exit_codes.requirement_infer == 0)
    )
    and (.scenarios[] | select(.scenario_id == "hdf5_fixture_selects_compatible_worker") | .expected_exit_code == 0 and .expected.status == "PASS")
    and (.scenarios[] | select(.scenario_id == "hdf5_fixture_all_workers_missing_blocked") | .expected_exit_code == 75 and .expected.status == "BLOCKED")
    and (.scenarios[] | select(.scenario_id == "hdf5_fixture_stale_probe_fail_closed") | .expected_exit_code == 42 and .expected.status == "FAIL-CLOSED")
  ' "$cases_path" >/dev/null
}

run_check() {
  bash -n "$drill_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$cases_path"
  if cases_shape_ok; then
    record_pass "fixture cases"
  else
    record_failure "fixture cases mismatch"
  fi

  grep -Fq 'no-mock replay gate' "$docs_path" || record_failure "docs must identify no-mock replay gate"
  grep -Fq 'optional operator proof' "$docs_path" || record_failure "docs must mark live rch as optional operator proof"
  grep -Fq 'not evidence that the source patch failed' "$docs_path" || record_failure "docs must preserve source/environment wording"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$drill_script"
  check_no_mutation_claims "$cases_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$drill_script"
  check_no_bare_heavy_cargo "$cases_path"
}

assert_case_outputs() {
  local scenario="$1"
  local output_dir="$2"
  local expected_status expected_route_decision
  expected_status="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected.status' "$cases_path")"
  expected_route_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected.route_decision' "$cases_path")"

  jq -e \
    --arg status "$expected_status" \
    --arg route_decision "$expected_route_decision" \
    --argjson compatible "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected.compatible_worker_ids' "$cases_path")" '
      .operator_status == $status
      and .drill_decision == $route_decision
      and .compatible_worker_ids == $compatible
      and .required_dependency_ids == ["hdf5"]
      and .source_failure_claimed == false
      and .advisory_only == true
      and .live_rch_required == false
      and .live_rch_operator_proof_optional == true
    ' "${output_dir}/run_manifest.json" >/dev/null || {
      record_failure "${scenario} run_manifest mismatch"
      return 1
    }

  jq -e '
    .traces.requirement_infer
    and (.traces.worker_probes | length > 0)
    and .traces.route_planner
    and .traces.abi_cache_ledger
    and .traces.operator_status
  ' "${output_dir}/command_trace_ids.json" >/dev/null || {
    record_failure "${scenario} missing command trace ids"
    return 1
  }

  jq -e '
    .evidence.requirement.dependency_requirements | any(.dependency_id == "hdf5" and .required == true)
  ' "${output_dir}/step_evidence.json" >/dev/null || {
    record_failure "${scenario} did not infer HDF5 requirement"
    return 1
  }

  jq -e '.schema_version == "franken-engine.worker-native-probe-snapshot-set.v1" and (.snapshots | length > 0)' "${output_dir}/worker_probe_snapshots.json" >/dev/null || {
    record_failure "${scenario} missing worker probe snapshots"
    return 1
  }

  [[ -s "${output_dir}/native_dependency_routing_report.md" ]] || {
    record_failure "${scenario} missing routing report"
    return 1
  }
  [[ -s "${output_dir}/events.jsonl" ]] || {
    record_failure "${scenario} missing event log"
    return 1
  }
  [[ -s "${output_dir}/commands.txt" ]] || {
    record_failure "${scenario} missing command log"
    return 1
  }

  while IFS= read -r expected; do
    grep -Fq "$expected" "${output_dir}/native_dependency_routing_report.md" "${output_dir}/operator_status/agent_mail_handoff.md" "${output_dir}/operator_status/br_closeout_snippet.md" || {
      record_failure "${scenario} missing expected text: ${expected}"
      return 1
    }
  done < <(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_strings[]' "$cases_path")
}

run_selftest() {
  local tmp_root scenario output_dir expected_exit code
  tmp_root="${TMPDIR:-/tmp}/swarm-native-dependency-hdf5-replay-drill-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    output_dir="${tmp_root}/${scenario}/out"
    expected_exit="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$cases_path")"
    mkdir -p "$output_dir"
    code=0
    set +e
    bash "$drill_script" \
      --source-revision fixture-rev \
      --cases-json "$cases_path" \
      --scenario-id "$scenario" \
      --output-dir "$output_dir" >/dev/null
    code=$?
    set -e
    if [[ "$code" -ne "$expected_exit" ]]; then
      record_failure "${scenario} expected exit ${expected_exit}, got ${code}"
      continue
    fi
    assert_case_outputs "$scenario" "$output_dir" || continue
    record_pass "selftest ${scenario}"
  done < <(jq -r '.scenarios[].scenario_id' "$cases_path")
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
