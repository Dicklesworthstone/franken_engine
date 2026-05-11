#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
heatmap="${root_dir}/scripts/idea_wizard_iv_resource_proof_heatmap.sh"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-resource-proof-heatmap %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-resource-proof-heatmap %s\n' "$1" >&2
  exit 1
}

write_common_optional_files() {
  local tmpdir="$1"
  cat >"${tmpdir}/target.json" <<'JSON'
{"schema_version":"franken-engine.swarm-rch-target-dir-heatmap.v1","decision":"pass","cache_heat":"warm"}
JSON
  cat >"${tmpdir}/cache.json" <<'JSON'
{"schema_version":"franken-engine.swarm-proof-cache-locality-plan.v1","decision":"pass","cache_heat":"warm"}
JSON
  cat >"${tmpdir}/pressure.json" <<'JSON'
{"memory_available_bytes":274877906944,"memory_pressure":"low"}
JSON
  cat >"${tmpdir}/validation.json" <<'JSON'
{"schema_version":"franken-engine.idea-wizard-iv-validation-impact-plan.v1","decision":"green","cost_class":"low","recommended_commands":[{"display":"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_iw4_smoke cargo check --all-targets"}]}
JSON
  cat >"${tmpdir}/archive.json" <<'JSON'
{"schema_version":"franken-engine.remote-proof-archive-pressure-scoreboard.v1","pressure_class":"low","decision":"retain"}
JSON
  cat >"${tmpdir}/resource.json" <<'JSON'
{"schema_version":"franken-engine.swarm-resource-envelope.v1","decision":"pass","memory":{"available_bytes":274877906944}}
JSON
  cat >"${tmpdir}/queue.json" <<'JSON'
{"queue_depth":0}
JSON
}

write_case_files() {
  local case_id="$1"
  local tmpdir="$2"
  write_common_optional_files "$tmpdir"
  case "$case_id" in
    healthy-idle)
      cat >"${tmpdir}/rch.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":8,"total_slots":8,"active_compiles":0,"status":"idle"},{"worker_id":"w2","slots_available":8,"total_slots":8,"active_compiles":0,"status":"idle"}],"queue_depth":0,"local_fallback_detected":false}
JSON
      ;;
    high-compile-count)
      cat >"${tmpdir}/rch.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":0,"total_slots":32,"active_compiles":32,"status":"busy"}],"queue_depth":40,"local_fallback_detected":false}
JSON
      ;;
    archive-pressure)
      cat >"${tmpdir}/rch.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":4,"total_slots":8,"active_compiles":1,"status":"idle"}],"queue_depth":1,"local_fallback_detected":false}
JSON
      cat >"${tmpdir}/archive.json" <<'JSON'
{"schema_version":"franken-engine.remote-proof-archive-pressure-scoreboard.v1","pressure_class":"critical","decision":"compact_first"}
JSON
      ;;
    local-fallback)
      cat >"${tmpdir}/rch.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":4,"total_slots":8,"active_compiles":0,"status":"local_fallback"}],"queue_depth":0,"local_fallback_detected":true}
JSON
      ;;
    missing-optional-metrics)
      cat >"${tmpdir}/rch.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":4,"total_slots":8,"active_compiles":0,"status":"idle"}],"queue_depth":0,"local_fallback_detected":false}
JSON
      ;;
    *)
      record_failure "unknown fixture ${case_id}"
      ;;
  esac
}

run_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_worker_pressure="$3"
  local tmpdir output_dir status expected_status

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  write_case_files "$case_id" "$tmpdir"
  expected_status=0
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_status=42
  fi

  set +e
  if [[ "$case_id" == "missing-optional-metrics" ]]; then
    IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
      "$heatmap" \
      --rch-status-json "${tmpdir}/rch.json" \
      --source-revision "smoke-${case_id}" \
      --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  else
    IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
      "$heatmap" \
      --rch-status-json "${tmpdir}/rch.json" \
      --queue-depth-json "${tmpdir}/queue.json" \
      --target-dir-heatmap-json "${tmpdir}/target.json" \
      --proof-cache-locality-json "${tmpdir}/cache.json" \
      --pressure-metrics-json "${tmpdir}/pressure.json" \
      --validation-impact-plan-json "${tmpdir}/validation.json" \
      --archive-pressure-json "${tmpdir}/archive.json" \
      --resource-envelope-json "${tmpdir}/resource.json" \
      --source-revision "smoke-${case_id}" \
      --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  fi
  status=$?
  set -e

  if [[ "$status" -ne "$expected_status" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_status}"
  fi

  [[ -f "${output_dir}/resource_proof_heatmap.json" ]] || record_failure "missing heatmap for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/trace_ids.json" ]] || record_failure "missing trace ids for ${case_id}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing report for ${case_id}"

  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  jq -e --arg pressure "$expected_worker_pressure" '.worker_pressure.class == $pressure' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
    || record_failure "worker pressure mismatch for ${case_id}"
  jq -e '.mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false and .mutation_policy.mutates_remote_workers == false and .mutation_policy.deletes_or_overwrites_target_dirs == false' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
    || record_failure "mutation policy mismatch for ${case_id}"
  grep -Fq 'rch exec -- env CARGO_TARGET_DIR=' "${output_dir}/commands.txt" \
    || record_failure "missing rch command guidance for ${case_id}"

  if [[ "$case_id" == "high-compile-count" ]]; then
    jq -e 'any(.scheduling_advice[]?; test("Defer broad Cargo proof"))' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
      || record_failure "missing defer advice for high compile count"
  fi
  if [[ "$case_id" == "local-fallback" ]]; then
    jq -e 'any(.fail_closed_reasons[]?; .code == "FE-IW4-LOCAL-FALLBACK-CONTAMINATION")' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
      || record_failure "missing local fallback reason"
  fi
  if [[ "$case_id" == "missing-optional-metrics" ]]; then
    jq -e '(.degraded_reasons | length) >= 5' "${output_dir}/resource_proof_heatmap.json" >/dev/null \
      || record_failure "missing optional metric degraded reasons"
  fi

  record_pass "$case_id"
}

run_check() {
  bash -n "$heatmap" "${BASH_SOURCE[0]}"
  run_case "healthy-idle" "green" "idle"
  run_case "high-compile-count" "degraded" "saturated"
  run_case "archive-pressure" "degraded" "moderate"
  run_case "local-fallback" "fail_closed" "contaminated"
  run_case "missing-optional-metrics" "degraded" "idle"
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP.md \
    scripts/idea_wizard_iv_resource_proof_heatmap.sh \
    scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
