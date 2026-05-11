#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/idea_wizard_iv_zero_ready_saturation_drill.sh"
replay="${root_dir}/scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-zero-ready-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-zero-ready-drill %s\n' "$1" >&2
  exit 1
}

write_fixture_bundle() {
  local tmpdir="$1"
  local ready_count="$2"
  if [[ "$ready_count" -eq 0 ]]; then
    printf '[]\n' >"${tmpdir}/br_ready.json"
  else
    printf '[{"id":"bd-open","status":"open","title":"not saturated"}]\n' >"${tmpdir}/br_ready.json"
  fi
  cat >"${tmpdir}/br_list.json" <<'JSON'
[
  {
    "id": "bd-closed",
    "title": "Strong closed bead",
    "status": "closed",
    "priority": 1,
    "updated_at": "2026-05-11T00:00:00Z",
    "closed_at": "2026-05-11T00:00:00Z",
    "close_reason": "Done in commit abc1234. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p frankenengine-engine zero_ready_saturation",
    "labels": ["idea-wizard"]
  }
]
JSON
  cat >"${tmpdir}/br_in_progress.json" <<'JSON'
[{"id":"bd-aqijn","status":"in_progress","assignee":"RainyBadger"}]
JSON
  cat >"${tmpdir}/mail_health.json" <<'JSON'
{"status":"error","health_level":"red","semantic_readiness":{"status":"fail","detail":"sqlite schema missing required health_check tables: projects, agents, messages, message_recipients"}}
JSON
  cat >"${tmpdir}/rch_status.json" <<'JSON'
{"workers":[{"worker_id":"w1","slots_available":8,"total_slots":8,"active_compiles":0,"status":"idle"}],"queue_depth":0,"local_fallback_detected":false}
JSON
  cat >"${tmpdir}/git_status.json" <<'JSON'
{"tracked_dirty":false,"untracked":[".stash_janitor_workspace/"],"allowed_untracked":[".stash_janitor_workspace/"]}
JSON
  cat >"${tmpdir}/queue.json" <<'JSON'
{"queue_depth":0}
JSON
  cat >"${tmpdir}/target.json" <<'JSON'
{"schema_version":"franken-engine.swarm-rch-target-dir-heatmap.v1","decision":"pass","cache_heat":"warm"}
JSON
  cat >"${tmpdir}/cache.json" <<'JSON'
{"schema_version":"franken-engine.swarm-proof-cache-locality-plan.v1","decision":"pass","cache_heat":"warm"}
JSON
  cat >"${tmpdir}/pressure.json" <<'JSON'
{"memory_available_bytes":274877906944,"memory_pressure":"low"}
JSON
  cat >"${tmpdir}/archive.json" <<'JSON'
{"schema_version":"franken-engine.remote-proof-archive-pressure-scoreboard.v1","pressure_class":"low","decision":"retain"}
JSON
  cat >"${tmpdir}/resource.json" <<'JSON'
{"schema_version":"franken-engine.swarm-resource-envelope.v1","decision":"pass","memory":{"available_bytes":274877906944}}
JSON
}

run_drill_case() {
  local case_id="$1"
  local ready_count="$2"
  local expected_decision="$3"
  local expected_exit="$4"
  local tmpdir output_dir status

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  write_fixture_bundle "$tmpdir" "$ready_count"
  set +e
  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="" \
    IDEA_WIZARD_IV_ZERO_READY_DRILL_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$drill" \
    --br-ready-json "${tmpdir}/br_ready.json" \
    --br-list-json "${tmpdir}/br_list.json" \
    --br-in-progress-json "${tmpdir}/br_in_progress.json" \
    --mail-health-json "${tmpdir}/mail_health.json" \
    --rch-status-json "${tmpdir}/rch_status.json" \
    --git-status-json "${tmpdir}/git_status.json" \
    --queue-depth-json "${tmpdir}/queue.json" \
    --target-dir-heatmap-json "${tmpdir}/target.json" \
    --proof-cache-locality-json "${tmpdir}/cache.json" \
    --pressure-metrics-json "${tmpdir}/pressure.json" \
    --archive-pressure-json "${tmpdir}/archive.json" \
    --resource-envelope-json "${tmpdir}/resource.json" \
    --changed-path "docs/idea_wizard_iv_saturation_convergence_v1.json" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_exit}"
  fi
  [[ -f "${output_dir}/saturation_convergence_report.json" ]] || record_failure "missing report for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/trace_ids.json" ]] || record_failure "missing trace ids for ${case_id}"
  [[ -f "${output_dir}/step_logs/step_000.log" ]] || record_failure "missing step log for ${case_id}"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/saturation_convergence_report.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  "$replay" --bundle-dir "$output_dir" >/dev/null \
    || record_failure "replay failed for ${case_id}"
  record_pass "$case_id"
}

run_replay_missing_child_case() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  cat >"${tmpdir}/saturation_convergence_report.json" <<'JSON'
{"schema_version":"franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1","decision":"fail_closed","child_reports":[{"surface_id":"closed","path":"","decision":"missing"},{"surface_id":"coord","path":"x","decision":"degraded"},{"surface_id":"validation","path":"x","decision":"degraded"},{"surface_id":"heatmap","path":"x","decision":"degraded"}],"mutation_policy":{"mutates_br":false,"runs_cargo":false,"runs_rch":false},"artifact_paths":{"saturation_convergence_report_json":"x"}}
JSON
  printf '{"schema_version":"manifest"}\n' >"${tmpdir}/run_manifest.json"
  printf '{"schema_version":"trace"}\n' >"${tmpdir}/trace_ids.json"
  : >"${tmpdir}/events.jsonl"
  : >"${tmpdir}/commands.txt"
  if "$replay" --bundle-dir "$tmpdir" >/dev/null 2>&1; then
    record_failure "replay unexpectedly accepted missing child"
  fi
  record_pass "replay-missing-child"
}

run_check() {
  bash -n "$drill" "$replay" "${BASH_SOURCE[0]}"
  run_drill_case "zero-ready-red-mail" 0 "degraded" 0
  run_drill_case "nonzero-ready" 1 "fail_closed" 42
  run_replay_missing_child_case
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_ZERO_READY_SATURATION_DRILL.md \
    scripts/idea_wizard_iv_zero_ready_saturation_drill.sh \
    scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh \
    scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
