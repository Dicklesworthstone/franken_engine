#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_RESIDENCY_REMOTE_PROOF_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-residency-remote-proof-drill}"
run_id="${SWARM_RESIDENCY_REMOTE_PROOF_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESIDENCY_REMOTE_PROOF_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"

record_pass() {
  printf 'PASS swarm-residency-remote-proof-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-residency-remote-proof-drill %s\n' "$1" >&2
}

write_report() {
  local output_dir="$1"
  local sticky_plan="$2"
  local hotspot_ledger="$3"
  local retrieval_verdict="$4"
  local incident_packet="$5"

  local events_path="${output_dir}/events.jsonl"
  local commands_path="${output_dir}/commands.txt"
  local report_json="${output_dir}/residency_drill_report.json"
  local report_md="${output_dir}/report.md"
  mkdir -p "$output_dir"
  : >"$events_path"
  printf 'bash scripts/e2e/swarm_residency_remote_proof_drill.sh selftest\n' >"$commands_path"

  jq -n \
    --slurpfile sticky "$sticky_plan" \
    --slurpfile hotspot "$hotspot_ledger" \
    --slurpfile retrieval "$retrieval_verdict" \
    --slurpfile incident "$incident_packet" '
    ($sticky[0]) as $sticky
    | ($hotspot[0]) as $hotspot
    | ($retrieval[0]) as $retrieval
    | ($incident[0]) as $incident
    | (
        if ($sticky.plan_decision == "admit_sticky")
          and (($sticky.phase_plans | length) == 3)
          and ($hotspot.repeated_hotspot_count > 0)
          and ($hotspot.total_full_sync_commands > 0)
          and ($retrieval.budget_verdict == "pass")
          and ($incident.failure_kind == "clean_remote_success")
        then
          {
            drill_status: "pass",
            reason: "warm worker reuse, repeated sync hotspot evidence, bounded retrieval, and clean incident packet all agree"
          }
        elif ($retrieval.budget_verdict == "fail_closed") then
          {
            drill_status: "fail_closed",
            reason: "artifact retrieval exceeded the declared replay budget"
          }
        elif ($incident.failure_kind == "canceled_build_live_orphaned_rustc") then
          {
            drill_status: "fail_closed",
            reason: "orphaned remote compile evidence blocks safe proof reuse"
          }
        else
          {
            drill_status: "degraded",
            reason: "residency drill inputs do not prove a safe warm remote proof lane"
          }
        end
      ) as $decision
    | {
        schema_version: "franken-engine.swarm-residency-remote-proof-drill.v1",
        drill_status: $decision.drill_status,
        reason: $decision.reason,
        sticky_worker_decision: ($sticky.plan_decision // "unknown"),
        sticky_worker_id: ($sticky.assigned_worker_id // null),
        sticky_target_dir: ($sticky.assigned_target_dir // null),
        hotspot_repeated_count: ($hotspot.repeated_hotspot_count // 0),
        hotspot_full_sync_commands: ($hotspot.total_full_sync_commands // 0),
        retrieval_budget_verdict: ($retrieval.budget_verdict // "unknown"),
        incident_failure_kind: ($incident.failure_kind // "unknown"),
        artifact_paths: {
          sticky_worker_warm_target_plan_json: ($sticky.artifact_paths.sticky_worker_warm_target_plan_json // null),
          sync_closure_hotspots_json: ($hotspot.artifact_paths.sync_closure_hotspots_json // null),
          artifact_retrieval_budget_verdict_json: ($retrieval.artifact_paths.artifact_retrieval_budget_verdict_json // null),
          incident_packet_json: ($incident.artifact_paths.incident_packet_json // null)
        }
      }
  ' >"$report_json"

  jq -nc --arg event "residency_drill_completed" --arg detail "$(jq -r '.reason' "$report_json")" \
    '{event: $event, detail: $detail}' >>"$events_path"

  {
    printf '# SWARM-CTRL-IV Residency Drill\n\n'
    printf -- '- Drill status: %s\n' "$(jq -r '.drill_status' "$report_json")"
    printf -- '- Reason: %s\n' "$(jq -r '.reason' "$report_json")"
    printf -- '- Sticky worker decision: %s\n' "$(jq -r '.sticky_worker_decision' "$report_json")"
    printf -- '- Sticky worker id: %s\n' "$(jq -r '.sticky_worker_id // "none"' "$report_json")"
    printf -- '- Hotspot repeated count: %s\n' "$(jq -r '.hotspot_repeated_count' "$report_json")"
    printf -- '- Retrieval budget verdict: %s\n' "$(jq -r '.retrieval_budget_verdict' "$report_json")"
    printf -- '- Incident failure kind: %s\n' "$(jq -r '.incident_failure_kind' "$report_json")"
  } >"$report_md"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  test -f "${root_dir}/scripts/sticky_worker_warm_target_lease_planner.sh"
  test -f "${root_dir}/scripts/rch_sync_closure_hotspot_ledger.sh"
  test -f "${root_dir}/scripts/artifact_retrieval_budget_manifest_gate.sh"
  test -f "${root_dir}/scripts/rch_incident_packet_gate.sh"
  record_pass "bash syntax and composed gate surfaces exist"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir case_dir

  run_check
  tmp_parent="${SWARM_RESIDENCY_REMOTE_PROOF_DRILL_SMOKE_ARTIFACT_ROOT:-$run_dir}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-residency-remote-proof-drill.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"

  jq -n '
    {
      schema_version: "franken-engine.sticky-worker-warm-target-lease-plan.v1",
      plan_decision: "admit_sticky",
      assigned_worker_id: "vmi1156319",
      assigned_target_dir: "/tmp/rch_target_franken_engine_bd_5az39",
      phase_plans: [
        {phase:"check"},
        {phase:"test"},
        {phase:"clippy"}
      ],
      artifact_paths: {
        sticky_worker_warm_target_plan_json: "/tmp/sticky_worker_warm_target_plan.json"
      }
    }
  ' >"${fixture_dir}/sticky-pass.json"
  jq -n '
    {
      schema_version: "franken-engine.rch-sync-closure-hotspot-ledger.v1",
      repeated_hotspot_count: 47,
      total_full_sync_commands: 2,
      artifact_paths: {
        sync_closure_hotspots_json: "/tmp/sync_closure_hotspots.json"
      }
    }
  ' >"${fixture_dir}/hotspots-pass.json"
  jq -n '
    {
      schema_version: "franken-engine.artifact-retrieval-budget-manifest-gate.v1",
      budget_verdict: "pass",
      artifact_paths: {
        artifact_retrieval_budget_verdict_json: "/tmp/artifact_retrieval_budget_verdict.json"
      }
    }
  ' >"${fixture_dir}/retrieval-pass.json"
  jq -n '
    {
      schema_version: "franken-engine.rch-incident-packet.v1",
      failure_kind: "clean_remote_success",
      artifact_paths: {
        incident_packet_json: "/tmp/incident_packet.json"
      }
    }
  ' >"${fixture_dir}/incident-pass.json"

  case_dir="${tmp_root}/warm-worker-success"
  write_report "$case_dir" \
    "${fixture_dir}/sticky-pass.json" \
    "${fixture_dir}/hotspots-pass.json" \
    "${fixture_dir}/retrieval-pass.json" \
    "${fixture_dir}/incident-pass.json"
  jq -e '
    .drill_status == "pass"
    and .sticky_worker_decision == "admit_sticky"
    and .sticky_worker_id == "vmi1156319"
    and .hotspot_repeated_count == 47
    and .retrieval_budget_verdict == "pass"
    and .incident_failure_kind == "clean_remote_success"
  ' "${case_dir}/residency_drill_report.json" >/dev/null
  record_pass "warm-worker success with repeated full-sync hotspot assertions"

  jq -n '
    {
      schema_version: "franken-engine.artifact-retrieval-budget-manifest-gate.v1",
      budget_verdict: "fail_closed",
      artifact_paths: {
        artifact_retrieval_budget_verdict_json: "/tmp/artifact_retrieval_budget_verdict.json"
      }
    }
  ' >"${fixture_dir}/retrieval-fail.json"
  case_dir="${tmp_root}/retrieval-over-budget-rejection"
  write_report "$case_dir" \
    "${fixture_dir}/sticky-pass.json" \
    "${fixture_dir}/hotspots-pass.json" \
    "${fixture_dir}/retrieval-fail.json" \
    "${fixture_dir}/incident-pass.json"
  jq -e '
    .drill_status == "fail_closed"
    and .retrieval_budget_verdict == "fail_closed"
  ' "${case_dir}/residency_drill_report.json" >/dev/null
  record_pass "retrieval over-budget rejection assertions"

  jq -n '
    {
      schema_version: "franken-engine.rch-incident-packet.v1",
      failure_kind: "canceled_build_live_orphaned_rustc",
      artifact_paths: {
        incident_packet_json: "/tmp/incident_packet.json"
      }
    }
  ' >"${fixture_dir}/incident-orphaned.json"
  case_dir="${tmp_root}/orphaned-compile-incident"
  write_report "$case_dir" \
    "${fixture_dir}/sticky-pass.json" \
    "${fixture_dir}/hotspots-pass.json" \
    "${fixture_dir}/retrieval-pass.json" \
    "${fixture_dir}/incident-orphaned.json"
  jq -e '
    .drill_status == "fail_closed"
    and .incident_failure_kind == "canceled_build_live_orphaned_rustc"
  ' "${case_dir}/residency_drill_report.json" >/dev/null
  record_pass "orphaned compile incident assertions"

  printf 'swarm_residency_remote_proof_drill_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
