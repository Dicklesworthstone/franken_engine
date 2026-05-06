#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${RCH_REMOTE_COMPILE_STALL_BUNDLE_DOC:-${root_dir}/docs/RCH_REMOTE_COMPILE_STALL_BUNDLE_CONTRACT.md}"
contract_path="${RCH_REMOTE_COMPILE_STALL_BUNDLE_CONTRACT:-${root_dir}/docs/rch_remote_compile_stall_bundle_contract_v1.json}"
mode="${1:-check}"
bundle_path="${2:-}"

record_pass() {
  printf 'PASS rch-remote-compile-stall-bundle-contract %s\n' "$1"
}

record_fail() {
  printf 'FAIL rch-remote-compile-stall-bundle-contract %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

bundle_has_path() {
  local bundle="$1"
  local dotted_path="$2"
  jq -e --arg dotted_path "$dotted_path" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );
    dotted_get($dotted_path) != null
  ' "$bundle" >/dev/null
}

validate_bundle_against_contract() {
  local bundle="$1"

  jq -e --slurpfile contract "$contract_path" '
    ($contract[0]) as $contract_doc
    | .schema_version == $contract_doc.bundle_schema_version
    and (.capture_decision | IN("captured", "captured_degraded", "fail_closed"))
    and (.truth_state | IN("confirmed", "degraded", "blocked", "contaminated"))
  ' "$bundle" >/dev/null || return 1

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_has_path "$bundle" "$dotted_path" || return 1
  done < <(jq -r '.required_bundle_fields[]' "$contract_path")

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_has_path "$bundle" "$dotted_path" || return 1
  done < <(jq -r '.required_stall_subject_fields[]' "$contract_path")

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_has_path "$bundle" "$dotted_path" || return 1
  done < <(jq -r '.required_snapshot_health_fields[]' "$contract_path")

  jq -e '
    .snapshot_health.required_snapshot_count >= 4
    and .snapshot_health.required_present_count <= .snapshot_health.required_snapshot_count
    and .snapshot_health.optional_present_count <= .snapshot_health.optional_snapshot_count
    and (.snapshot_health.optional_present_count + .snapshot_health.optional_missing_count == .snapshot_health.optional_snapshot_count)
  ' "$bundle" >/dev/null || return 1

  jq -e '
    if .truth_state == "confirmed" then
      .capture_decision == "captured"
      and .local_fallback_observed == false
      and .snapshot_health.required_present_count == .snapshot_health.required_snapshot_count
      and .snapshot_health.optional_missing_count == 0
      and .snapshot_health.contradictory_snapshot_count == 0
      and (.blockers | length) == 0
    elif .truth_state == "degraded" then
      .capture_decision == "captured_degraded"
      and .local_fallback_observed == false
      and .snapshot_health.required_present_count == .snapshot_health.required_snapshot_count
      and .snapshot_health.optional_missing_count > 0
      and .snapshot_health.contradictory_snapshot_count == 0
    elif .truth_state == "blocked" then
      .capture_decision == "fail_closed"
      and .local_fallback_observed == false
      and (
        .snapshot_health.required_present_count < .snapshot_health.required_snapshot_count
        or .snapshot_health.contradictory_snapshot_count > 0
      )
      and (.blockers | length) > 0
    elif .truth_state == "contaminated" then
      .capture_decision == "fail_closed"
      and .local_fallback_observed == true
      and (.blockers | length) > 0
    else
      false
    end
  ' "$bundle" >/dev/null || return 1

  jq -e '
    .stall_subject.progress_age_seconds >= 0
    and .stall_subject.last_progress_epoch_seconds <= .captured_at_epoch_seconds
    and .queue_snapshot.captured_at_epoch_seconds <= .captured_at_epoch_seconds
    and .status_snapshot.captured_at_epoch_seconds <= .captured_at_epoch_seconds
  ' "$bundle" >/dev/null || return 1
}

assert_bundle_valid() {
  local bundle="$1"
  local label="$2"
  validate_bundle_against_contract "$bundle" \
    || record_fail "${label} failed bundle validation"
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic retry is allowed|automatically resolves|resolved remotely without proof|local fallback is acceptable|may mutate beads|can mutate beads|may release reservations|can release reservations|may send Agent Mail|can send Agent Mail|may mutate workers|can mutate workers' "$path"; then
    record_fail "${path#"$root_dir"/} contains unsafe truth or mutation wording"
  fi
}

write_bundle() {
  local path="$1"
  local scenario="$2"

  local capture_decision="captured"
  local truth_state="confirmed"
  local local_fallback_observed="false"
  local required_present_count="4"
  local optional_present_count="3"
  local optional_missing_count="0"
  local contradictory_snapshot_count="0"
  local blockers='[]'

  case "$scenario" in
    confirmed)
      ;;
    degraded_missing_optional)
      capture_decision="captured_degraded"
      truth_state="degraded"
      optional_present_count="1"
      optional_missing_count="2"
      blockers='[
        {
          "code": "optional_snapshot_missing",
          "detail": "worker_inventory_snapshot and operator_note are missing."
        }
      ]'
      ;;
    blocked_contradictory_queue)
      capture_decision="fail_closed"
      truth_state="blocked"
      contradictory_snapshot_count="1"
      blockers='[
        {
          "code": "queue_status_conflict",
          "detail": "rch queue and worker/jobs snapshots disagree on the active build owner."
        }
      ]'
      ;;
    contaminated_local_fallback)
      capture_decision="fail_closed"
      truth_state="contaminated"
      local_fallback_observed="true"
      blockers='[
        {
          "code": "local_fallback_observed",
          "detail": "rch refused local fallback after the remote timeout, so the bundle cannot be remote-only truth."
        }
      ]'
      ;;
    *)
      record_fail "unknown bundle scenario ${scenario}"
      ;;
  esac

  write_json "$path" "$(jq -n \
    --arg capture_decision "$capture_decision" \
    --arg truth_state "$truth_state" \
    --argjson local_fallback_observed "$local_fallback_observed" \
    --argjson required_present_count "$required_present_count" \
    --argjson optional_present_count "$optional_present_count" \
    --argjson optional_missing_count "$optional_missing_count" \
    --argjson contradictory_snapshot_count "$contradictory_snapshot_count" \
    --argjson blockers "$blockers" \
    '{
      schema_version: "franken-engine.rch-remote-compile-stall-bundle.v1",
      stall_bundle_id: "rch-remote-compile-stall-smoke",
      bead_id: "bd-gtr99",
      capture_decision: $capture_decision,
      truth_state: $truth_state,
      captured_at_epoch_seconds: 2000,
      local_fallback_observed: $local_fallback_observed,
      stall_subject: {
        command: "rch exec -- env RUSTUP_TOOLCHAIN=nightly cargo check -p frankenengine-engine --lib",
        worker_id: "vmi1153651",
        build_id: "29830575799926875",
        heartbeat: {
          phase: "remote_exec_start",
          detail: "fresh heartbeat but frozen progress_age",
          last_heartbeat_epoch_seconds: 1995
        },
        last_progress_epoch_seconds: 1500,
        progress_age_seconds: 500
      },
      snapshot_health: {
        required_snapshot_count: 4,
        required_present_count: $required_present_count,
        optional_snapshot_count: 3,
        optional_present_count: $optional_present_count,
        optional_missing_count: $optional_missing_count,
        contradictory_snapshot_count: $contradictory_snapshot_count
      },
      queue_snapshot: {
        capture_command: "rch queue --json",
        captured_at_epoch_seconds: 1990,
        queue_depth: 3,
        matching_build_present: true,
        matching_worker_present: true
      },
      status_snapshot: {
        capture_command: "rch status --workers --jobs --json",
        captured_at_epoch_seconds: 1991,
        active_build_count: 3,
        matching_worker_present: true,
        matching_build_present: true
      },
      blockers: $blockers,
      artifact_paths: {
        stall_bundle_json: "/fixture/stall_bundle.json",
        events_jsonl: "/fixture/events.jsonl",
        commands_txt: "/fixture/commands.txt",
        summary_md: "/fixture/summary.md"
      }
    }')"
}

run_check() {
  [[ -f "$docs_path" ]] || record_fail "missing doc ${docs_path}"
  [[ -f "$contract_path" ]] || record_fail "missing contract ${contract_path}"

  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.rch-remote-compile-stall-bundle-contract.v1"
    and .bead_id == "bd-m5jwi.1"
    and .parent_bead_id == "bd-m5jwi"
    and .bundle_schema_version == "franken-engine.rch-remote-compile-stall-bundle.v1"
    and .planned_producer_script == "scripts/rch_remote_compile_stall_bundle_capture.sh"
    and (.required_snapshot_contracts | length) == 4
    and (.optional_snapshot_contracts | length) == 3
    and .capture_decisions == ["captured", "captured_degraded", "fail_closed"]
    and .truth_states == ["confirmed", "degraded", "blocked", "contaminated"]
    and ([.required_snapshot_contracts[].name] | index("rch_queue_snapshot") != null)
    and ([.required_snapshot_contracts[].name] | index("rch_status_workers_jobs_snapshot") != null)
    and ([.required_stall_subject_fields[]] | index("stall_subject.progress_age_seconds") != null)
    and ([.required_stall_subject_fields[]] | index("stall_subject.heartbeat.phase") != null)
    and ([.fail_closed_rules[]] | index("local fallback observed forces contaminated fail closed truth") != null)
  ' "$contract_path" >/dev/null || record_fail "contract shape mismatch"

  while IFS= read -r required_text; do
    grep -Fq "$required_text" "$docs_path" \
      || record_fail "doc missing required text: ${required_text}"
  done < <(jq -r '.required_doc_text[]' "$contract_path")

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"

  record_pass "check"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "${tmp_root:-}"' RETURN

  write_bundle "${tmp_root}/confirmed.json" confirmed
  assert_bundle_valid "${tmp_root}/confirmed.json" "confirmed"

  write_bundle "${tmp_root}/degraded.json" degraded_missing_optional
  assert_bundle_valid "${tmp_root}/degraded.json" "degraded_missing_optional"

  write_bundle "${tmp_root}/blocked.json" blocked_contradictory_queue
  assert_bundle_valid "${tmp_root}/blocked.json" "blocked_contradictory_queue"

  write_bundle "${tmp_root}/contaminated.json" contaminated_local_fallback
  assert_bundle_valid "${tmp_root}/contaminated.json" "contaminated_local_fallback"

  jq 'del(.stall_subject.build_id)' \
    "${tmp_root}/confirmed.json" >"${tmp_root}/missing_required_field.json"
  if validate_bundle_against_contract "${tmp_root}/missing_required_field.json"; then
    record_fail "missing required stall subject field unexpectedly passed"
  fi

  record_pass "selftest"
}

validate_bundle_mode() {
  local path="$1"
  [[ -n "$path" && -f "$path" ]] || record_fail "missing bundle path"
  jq empty "$path" >/dev/null
  assert_bundle_valid "$path" "validate-bundle"
  record_pass "validate-bundle"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  validate-bundle)
    run_check
    validate_bundle_mode "$bundle_path"
    ;;
  *)
    printf 'usage: %s [check|selftest|validate-bundle FILE]\n' "${0##*/}" >&2
    exit 64
    ;;
esac
