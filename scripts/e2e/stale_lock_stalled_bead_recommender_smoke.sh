#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
recommender="${root_dir}/scripts/stale_lock_stalled_bead_recommender.sh"
docs_path="${root_dir}/docs/STALE_LOCK_STALLED_BEAD_RECOMMENDER.md"
golden_dir="${STALE_LOCK_RECOMMENDER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS stale-lock-stalled-bead-recommender %s\n' "$1"
}

record_failure() {
  printf 'FAIL stale-lock-stalled-bead-recommender %s\n' "$1" >&2
}

golden_case_names() {
  cat <<'EOF'
active-owner
stale-owner-no-reservations
stale-owner-recent-git-activity
missing-agent-mail-degraded-mode
high-priority-contact-first
EOF
}

write_empty_agent_mail() {
  local fixture_dir="$1"

  jq -n '{agents:[]}' >"${fixture_dir}/agents-empty.json"
  jq -n '{messages:[]}' >"${fixture_dir}/threads-empty.json"
  jq -n '{reservations:[]}' >"${fixture_dir}/reservations-empty.json"
  jq -n '{activity:[]}' >"${fixture_dir}/git-empty.json"
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_case_golden() {
  local case_name="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/stale_lock_stalled_bead_recommender_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local missing=0
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/stale_lock_stalled_bead_recommender_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      missing=1
      continue
    fi
    jq empty "$golden_path" >/dev/null || {
      record_failure "${case_name} invalid golden json"
      missing=1
    }
  done < <(golden_case_names)

  [[ "$missing" -eq 0 ]]
}

run_case() {
  local case_name="$1"
  local output_dir="$2"
  local tmp_root="$3"
  shift 3
  local output
  local exit_code

  set +e
  output="$("$recommender" --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne 0 ]]; then
    record_failure "${case_name} exit ${exit_code}, expected 0"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.stale-lock-recommendations.v1"
    and (.stale_lock_recommendations | type == "array")
    and (.safe_to_reopen | type == "array")
    and (.contact_first | type == "array")
    and (.evidence | type == "array")
    and (.artifact_paths.stale_lock_recommendations_json | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.report_md | length > 0)
  ' "${output_dir}/stale_lock_recommendations.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  assert_case_golden "$case_name" "${output_dir}/stale_lock_recommendations.json" "$tmp_root"
  record_pass "${case_name} produced recommendation packet"
}

assert_safe_ids() {
  local report="$1"
  shift
  local expected
  expected="$(printf '%s\n' "$@" | jq -R 'select(length > 0)' | jq -s 'sort')"
  jq -e --argjson expected "$expected" '(.safe_to_reopen | sort) == $expected' "$report" >/dev/null
}

assert_recommendation() {
  local report="$1"
  local bead_id="$2"
  local expected="$3"

  jq -e --arg bead_id "$bead_id" --arg expected "$expected" '
    any(.stale_lock_recommendations[]?;
      .bead_id == $bead_id and .recommendation == $expected
    )
  ' "$report" >/dev/null
}

run_check() {
  local scope_file

  bash -n "$recommender"
  bash -n "${BASH_SOURCE[0]}"
  test -f "$docs_path"
  goldens_shape_ok
  record_pass "bash syntax and docs exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/stale-lock-rch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/stale_lock_stalled_bead_recommender.sh" \
    "scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh" \
    "docs/STALE_LOCK_STALLED_BEAD_RECOMMENDER.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/stale-lock-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir now report

  run_check
  tmp_parent="${STALE_LOCK_RECOMMENDER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/stale-lock-recommender.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  now=100000
  mkdir -p "$fixture_dir"
  write_empty_agent_mail "$fixture_dir"

  jq -n '{issues:[{id:"bd-active", title:"active owner", priority:2, assignee:"ActiveAgent"}]}' >"${fixture_dir}/active-in-progress.json"
  jq -n '{agents:[{name:"ActiveAgent", last_active_epoch_seconds:99900}]}' >"${fixture_dir}/active-agents.json"
  run_case "active-owner" "${tmp_root}/active-owner" "$tmp_root" \
    --in-progress-json "${fixture_dir}/active-in-progress.json" \
    --agent-profiles-json "${fixture_dir}/active-agents.json" \
    --thread-timestamps-json "${fixture_dir}/threads-empty.json" \
    --file-reservations-json "${fixture_dir}/reservations-empty.json" \
    --git-activity-json "${fixture_dir}/git-empty.json" \
    --now-epoch-seconds "$now" \
    --stale-owner-seconds 1000
  report="${tmp_root}/active-owner/stale_lock_recommendations.json"
  assert_safe_ids "$report"
  assert_recommendation "$report" bd-active owner_active

  jq -n '{issues:[{id:"bd-stale", title:"stale owner", priority:2, assignee:"OldAgent"}]}' >"${fixture_dir}/stale-in-progress.json"
  jq -n '{agents:[{name:"OldAgent", last_active_epoch_seconds:80000}]}' >"${fixture_dir}/stale-agents.json"
  run_case "stale-owner-no-reservations" "${tmp_root}/stale-owner" "$tmp_root" \
    --in-progress-json "${fixture_dir}/stale-in-progress.json" \
    --agent-profiles-json "${fixture_dir}/stale-agents.json" \
    --thread-timestamps-json "${fixture_dir}/threads-empty.json" \
    --file-reservations-json "${fixture_dir}/reservations-empty.json" \
    --git-activity-json "${fixture_dir}/git-empty.json" \
    --now-epoch-seconds "$now" \
    --stale-owner-seconds 1000
  report="${tmp_root}/stale-owner/stale_lock_recommendations.json"
  assert_safe_ids "$report" bd-stale
  assert_recommendation "$report" bd-stale safe_to_reopen
  jq -e 'any(.stale_lock_recommendations[]?; .bead_id == "bd-stale" and (.suggested_br_commands[0] | contains("br update bd-stale --status open --assignee")))' "$report" >/dev/null

  jq -n '{issues:[{id:"bd-git", title:"recent git", priority:2, assignee:"OldGit"}]}' >"${fixture_dir}/git-in-progress.json"
  jq -n '{agents:[{name:"OldGit", last_active_epoch_seconds:80000}]}' >"${fixture_dir}/git-agents.json"
  jq -n '{activity:[{bead_id:"bd-git", agent_id:"OldGit", touched_epoch_seconds:99950, path:"scripts/owned-by-oldgit.sh"}]}' >"${fixture_dir}/git-recent.json"
  run_case "stale-owner-recent-git-activity" "${tmp_root}/recent-git" "$tmp_root" \
    --in-progress-json "${fixture_dir}/git-in-progress.json" \
    --agent-profiles-json "${fixture_dir}/git-agents.json" \
    --thread-timestamps-json "${fixture_dir}/threads-empty.json" \
    --file-reservations-json "${fixture_dir}/reservations-empty.json" \
    --git-activity-json "${fixture_dir}/git-recent.json" \
    --now-epoch-seconds "$now" \
    --stale-owner-seconds 1000
  report="${tmp_root}/recent-git/stale_lock_recommendations.json"
  assert_safe_ids "$report"
  assert_recommendation "$report" bd-git contact_first_recent_git_activity

  jq -n '{issues:[{id:"bd-degraded", title:"missing mail", priority:2, assignee:"MissingMail"}]}' >"${fixture_dir}/degraded-in-progress.json"
  run_case "missing-agent-mail-degraded-mode" "${tmp_root}/degraded" "$tmp_root" \
    --in-progress-json "${fixture_dir}/degraded-in-progress.json" \
    --now-epoch-seconds "$now" \
    --stale-owner-seconds 1000
  report="${tmp_root}/degraded/stale_lock_recommendations.json"
  assert_safe_ids "$report"
  assert_recommendation "$report" bd-degraded manual_confirmation_required
  jq -e 'any(.evidence[]?; .bead_id == "bd-degraded" and (.evidence.degraded_reasons | length) > 0)' "$report" >/dev/null

  jq -n '{issues:[{id:"bd-p1", title:"high priority", priority:1, assignee:"OldP1"}]}' >"${fixture_dir}/p1-in-progress.json"
  jq -n '{agents:[{name:"OldP1", last_active_epoch_seconds:80000}]}' >"${fixture_dir}/p1-agents.json"
  run_case "high-priority-contact-first" "${tmp_root}/high-priority" "$tmp_root" \
    --in-progress-json "${fixture_dir}/p1-in-progress.json" \
    --agent-profiles-json "${fixture_dir}/p1-agents.json" \
    --thread-timestamps-json "${fixture_dir}/threads-empty.json" \
    --file-reservations-json "${fixture_dir}/reservations-empty.json" \
    --git-activity-json "${fixture_dir}/git-empty.json" \
    --now-epoch-seconds "$now" \
    --stale-owner-seconds 1000
  report="${tmp_root}/high-priority/stale_lock_recommendations.json"
  assert_safe_ids "$report"
  assert_recommendation "$report" bd-p1 contact_first_high_priority

  printf 'stale_lock_recommender_smoke_artifacts=%s\n' "$tmp_root"
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
