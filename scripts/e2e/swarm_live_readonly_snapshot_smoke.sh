#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle_script="${root_dir}/scripts/swarm_live_readonly_snapshot_bundle.sh"
bundle_smoke="${root_dir}/scripts/e2e/swarm_live_readonly_snapshot_bundle_smoke.sh"
fixtures_path="${SWARM_LIVE_READONLY_SNAPSHOT_FIXTURES:-${root_dir}/scripts/testdata/swarm_live_readonly_snapshot/cases.json}"
golden_dir="${root_dir}/scripts/testdata/goldens"
mode="${1:-check}"
output_dir="${2:-${SWARM_LIVE_READONLY_SNAPSHOT_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  healthy
  missing_optional_sources
  stale_required_live_state
  malformed_required_rch_status
  rch_local_fallback_marker
  mutating_proof_transcript
)

record_pass() {
  printf 'PASS swarm-live-readonly-snapshot-goldens %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-live-readonly-snapshot-goldens %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_live_readonly_snapshot_smoke.sh [check|selftest] [output_dir]
EOF
}

golden_path_for() {
  local case_id="$1"
  printf '%s/swarm_live_readonly_snapshot_%s.golden' "$golden_dir" "$case_id"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-live-readonly-snapshot-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "healthy",
      "malformed_required_rch_status",
      "missing_optional_sources",
      "mutating_proof_transcript",
      "rch_local_fallback_marker",
      "stale_required_live_state"
    ] | sort)
    and any(.cases[]; .case_id == "healthy" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "missing_optional_sources" and .expected.decision == "degraded")
    and any(.cases[]; .case_id == "stale_required_live_state" and (.expected.fail_closed_reasons | index("stale_required_source") != null))
    and any(.cases[]; .case_id == "malformed_required_rch_status" and (.expected.fail_closed_reasons | index("malformed_source") != null))
    and any(.cases[]; .case_id == "rch_local_fallback_marker" and (.expected.fail_closed_reasons | index("local_rch_fallback_marker") != null))
    and any(.cases[]; .case_id == "mutating_proof_transcript" and (.expected.fail_closed_reasons | index("mutating_command_observed") != null))
  ' "$fixtures_path" >/dev/null
}

canonicalize_json() {
  local path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
        | if has("run_id") then .run_id = "[RUN_ID]" else . end
        | if has("trace_id") and (.trace_id | type == "string") and (.trace_id | startswith("trace-swarm-live-readonly-")) then
            .trace_id = "trace-swarm-live-readonly-[RUN_ID]"
          else
            .
          end
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | if test("^sha256:[0-9a-f]{64}$") then
            "sha256:[SHA256]"
          elif test("^[0-9a-f]{64}$") then
            "[SHA256]"
          else
            .
          end
      else
        .
      end;
    scrub
  ' "$path" | jq -S .
}

canonicalize_jsonl() {
  local path="$1"
  local tmp_root="$2"

  jq -s '.' "$path" | jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
        | if has("run_id") then .run_id = "[RUN_ID]" else . end
        | if has("trace_id") and (.trace_id | type == "string") and (.trace_id | startswith("trace-swarm-live-readonly-")) then
            .trace_id = "trace-swarm-live-readonly-[RUN_ID]"
          else
            .
          end
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | if test("^sha256:[0-9a-f]{64}$") then
            "sha256:[SHA256]"
          elif test("^[0-9a-f]{64}$") then
            "[SHA256]"
          else
            .
          end
      else
        .
      end;
    scrub
  ' | jq -S .
}

canonicalize_text() {
  local path="$1"
  local tmp_root="$2"

  sed "s#${tmp_root}#[SMOKE_ROOT]#g" "$path" \
    | sed -E 's/(command_hash=)[0-9a-f]{64}/\1[SHA256]/g' \
    | sed -E 's/(payload_hash=)[0-9a-f]{64}/\1[SHA256]/g' \
    | sed -E 's/(redacted_payload_hash=)[0-9a-f]{64}/\1[SHA256]/g'
}

write_case_golden() {
  local tmp_root="$1"
  local case_id="$2"
  local run_dir="$3"
  local actual_path="$4"

  {
    printf '=== CASE ===\n%s\n' "$case_id"
    printf '=== SNAPSHOT ===\n'
    canonicalize_json "${run_dir}/snapshot.json" "$tmp_root"
    printf '=== REDACTION REPORT ===\n'
    canonicalize_json "${run_dir}/redaction_report.json" "$tmp_root"
    printf '=== EVENTS ===\n'
    canonicalize_jsonl "${run_dir}/events.jsonl" "$tmp_root"
    printf '=== COMMANDS ===\n'
    canonicalize_text "${run_dir}/commands.txt" "$tmp_root"
    printf '=== REPORT ===\n'
    canonicalize_text "${run_dir}/report.md" "$tmp_root"
  } >"$actual_path"
}

compare_case_golden() {
  local case_id="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_id}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_id}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_id}"
}

assert_artifacts_present() {
  local case_id="$1"
  local run_dir="$2"
  local artifact

  for artifact in snapshot.json redaction_report.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${run_dir}/${artifact}" ]]; then
      record_failure "${case_id} missing ${artifact}"
    fi
  done
}

assert_mutation_fixture_fail_closed() {
  local snapshot_path="$1"
  local report_path="$2"

  jq -e '
    .decision == "fail_closed"
    and (.fail_closed_reasons | index("mutating_command_observed") != null)
    and any(.sources[]; .component == "proof_transcript"
      and .trust_state == "fail_closed"
      and .error_code == "FE-SWARM-LIVE-MUTATING-COMMAND"
      and .mutating_command_observed == true)
  ' "$snapshot_path" >/dev/null || {
    record_failure "mutating proof transcript did not fail closed with source diagnostics"
    return
  }

  grep -Fq 'fail closed reasons: mutating_command_observed' "$report_path" \
    || record_failure "mutating proof transcript report omitted fail-closed reason"
}

assert_no_dynamic_golden_values() {
  local golden_path="$1"

  if grep -Eq '/data/projects|/home/ubuntu|/tmp/' "$golden_path"; then
    record_failure "${golden_path#"$root_dir"/} contains host path"
  fi
  if grep -Fq 'secret-token-value' "$golden_path"; then
    record_failure "${golden_path#"$root_dir"/} contains unredacted Agent Mail secret"
  fi
}

assert_golden_sections() {
  local golden_path="$1"

  if ! {
    grep -Fq '=== CASE ===' "$golden_path" \
      && grep -Fq '=== SNAPSHOT ===' "$golden_path" \
      && grep -Fq '=== REDACTION REPORT ===' "$golden_path" \
      && grep -Fq '=== EVENTS ===' "$golden_path" \
      && grep -Fq '=== COMMANDS ===' "$golden_path" \
      && grep -Fq '=== REPORT ===' "$golden_path"
  }; then
    record_failure "${golden_path#"$root_dir"/} missing expected golden sections"
  fi
}

run_check() {
  bash -n "$bundle_script" "$bundle_smoke" "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  local case_id golden_path
  for case_id in "${case_ids[@]}"; do
    golden_path="$(golden_path_for "$case_id")"
    if [[ -f "$golden_path" ]]; then
      assert_golden_sections "$golden_path"
      assert_no_dynamic_golden_values "$golden_path"
    elif [[ "${UPDATE_GOLDENS:-0}" != "1" ]]; then
      record_failure "missing golden ${golden_path}"
    fi
  done
}

run_selftest() {
  local tmp_parent tmp_root cases_root case_id run_dir actual_path golden_path

  tmp_parent="${SWARM_LIVE_READONLY_SNAPSHOT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-live-readonly-snapshot-goldens.XXXXXX")"
  cases_root="${tmp_root}/cases"

  "$bundle_smoke" run "$cases_root"

  for case_id in "${case_ids[@]}"; do
    run_dir="${cases_root}/${case_id}/out"
    actual_path="${tmp_root}/${case_id}.actual.golden"
    golden_path="$(golden_path_for "$case_id")"
    assert_artifacts_present "$case_id" "$run_dir"
    write_case_golden "$tmp_root" "$case_id" "$run_dir" "$actual_path"
    compare_case_golden "$case_id" "$actual_path" "$golden_path"
  done

  assert_mutation_fixture_fail_closed \
    "${cases_root}/mutating_proof_transcript/out/snapshot.json" \
    "${cases_root}/mutating_proof_transcript/out/report.md"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -n "$output_dir" ]]; then
        SWARM_LIVE_READONLY_SNAPSHOT_ARTIFACT_ROOT="$output_dir" run_selftest
      else
        run_selftest
      fi
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
