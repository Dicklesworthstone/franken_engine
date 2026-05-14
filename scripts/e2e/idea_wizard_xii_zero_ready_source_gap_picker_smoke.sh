#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
picker="${root_dir}/scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xii-source-gap-picker %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xii-source-gap-picker %s\n' "$1" >&2
  exit 1
}

canonicalize_report() {
  local report_path="$1"
  jq '
    del(.artifact_paths)
    | del(.proposed_beads[].closed_bead_matches[].updated_at)
    | del(.proposed_beads[].closed_bead_matches[].closed_at)
    | del(.suppressed_candidates[].closed_bead_matches[].updated_at)
    | del(.suppressed_candidates[].closed_bead_matches[].closed_at)
  ' "$report_path"
}

compare_golden() {
  local case_id="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_id}"
    return
  fi

  [[ -f "$golden_path" ]] || record_failure "missing golden ${golden_path}"
  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_id}; set UPDATE_GOLDENS=1 only after reviewing the diff"
  fi
  record_pass "golden matches ${case_id}"
}

write_common_closed_beads() {
  local closed_json="$1"
  cat >"$closed_json" <<'JSON'
[
  {
    "id": "bd-zlvz8",
    "title": "[MOCK] CRITICAL: Implement async/await pending promise execution",
    "status": "closed",
    "priority": 1,
    "assignee": "ClaudeAlpha",
    "updated_at": "2026-05-03T04:00:49Z",
    "closed_at": "2026-05-03T04:00:49Z",
    "close_reason": "Done in commit cafefeed. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p franken-core async_function_pending_await",
    "labels": ["async-await", "franken-core"],
    "dependencies": []
  },
  {
    "id": "bd-closed-duplicate",
    "title": "[SOURCE-GAP] Resolve TODO production marker in scripts/legacy_gap_fixture.sh",
    "status": "closed",
    "priority": 3,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-03T04:02:49Z",
    "closed_at": "2026-05-03T04:02:49Z",
    "close_reason": "Closed duplicate source marker for scripts/legacy_gap_fixture.sh TODO production readiness.",
    "labels": ["tests"],
    "dependencies": []
  }
]
JSON
}

write_common_closed_beads_jsonl() {
  local issues_jsonl="$1"
  cat >"$issues_jsonl" <<'JSONL'
{"id":"bd-zlvz8","title":"[MOCK] CRITICAL: Implement async/await pending promise execution","status":"closed","priority":1,"assignee":"ClaudeAlpha","updated_at":"2026-05-03T04:00:49Z","closed_at":"2026-05-03T04:00:49Z","close_reason":"Done in commit cafefeed. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p franken-core async_function_pending_await","labels":["async-await","franken-core"],"dependencies":[]}
{"id":"bd-closed-duplicate","title":"[SOURCE-GAP] Resolve TODO production marker in scripts/legacy_gap_fixture.sh","status":"closed","priority":3,"assignee":"RainyBadger","updated_at":"2026-05-03T04:02:49Z","closed_at":"2026-05-03T04:02:49Z","close_reason":"Closed duplicate source marker for scripts/legacy_gap_fixture.sh TODO production readiness.","labels":["tests"],"dependencies":[]}
JSONL
}

write_source_markers() {
  local marker_json="$1"
  cat >"$marker_json" <<'JSON'
[
  {
    "bead_id": "bd-zlvz8",
    "file": "crates/franken-core/src/baseline_interpreter.rs",
    "line": 5408,
    "marker": "pending promise requires full async scheduling (not yet implemented)",
    "marker_class": "unsupported_semantic_marker",
    "detail": "Closed bead claims pending async/await execution is implemented, but source still fails closed for pending promise scheduling.",
    "confidence": "high",
    "suggested_next_bead_title": "[IDEA-WIZARD-XII-C] Reopen real pending-promise await execution from source evidence"
  },
  {
    "bead_id": "bd-closed-duplicate",
    "file": "scripts/legacy_gap_fixture.sh",
    "line": 12,
    "marker": "TODO production readiness",
    "marker_class": "todo_marker",
    "detail": "Duplicate closed source marker should not produce another bead without a follow-up signal.",
    "confidence": "medium"
  },
  {
    "file": "tests/negative_fixture.rs",
    "line": 99,
    "marker": "not yet implemented",
    "marker_class": "negative_fixture_marker",
    "detail": "Negative fixture intentionally includes unsupported wording.",
    "confidence": "high",
    "negative_fixture": true
  }
]
JSON
}

run_zero_ready_case() {
  local tmpdir ready_json open_json issues_jsonl marker_json output_dir actual_golden status

  tmpdir="$(mktemp -d)"
  ready_json="${tmpdir}/br_ready.json"
  open_json="${tmpdir}/br_open.json"
  issues_jsonl="${tmpdir}/issues.jsonl"
  marker_json="${tmpdir}/source_markers.json"
  output_dir="${tmpdir}/out"

  printf '[]\n' >"$ready_json"
  printf '[]\n' >"$open_json"
  write_common_closed_beads_jsonl "$issues_jsonl"
  write_source_markers "$marker_json"

  set +e
  IDEA_WIZARD_XII_SOURCE_GAP_PICKER_GENERATED_AT_UTC="2026-05-14T07:00:00Z" \
    "$picker" \
    --br-ready-json "$ready_json" \
    --br-open-json "$open_json" \
    --issues-jsonl "$issues_jsonl" \
    --source-marker-json "$marker_json" \
    --source-revision "smoke-zero-ready" \
    --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected zero-ready exit ${status}"
  fi

  [[ -f "${output_dir}/zero_ready_source_gap_picker.json" ]] || record_failure "missing report"
  [[ -f "${output_dir}/proposed_beads.json" ]] || record_failure "missing proposed beads"
  [[ -f "${output_dir}/suppressed_candidates.json" ]] || record_failure "missing suppressed candidates"
  [[ -f "${output_dir}/br_commands.sh" ]] || record_failure "missing br commands"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown report"
  [[ -f "${output_dir}/trace_ids.json" ]] || record_failure "missing trace ids"

  jq -e '
    .decision == "proposals_emitted"
    and .classification == "source_gap_candidates"
    and .ready_count == 0
    and .open_count == 0
    and .source_marker_count == 2
    and .proposal_count == 1
    and .suppressed_count == 1
    and .duplicate_suppressed_count == 1
    and .mutation_policy.creates_beads == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "${output_dir}/zero_ready_source_gap_picker.json" >/dev/null \
    || record_failure "zero-ready report summary mismatch"
  jq -e '
    .[0].title == "[IDEA-WIZARD-XII-C] Reopen real pending-promise await execution from source evidence"
    and .[0].priority == 1
    and .[0].file == "crates/franken-core/src/baseline_interpreter.rs"
    and .[0].under_60_minute_estimate == true
    and (.[0].closed_bead_matches | map(.id) | index("bd-zlvz8"))
    and (.[0].body_md | contains("pending promise requires full async scheduling"))
    and (.[0].validation_scope | contains("rch exec -- env CARGO_TARGET_DIR="))
  ' "${output_dir}/proposed_beads.json" >/dev/null \
    || record_failure "proposed bead payload mismatch"
  jq -e '
    .[0].suppression_reason == "duplicate_closed_bead_without_followup_signal"
    and .[0].file == "scripts/legacy_gap_fixture.sh"
  ' "${output_dir}/suppressed_candidates.json" >/dev/null \
    || record_failure "suppressed duplicate payload mismatch"
  grep -Fq 'br create' "${output_dir}/br_commands.sh" \
    || record_failure "missing br create transcript"
  jq -e 'select(.event == "source_gap_candidate_proposed")' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "missing proposal event"

  actual_golden="${tmpdir}/zero-ready.actual.golden"
  canonicalize_report "${output_dir}/zero_ready_source_gap_picker.json" >"$actual_golden"
  compare_golden \
    "zero-ready" \
    "$actual_golden" \
    "${golden_dir}/idea_wizard_xii_zero_ready_source_gap_picker.golden"

  record_pass "zero-ready"
}

run_nonzero_queue_case() {
  local tmpdir ready_json open_json closed_json marker_json output_dir status

  tmpdir="$(mktemp -d)"
  ready_json="${tmpdir}/br_ready.json"
  open_json="${tmpdir}/br_open.json"
  closed_json="${tmpdir}/closed_beads.json"
  marker_json="${tmpdir}/source_markers.json"
  output_dir="${tmpdir}/out"

  printf '[{"id":"bd-open","title":"Open work","status":"open"}]\n' >"$ready_json"
  printf '[{"id":"bd-open","title":"Open work","status":"open"}]\n' >"$open_json"
  write_common_closed_beads "$closed_json"
  write_source_markers "$marker_json"

  set +e
  IDEA_WIZARD_XII_SOURCE_GAP_PICKER_GENERATED_AT_UTC="2026-05-14T07:00:00Z" \
    "$picker" \
    --br-ready-json "$ready_json" \
    --br-open-json "$open_json" \
    --closed-beads-json "$closed_json" \
    --source-marker-json "$marker_json" \
    --source-revision "smoke-nonzero" \
    --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne 42 ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected nonzero queue exit ${status}"
  fi
  jq -e '.decision == "not_zero_ready" and .proposal_count == 0 and .suppressed_count == 2' "${output_dir}/zero_ready_source_gap_picker.json" >/dev/null \
    || record_failure "nonzero queue report mismatch"
  jq -e 'all(.[]; .suppression_reason == "nonzero_ready_or_open_queue")' "${output_dir}/suppressed_candidates.json" >/dev/null \
    || record_failure "nonzero queue suppression mismatch"
  record_pass "nonzero-queue"
}

run_check() {
  bash -n "$picker" "${BASH_SOURCE[0]}"
  run_zero_ready_case
  run_nonzero_queue_case
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_XII_ZERO_READY_SOURCE_GAP_PICKER.md \
    scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh \
    scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh \
    scripts/testdata/goldens/idea_wizard_xii_zero_ready_source_gap_picker.golden
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
