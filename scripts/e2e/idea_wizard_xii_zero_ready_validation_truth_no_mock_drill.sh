#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${ZERO_READY_VALIDATION_TRUTH_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iwxii-zero-ready-validation-truth-drill}"
run_id="${ZERO_READY_VALIDATION_TRUTH_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${ZERO_READY_VALIDATION_TRUTH_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${ZERO_READY_VALIDATION_TRUTH_DRILL_SOURCE_REVISION:-}"
generated_at_utc="${ZERO_READY_VALIDATION_TRUTH_DRILL_GENERATED_AT_UTC:-2026-05-14T00:00:00Z}"
mode="${1:-fixture}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

rch_gate="${root_dir}/scripts/rch_policy_compliance_gate.sh"
closed_proof="${root_dir}/scripts/idea_wizard_iv_closed_bead_proof_integrity.sh"
source_gap_picker="${root_dir}/scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh"
operator_gate="${root_dir}/scripts/idea_wizard_iv_operator_status_truth_gate.sh"
doc_path="${root_dir}/docs/IDEA_WIZARD_XII_ZERO_READY_VALIDATION_TRUTH_NO_MOCK_DRILL.md"
smoke_path="${root_dir}/scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh"
golden_path="${root_dir}/scripts/testdata/goldens/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.golden"

replay_run_dir=""
latest_from=""

manifest_path=""
events_path=""
commands_path=""
report_path=""
source_inputs_path=""
operator_summary_path=""
fixtures_dir=""
steps_dir=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.sh [fixture|replay|check|selftest] [OPTIONS]

Options:
  --output-dir DIR
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --replay-run-dir DIR
  --latest-from DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-at-utc)
      generated_at_utc="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for zero-ready validation truth drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  manifest_path="${run_dir}/run_manifest.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_path="${run_dir}/zero_ready_validation_truth_no_mock_drill_report.json"
  source_inputs_path="${run_dir}/source_inputs.json"
  operator_summary_path="${run_dir}/operator_summary.md"
  fixtures_dir="${run_dir}/source_inputs"
  steps_dir="${run_dir}/steps"
}

record_pass() {
  printf 'PASS zero-ready-validation-truth-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL zero-ready-validation-truth-no-mock-drill %s\n' "$1" >&2
}

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-validation-truth-drill.event.v1" \
    --arg component "$1" \
    --arg event_name "$2" \
    --arg outcome "$3" \
    --arg artifact_path "$4" \
    '{schema_version:$schema_version,component:$component,event_name:$event_name,outcome:$outcome,artifact_path:$artifact_path}' \
    >>"$events_path"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  for artifact_path in "$manifest_path" "$events_path" "$commands_path" "$report_path" "$source_inputs_path" "$operator_summary_path"; do
    if [[ -e "$artifact_path" ]]; then
      printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
      exit 73
    fi
  done
  mkdir -p "$fixtures_dir" "$steps_dir"
  : >"$events_path"
  : >"$commands_path"
  write_event "drill" "started" "running" "$run_dir"
}

run_logged_step() {
  local component="$1"
  local expected_codes="$2"
  shift 2
  local step_dir="${steps_dir}/${component}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code expected
  mkdir -p "$step_dir"
  log_command "$@"
  write_event "$component" "started" "running" "$step_dir"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  IFS=',' read -r -a expected_list <<<"$expected_codes"
  for expected in "${expected_list[@]}"; do
    if [[ "$exit_code" == "$expected" ]]; then
      write_event "$component" "finished" "pass" "$step_dir"
      return 0
    fi
  done
  write_event "$component" "finished" "fail" "$stderr_path"
  printf 'component %s expected exit %s, got %s\n' "$component" "$expected_codes" "$exit_code" >&2
  cat "$stderr_path" >&2
  return 1
}

write_fixtures() {
  mkdir -p \
    "${fixtures_dir}/policy" \
    "${fixtures_dir}/tracker" \
    "${fixtures_dir}/source_markers" \
    "${fixtures_dir}/operator"

  cat >"${fixtures_dir}/policy/trusted-wrapper.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_zero_ready_validation_truth}"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

run_step() {
  local command_text="$1"
  shift
  printf '==> %s\n' "$command_text"
  run_rch "$@"
}

run_step "cargo check -p frankenengine-engine --all-targets" \
  cargo check -p frankenengine-engine --all-targets
run_step "cargo test -p frankenengine-engine --test promise_pending_state" \
  cargo test -p frankenengine-engine --test promise_pending_state

if grep -q "falling back to local" "${log_path:-/dev/null}"; then # reject local fallback
  echo "refusing local fallback"
  exit 1
fi
SH

  cat >"${fixtures_dir}/policy/bare-cargo.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cargo test -p frankenengine-engine --lib
SH

  cat >"${fixtures_dir}/tracker/issues.jsonl" <<'JSONL'
{"id":"bd-zlvz8","title":"[MOCK] CRITICAL: Implement async/await pending promise execution","status":"closed","priority":1,"assignee":"ClaudeAlpha","updated_at":"2026-05-03T04:00:49Z","closed_at":"2026-05-03T04:00:49Z","close_reason":"Done in commit cafefeed. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test --manifest-path crates/franken-core/Cargo.toml async_function_pending_await","labels":["async-await","franken-core"],"dependencies":[]}
JSONL

  printf '[]\n' >"${fixtures_dir}/tracker/br_ready_empty.json"
  printf '[]\n' >"${fixtures_dir}/tracker/br_open_empty.json"

  cat >"${fixtures_dir}/tracker/git_log.json" <<'JSON'
[
  {"commit": "cafefeeddeadbeef", "subject": "Implement bd-zlvz8 async await pending promise scheduling"}
]
JSON

  cat >"${fixtures_dir}/source_markers/pending_promise_markers.json" <<'JSON'
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
  }
]
JSON

  printf '[]\n' >"${fixtures_dir}/source_markers/clean_markers.json"

  cat >"${fixtures_dir}/operator/saturation_report.json" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1",
  "decision": "green",
  "classification": "true_saturation",
  "br_ready_count": 0,
  "child_reports": [
    {"surface_id": "closed_bead_proof_integrity", "decision": "green"},
    {"surface_id": "coordination_health_packet", "decision": "green"},
    {"surface_id": "validation_impact_plan", "decision": "green"},
    {"surface_id": "resource_proof_heatmap", "decision": "green"}
  ]
}
JSON

  cat >"${fixtures_dir}/operator/operator.md" <<'EOF'
The IW4/IWXII zero-ready control plane is advisory and proof-only. Green status
requires the required artifacts from the replay bundle and child reports. Heavy
validation is RCH-backed with `rch exec -- env CARGO_TARGET_DIR=`. Degraded
coordination and Agent Mail degraded states are limitations; this gate does not
repair Agent Mail, mutate beads, or claim repository completion.
EOF
}

write_source_inputs_manifest() {
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-validation-truth-drill.source-inputs.v1" \
    --arg trusted_wrapper "${fixtures_dir}/policy/trusted-wrapper.sh" \
    --arg bare_cargo "${fixtures_dir}/policy/bare-cargo.sh" \
    --arg issues_jsonl "${fixtures_dir}/tracker/issues.jsonl" \
    --arg br_ready_json "${fixtures_dir}/tracker/br_ready_empty.json" \
    --arg br_open_json "${fixtures_dir}/tracker/br_open_empty.json" \
    --arg git_log_json "${fixtures_dir}/tracker/git_log.json" \
    --arg pending_markers "${fixtures_dir}/source_markers/pending_promise_markers.json" \
    --arg clean_markers "${fixtures_dir}/source_markers/clean_markers.json" \
    --arg saturation_report "${fixtures_dir}/operator/saturation_report.json" \
    --arg operator_doc "${fixtures_dir}/operator/operator.md" \
    '{
      schema_version:$schema_version,
      source_inputs:{
        trusted_rch_wrapper_script:$trusted_wrapper,
        bare_cargo_script:$bare_cargo,
        issues_jsonl:$issues_jsonl,
        br_ready_json:$br_ready_json,
        br_open_json:$br_open_json,
        git_log_json:$git_log_json,
        pending_promise_source_markers_json:$pending_markers,
        clean_source_markers_json:$clean_markers,
        saturation_report_json:$saturation_report,
        operator_doc:$operator_doc
      }
    }' >"$source_inputs_path"
}

write_report() {
  local trusted_report="${steps_dir}/rch-trusted/out/diagnostics.json"
  local bare_report="${steps_dir}/rch-bare/out/diagnostics.json"
  local semantic_proof="${steps_dir}/closed-semantic/out/closed_bead_proof_integrity.json"
  local clean_proof="${steps_dir}/closed-clean/out/closed_bead_proof_integrity.json"
  local source_gap_report="${steps_dir}/source-gap/out/zero_ready_source_gap_picker.json"
  local clean_gap_report="${steps_dir}/source-gap-clean/out/zero_ready_source_gap_picker.json"
  local operator_gap_report="${steps_dir}/operator-source-gap/out/operator_truth_gate_report.json"
  local operator_clean_report="${steps_dir}/operator-clean/out/operator_truth_gate_report.json"
  local closed_commands="${steps_dir}/closed-semantic/out/commands.txt"
  local source_gap_commands="${steps_dir}/source-gap/out/commands.txt"

  cp "${steps_dir}/operator-source-gap/out/operator_status.md" "$operator_summary_path"

  # shellcheck disable=SC2094 # report_path is passed as metadata and is not read by jq.
  jq -n \
    --slurpfile trusted "$trusted_report" \
    --slurpfile bare "$bare_report" \
    --slurpfile semantic "$semantic_proof" \
    --slurpfile clean_proof "$clean_proof" \
    --slurpfile gap "$source_gap_report" \
    --slurpfile clean_gap "$clean_gap_report" \
    --slurpfile operator_gap "$operator_gap_report" \
    --slurpfile operator_clean "$operator_clean_report" \
    --rawfile command_transcript "$commands_path" \
    --rawfile closed_commands "$closed_commands" \
    --rawfile source_gap_commands "$source_gap_commands" \
    --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-validation-truth-no-mock-drill.v1" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg report_path "$report_path" \
    --arg manifest_path "$manifest_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg source_inputs_path "$source_inputs_path" \
    --arg operator_summary_path "$operator_summary_path" '
      ($trusted[0]) as $trusted_doc
      | ($bare[0]) as $bare_doc
      | ($semantic[0]) as $semantic_doc
      | ($clean_proof[0]) as $clean_proof_doc
      | ($gap[0]) as $gap_doc
      | ($clean_gap[0]) as $clean_gap_doc
      | ($operator_gap[0]) as $operator_gap_doc
      | ($operator_clean[0]) as $operator_clean_doc
      | ($trusted_doc.status == "pass" and ($trusted_doc.violation_count // 1) == 0) as $trusted_wrapper_passed
      | ($bare_doc.status == "fail" and any($bare_doc.violations[]?; .kind == "bare_cargo")) as $bare_cargo_failed
      | (($semantic_doc.classification // "") == "semantic_contradiction" and (($semantic_doc.semantic_contradiction_count // 0) | tonumber) == 1) as $semantic_contradiction_reported
      | (($gap_doc.decision // "") == "proposals_emitted" and (($gap_doc.proposal_count // 0) | tonumber) == 1) as $source_gap_recommended
      | (($operator_gap_doc.zero_ready_truth.state // "") == "source_gap_found") as $operator_source_gap_found
      | (($operator_clean_doc.zero_ready_truth.state // "") == "true_saturation" and ($operator_clean_doc.decision // "") == "green") as $clean_zero_ready_green
      | (($command_transcript | test("(^|\\n)[^\\n]*\\bcargo\\s+(check|test|clippy|build|bench|run)(\\s|$)")) | not) as $no_local_heavy_cargo_executed
      | ((($closed_commands | contains("rch exec -- env CARGO_TARGET_DIR="))
          and (all($gap_doc.proposed_beads[]?.validation_scope; contains("rch exec -- env CARGO_TARGET_DIR=") or startswith("bash ")))
          and (($source_gap_commands | contains("advisory-only")) or ($source_gap_commands | contains("Review br_commands.sh"))))) as $suggested_heavy_commands_rch_wrapped
      | {
          schema_version:$schema_version,
          source_revision:$source_revision,
          decision:(if (
            $trusted_wrapper_passed
            and $bare_cargo_failed
            and $semantic_contradiction_reported
            and $source_gap_recommended
            and $operator_source_gap_found
            and $clean_zero_ready_green
            and $no_local_heavy_cargo_executed
            and $suggested_heavy_commands_rch_wrapped
          ) then "pass" else "fail" end),
          checks:{
            rch_policy:{
              trusted_wrapper_status:$trusted_doc.status,
              trusted_wrapper_violation_count:($trusted_doc.violation_count // 0),
              bare_cargo_status:$bare_doc.status,
              bare_cargo_violation_kinds:([$bare_doc.violations[]?.kind] | unique)
            },
            closed_bead_proof:{
              semantic_decision:$semantic_doc.decision,
              semantic_classification:$semantic_doc.classification,
              semantic_contradiction_count:($semantic_doc.semantic_contradiction_count // 0),
              semantic_reason_codes:([$semantic_doc.degraded_reasons[]?.reason_codes[]?] | unique),
              clean_decision:$clean_proof_doc.decision,
              clean_classification:$clean_proof_doc.classification
            },
            source_gap_picker:{
              decision:$gap_doc.decision,
              classification:$gap_doc.classification,
              proposal_count:($gap_doc.proposal_count // 0),
              proposed_titles:[$gap_doc.proposed_beads[]?.title],
              clean_decision:$clean_gap_doc.decision,
              clean_classification:$clean_gap_doc.classification
            },
            operator_handoff:{
              source_gap_decision:$operator_gap_doc.decision,
              source_gap_state:$operator_gap_doc.zero_ready_truth.state,
              source_gap_reason_codes:$operator_gap_doc.zero_ready_truth.reason_codes,
              clean_decision:$operator_clean_doc.decision,
              clean_state:$operator_clean_doc.zero_ready_truth.state
            }
          },
          assertion_results:{
            trusted_rch_wrapper_passed:$trusted_wrapper_passed,
            true_bare_cargo_failed:$bare_cargo_failed,
            pending_promise_contradiction_reported:$semantic_contradiction_reported,
            source_gap_picker_recommended_followup:$source_gap_recommended,
            operator_handoff_rendered_source_gap:$operator_source_gap_found,
            clean_zero_ready_remained_green:$clean_zero_ready_green,
            no_local_heavy_cargo_executed:$no_local_heavy_cargo_executed,
            suggested_heavy_commands_rch_wrapped:$suggested_heavy_commands_rch_wrapped
          },
          mutation_policy:{
            advisory_only:true,
            proof_only:true,
            mutates_br:false,
            sends_agent_mail:false,
            repairs_agent_mail_db:false,
            runs_cargo:false,
            runs_rch:false,
            mutates_git:false,
            queries_live_workers:false,
            mutates_live_workers:false
          },
          artifact_paths:{
            run_dir:$run_dir,
            report_json:$report_path,
            run_manifest_json:$manifest_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            source_inputs_json:$source_inputs_path,
            operator_summary_md:$operator_summary_path
          }
        }
    ' >"$report_path"

  jq -e '.decision == "pass" and ([.assertion_results[]] | all)' "$report_path" >/dev/null || {
    jq . "$report_path" >&2
    return 1
  }
}

write_run_manifest() {
  jq -n \
    --slurpfile source_inputs "$source_inputs_path" \
    --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-validation-truth-no-mock-drill.run-manifest.v1" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg report_path "$report_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg operator_summary_path "$operator_summary_path" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      run_dir:$run_dir,
      source_inputs:($source_inputs[0].source_inputs // {}),
      artifacts:{
        report_json:$report_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        operator_summary_md:$operator_summary_path
      },
      composed_scripts:[
        "scripts/rch_policy_compliance_gate.sh",
        "scripts/idea_wizard_iv_closed_bead_proof_integrity.sh",
        "scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh",
        "scripts/idea_wizard_iv_operator_status_truth_gate.sh"
      ],
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        mutates_br:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_git:false
      }
    }' >"$manifest_path"
}

run_fixture() {
  ensure_run_dir
  write_fixtures
  write_source_inputs_manifest

  run_logged_step "rch-trusted" "0" \
    "$rch_gate" \
    --output-dir "${steps_dir}/rch-trusted/out" \
    "${fixtures_dir}/policy/trusted-wrapper.sh"

  run_logged_step "rch-bare" "42" \
    "$rch_gate" \
    --output-dir "${steps_dir}/rch-bare/out" \
    "${fixtures_dir}/policy/bare-cargo.sh"

  run_logged_step "closed-semantic" "0" \
    "$closed_proof" \
    --issues-jsonl "${fixtures_dir}/tracker/issues.jsonl" \
    --git-log-json "${fixtures_dir}/tracker/git_log.json" \
    --source-marker-json "${fixtures_dir}/source_markers/pending_promise_markers.json" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/closed-semantic/out"

  run_logged_step "closed-clean" "0" \
    "$closed_proof" \
    --issues-jsonl "${fixtures_dir}/tracker/issues.jsonl" \
    --git-log-json "${fixtures_dir}/tracker/git_log.json" \
    --source-marker-json "${fixtures_dir}/source_markers/clean_markers.json" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/closed-clean/out"

  run_logged_step "source-gap" "0" \
    "$source_gap_picker" \
    --br-ready-json "${fixtures_dir}/tracker/br_ready_empty.json" \
    --br-open-json "${fixtures_dir}/tracker/br_open_empty.json" \
    --issues-jsonl "${fixtures_dir}/tracker/issues.jsonl" \
    --source-marker-json "${fixtures_dir}/source_markers/pending_promise_markers.json" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/source-gap/out"

  run_logged_step "source-gap-clean" "0" \
    "$source_gap_picker" \
    --br-ready-json "${fixtures_dir}/tracker/br_ready_empty.json" \
    --br-open-json "${fixtures_dir}/tracker/br_open_empty.json" \
    --issues-jsonl "${fixtures_dir}/tracker/issues.jsonl" \
    --source-marker-json "${fixtures_dir}/source_markers/clean_markers.json" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/source-gap-clean/out"

  run_logged_step "operator-source-gap" "0" \
    "$operator_gate" \
    --saturation-report-json "${fixtures_dir}/operator/saturation_report.json" \
    --closed-bead-proof-json "${steps_dir}/closed-semantic/out/closed_bead_proof_integrity.json" \
    --source-gap-picker-json "${steps_dir}/source-gap/out/zero_ready_source_gap_picker.json" \
    --operator-doc "${fixtures_dir}/operator/operator.md" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/operator-source-gap/out"

  run_logged_step "operator-clean" "0" \
    "$operator_gate" \
    --saturation-report-json "${fixtures_dir}/operator/saturation_report.json" \
    --closed-bead-proof-json "${steps_dir}/closed-clean/out/closed_bead_proof_integrity.json" \
    --source-gap-picker-json "${steps_dir}/source-gap-clean/out/zero_ready_source_gap_picker.json" \
    --operator-doc "${fixtures_dir}/operator/operator.md" \
    --source-revision "$source_revision" \
    --generated-at-utc "$generated_at_utc" \
    --output-dir "${steps_dir}/operator-clean/out"

  write_report
  write_run_manifest
  write_event "drill" "finished" "pass" "$report_path"
  record_pass "fixture"
  printf 'zero_ready_validation_truth_no_mock_drill_report=%s\n' "$report_path"
}

latest_bundle_dir() {
  local parent="$1"
  find "$parent" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -n \
    | awk 'END {print $2}'
}

verify_command_transcript_safe() {
  local transcript="$1"
  if grep -Eq '(^|[[:space:]])cargo[[:space:]]+(check|test|clippy|build|bench|run)([[:space:]]|$)' "$transcript"; then
    printf 'command transcript includes local heavy Cargo execution: %s\n' "$transcript" >&2
    return 1
  fi
}

run_replay() {
  if [[ -n "$latest_from" ]]; then
    replay_run_dir="$(latest_bundle_dir "$latest_from")"
  fi
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay requires --replay-run-dir or --latest-from\n' >&2
    exit 64
  fi
  run_dir="$replay_run_dir"
  refresh_paths
  for required in "$manifest_path" "$events_path" "$commands_path" "$report_path" "$source_inputs_path" "$operator_summary_path"; do
    if [[ ! -f "$required" ]]; then
      printf 'replay bundle missing required artifact: %s\n' "$required" >&2
      exit 1
    fi
  done
  jq empty "$manifest_path" "$report_path" "$source_inputs_path"
  jq empty "$events_path" >/dev/null
  verify_command_transcript_safe "$commands_path"
  jq -e '
    .decision == "pass"
    and ([.assertion_results[]] | all)
    and .checks.rch_policy.trusted_wrapper_status == "pass"
    and .checks.rch_policy.bare_cargo_status == "fail"
    and (.checks.rch_policy.bare_cargo_violation_kinds | index("bare_cargo"))
    and .checks.closed_bead_proof.semantic_contradiction_count == 1
    and .checks.source_gap_picker.proposal_count == 1
    and .checks.operator_handoff.source_gap_state == "source_gap_found"
    and .checks.operator_handoff.clean_state == "true_saturation"
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.repairs_agent_mail_db == false
  ' "$report_path" >/dev/null
  record_pass "replay"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}" "$smoke_path" "$rch_gate" "$closed_proof" "$source_gap_picker" "$operator_gate"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${BASH_SOURCE[0]}" "$smoke_path"
  fi
  grep -Fq "source_gap_found" "$doc_path"
  grep -Fq "run_manifest.json" "$doc_path"
  grep -Fq "rch exec -- env CARGO_TARGET_DIR=" "$doc_path"
  git -C "$root_dir" diff --check -- \
    "$doc_path" \
    "${BASH_SOURCE[0]}" \
    "$smoke_path" \
    "$golden_path"
  record_pass "check"
}

run_selftest() {
  run_check
  run_fixture
  replay_run_dir="$run_dir"
  run_replay
  record_pass "selftest"
}

case "$mode" in
  fixture)
    run_fixture
    ;;
  replay)
    run_replay
    ;;
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac
