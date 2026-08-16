#!/usr/bin/env bash
# BRIDGE-00.1 executable-vs-scaffold truth-ledger gate.
#
# This gate validates the machine crosswalk against the live tracker, claim
# matrix, source ranges, artifact hashes, Git tracking state, and deterministic
# Markdown renderer. It never overwrites the committed ledger or report: every
# run is written to a unique, recoverable artifact prefix.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
case "$mode" in
  check | ci) ;;
  *)
    echo "usage: $0 [check|ci] [run_dir]" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${EXECUTION_TRUTH_LEDGER_ARTIFACT_ROOT:-artifacts/execution_truth_ledger}"
run_dir="${2:-${artifact_root}/${timestamp}-$$}"
target_dir="${EXECUTION_TRUTH_LEDGER_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_truth_${timestamp}_$$}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1200}"
rch_bin="${EXECUTION_TRUTH_LEDGER_RCH_BIN:-rch}"
ledger_path="${EXECUTION_TRUTH_LEDGER_PATH:-docs/execution_truth_ledger_v1.json}"
markdown_path="docs/EXECUTION_TRUTH_LEDGER_V1.md"
tool_manifest="tools/execution-truth-ledger/Cargo.toml"
tool_lock="tools/execution-truth-ledger/Cargo.lock"
tool_bin_source="crates/franken-engine/src/bin/franken_execution_truth_ledger.rs"
tool_lib_source="crates/franken-engine/src/execution_truth_ledger.rs"
tool_binary="${target_dir}/debug/franken_execution_truth_ledger"
run_id="run-execution-truth-ledger-${timestamp}-$$"
trace_id="trace-execution-truth-ledger-${timestamp}-$$"
scenario_id="canonical-${mode}"
seed=424242
attempt=1
source_cutoff="$(jq -r '.source_cutoff_utc // "unknown"' "$ledger_path" 2>/dev/null || printf 'unknown')"
platform="$(uname -srm 2>/dev/null || printf 'unknown')"

commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
validator_events_path="${run_dir}/validator_events.jsonl"
validation_report_path="${run_dir}/validation_report.json"
generated_markdown_path="${run_dir}/EXECUTION_TRUTH_LEDGER_V1.generated.md"
render_diff_path="${run_dir}/render.diff"
env_path="${run_dir}/env.json"
source_lock_path="${run_dir}/source_lock.json"
review_record_path="${run_dir}/review_record.json"
provenance_graph_path="${run_dir}/provenance_graph.json"
repro_lock_path="${run_dir}/repro.lock"
legal_path="${run_dir}/LEGAL.md"
rollback_path="${run_dir}/ROLLBACK.md"
manifest_path="${run_dir}/run_manifest.json"
logs_dir="${run_dir}/logs"
validation_stderr_log="${logs_dir}/validate.stderr.log"
render_stderr_log="${logs_dir}/render.stderr.log"

mkdir -p "$(dirname "$run_dir")"
if [[ -e "$run_dir" ]]; then
  echo "refusing to overwrite existing truth-ledger run directory: ${run_dir}" >&2
  exit 2
fi
mkdir "$run_dir"
mkdir "$logs_dir"
: >"$commands_path"
: >"$events_path"
: >"$render_diff_path"

event_sequence=0
append_event() {
  local phase="$1"
  local decision="$2"
  local reason_raw="$3"
  local error_code="${4:-}"
  local duration_us="${5:-0}"
  local reason
  event_sequence=$((event_sequence + 1))
  reason="$(proof_contract_redact_text "$reason_raw" | cut -c1-768)"
  jq -nc \
    --arg schema_version "franken-engine.execution-truth-ledger.gate-event.v1" \
    --arg run_id "$run_id" \
    --arg trace_id "$trace_id" \
    --arg test_id "$phase" \
    --arg scenario_id "$scenario_id" \
    --argjson seed "$seed" \
    --argjson attempt "$attempt" \
    --arg source_cutoff "$source_cutoff" \
    --arg platform "$platform" \
    --arg phase "$phase" \
    --argjson sequence "$event_sequence" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --arg error_code "$error_code" \
    --argjson duration_us "$duration_us" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      trace_id: $trace_id,
      test_id: $test_id,
      scenario_id: $scenario_id,
      seed: $seed,
      attempt: $attempt,
      source_cutoff: $source_cutoff,
      platform: $platform,
      phase: $phase,
      sequence: $sequence,
      decision: $decision,
      reason: $reason,
      error_code: (if $error_code == "" then null else $error_code end),
      duration_us: $duration_us,
      artifact_hashes: {}
    }' >>"$events_path"
}

run_rch() {
  timeout "$rch_timeout_seconds" \
    env RCH_REQUIRE_REMOTE=1 \
    "$rch_bin" --no-color exec -- env -u CARGO_ENCODED_RUSTFLAGS \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "CARGO_INCREMENTAL=0" \
      "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" \
      "$@"
}

record_rch_command() {
  printf 'timeout %q env RCH_REQUIRE_REMOTE=1 %q --no-color exec -- env -u CARGO_ENCODED_RUSTFLAGS ' \
    "$rch_timeout_seconds" "$rch_bin" >>"$commands_path"
  printf '%q ' \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_INCREMENTAL=0" \
    "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" >>"$commands_path"
  printf '%q ' "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

record_local_command() {
  printf 'timeout %q ' "$rch_timeout_seconds" >>"$commands_path"
  printf '%q ' "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

if ! command -v jq >/dev/null 2>&1; then
  echo "missing required tool: jq; recoverable run prefix retained at ${run_dir}" >&2
  exit 2
fi

append_event "gate.start" "info" "mode=${mode}; run_dir=${run_dir}"

preflight_error=""
for required_tool in jq git sha256sum timeout diff; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    preflight_error="missing required tool: ${required_tool}"
    break
  fi
done
if [[ -z "$preflight_error" ]] && ! command -v "$rch_bin" >/dev/null 2>&1; then
  preflight_error="missing required rch executable: ${rch_bin}"
fi
if [[ -z "$preflight_error" && ! -f "$ledger_path" ]]; then
  preflight_error="missing ledger: ${ledger_path}"
fi
if [[ -z "$preflight_error" && ! -f "$markdown_path" ]]; then
  preflight_error="missing generated Markdown: ${markdown_path}"
fi
if [[ -z "$preflight_error" && ! -f "$tool_manifest" ]]; then
  preflight_error="missing independently locked validator manifest: ${tool_manifest}"
fi
if [[ -z "$preflight_error" && ! -f "$tool_lock" ]]; then
  preflight_error="missing independently locked validator lockfile: ${tool_lock}"
fi
if [[ -z "$preflight_error" && ! -f "$tool_bin_source" ]]; then
  preflight_error="missing validator binary source: ${tool_bin_source}"
fi
if [[ -z "$preflight_error" && ! -f "$tool_lib_source" ]]; then
  preflight_error="missing validator library source: ${tool_lib_source}"
fi
if [[ -z "$preflight_error" && ( -e "$tool_binary" || -L "$tool_binary" ) ]]; then
  preflight_error="refusing pre-existing validator binary: ${tool_binary}"
fi

test_exit=0
tool_build_exit=0
validate_process_exit=0
validate_exit=0
render_process_exit=0
render_exit=0
diff_exit=0
input_ledger_sha="$(proof_contract_sha256_file "$ledger_path")"

if [[ -n "$preflight_error" ]]; then
  append_event "gate.preflight" "fail" "$preflight_error" "FE-TRUTH-GATE-1001"
  tool_build_exit=2
  validate_exit=2
  render_exit=2
  diff_exit=2
else
  append_event "gate.preflight" "pass" "required tools and canonical inputs present"

  if [[ "$mode" == "ci" ]]; then
    record_rch_command cargo test --locked --manifest-path "$tool_manifest" --all-targets
    start_ns="$(date +%s%N)"
    set +e
    run_rch cargo test --locked --manifest-path "$tool_manifest" --all-targets \
      >"${logs_dir}/targeted_tests.log" 2>&1
    test_exit="$?"
    set -e
    duration_us=$((($(date +%s%N) - start_ns) / 1000))
    if [[ "$test_exit" -eq 0 ]]; then
      append_event "gate.targeted_tests" "pass" "unit and integration tests passed" "" "$duration_us"
    else
      append_event "gate.targeted_tests" "fail" "targeted tests exited ${test_exit}" "FE-TRUTH-GATE-1002" "$duration_us"
    fi
  fi

  record_rch_command cargo build --locked --manifest-path "$tool_manifest" \
    --bin franken_execution_truth_ledger
  start_ns="$(date +%s%N)"
  set +e
  run_rch cargo build --locked --manifest-path "$tool_manifest" \
    --bin franken_execution_truth_ledger \
    >"${logs_dir}/tool_build.log" 2>&1
  tool_build_exit="$?"
  set -e
  tool_build_error=""
  if [[ "$tool_build_exit" -ne 0 ]]; then
    tool_build_error="remote validator build exited ${tool_build_exit}"
  elif [[ ! -f "$tool_binary" || ! -x "$tool_binary" || -L "$tool_binary" ]]; then
    tool_build_error="remote build did not retrieve one regular executable validator"
    tool_build_exit=2
  fi
  duration_us=$((($(date +%s%N) - start_ns) / 1000))
  if [[ "$tool_build_exit" -eq 0 ]]; then
    append_event "gate.tool_build" "pass" "strict RCH build retrieved the validator executable" "" "$duration_us"
  else
    append_event "gate.tool_build" "fail" "$tool_build_error" "FE-TRUTH-GATE-1006" "$duration_us"
  fi

  if [[ "$tool_build_exit" -ne 0 ]]; then
    validate_exit=2
    render_exit=2
    diff_exit=2
    append_event "gate.validate" "fail" "validation skipped because the validator build was unavailable" "FE-TRUTH-GATE-1003"
    append_event "gate.render" "fail" "render skipped because the validator build was unavailable" "FE-TRUTH-GATE-1004"
    append_event "gate.render_drift" "fail" "render comparison skipped because no trustworthy generated document existed" "FE-TRUTH-GATE-1005"
  else
    record_local_command "$tool_binary" validate \
      --repo-root "$root_dir" \
      --ledger "$ledger_path" \
      --events "$validator_events_path" \
      --run-id "$run_id" \
      --trace-id "$trace_id" \
      --scenario-id "$scenario_id" \
      --seed "$seed" \
      --attempt "$attempt"
    start_ns="$(date +%s%N)"
    set +e
    timeout "$rch_timeout_seconds" \
      "$tool_binary" validate \
      --repo-root "$root_dir" \
      --ledger "$ledger_path" \
      --events "$validator_events_path" \
      --run-id "$run_id" \
      --trace-id "$trace_id" \
      --scenario-id "$scenario_id" \
      --seed "$seed" \
      --attempt "$attempt" \
      >"$validation_report_path" 2>"$validation_stderr_log"
    validate_process_exit="$?"
    set -e
    validation_contract_error=""
    if ! jq -e --arg ledger_sha "$input_ledger_sha" '
        .schema_version == "franken-engine.execution-truth-ledger.validation-report.v1"
        and .ledger_sha256 == $ledger_sha
        and (.status == "pass" or .status == "fail")
        and (.subject_count | type == "number")
        and (.proof_count | type == "number")
        and (.checks_run | type == "number")
        and (.error_count | type == "number")
        and (.findings | type == "array")
        and .error_count == (.findings | length)
        and (
          (.status == "pass" and .error_count == 0)
          or (.status == "fail" and .error_count > 0)
        )
      ' "$validation_report_path" >/dev/null 2>&1; then
      validation_contract_error="validation report is missing, malformed, or inconsistent"
    elif ! jq -se \
      --arg run_id "$run_id" \
      --arg trace_id "$trace_id" \
      --arg scenario_id "$scenario_id" \
      --argjson seed "$seed" \
      --argjson attempt "$attempt" '
        length > 0
        and all(.[];
          .schema_version == "franken-engine.execution-truth-ledger.validation-event.v1"
          and .run_id == $run_id
          and .trace_id == $trace_id
          and .scenario_id == $scenario_id
          and .seed == $seed
          and .attempt == $attempt
        )
        and ([.[].sequence] as $sequences
          | $sequences == [range(1; ($sequences | length) + 1)])
      ' "$validator_events_path" >/dev/null 2>&1; then
      validation_contract_error="validation events are missing, malformed, or identity-inconsistent"
    else
      validation_report_status="$(jq -r '.status' "$validation_report_path")"
      if [[ "$validate_process_exit" -eq 0 && "$validation_report_status" == "pass" ]]; then
        validate_exit=0
      elif [[ "$validate_process_exit" -eq 1 && "$validation_report_status" == "fail" ]]; then
        validate_exit=1
      else
        validation_contract_error="validator exit/status mismatch: exit=${validate_process_exit} status=${validation_report_status}"
      fi
    fi
    if [[ -n "$validation_contract_error" ]]; then
      validate_exit=2
    fi
    duration_us=$((($(date +%s%N) - start_ns) / 1000))
    if [[ "$validate_exit" -eq 0 ]]; then
      append_event "gate.validate" "pass" "live ledger validation passed" "" "$duration_us"
    else
      validation_reason="live ledger validation exited ${validate_exit}"
      if [[ -n "$validation_contract_error" ]]; then
        validation_reason="${validation_reason}; ${validation_contract_error}"
      fi
      append_event "gate.validate" "fail" "$validation_reason" "FE-TRUTH-GATE-1003" "$duration_us"
    fi

    record_local_command "$tool_binary" render \
      --repo-root "$root_dir" \
      --ledger "$ledger_path"
    start_ns="$(date +%s%N)"
    set +e
    timeout "$rch_timeout_seconds" \
      "$tool_binary" render \
      --repo-root "$root_dir" \
      --ledger "$ledger_path" \
      >"$generated_markdown_path" 2>"$render_stderr_log"
    render_process_exit="$?"
    set -e
    render_contract_error=""
    if [[ "$render_process_exit" -ne 0 ]]; then
      render_contract_error="renderer process exited ${render_process_exit}"
    elif [[ ! -s "$generated_markdown_path" || -L "$generated_markdown_path" ]] \
      || [[ "$(head -n 1 "$generated_markdown_path")" != "# Execution-vs-Scaffold Truth Ledger v1" ]]; then
      render_contract_error="generated Markdown is empty, symlinked, or has the wrong heading"
    fi
    if [[ -n "$render_contract_error" ]]; then
      render_exit=2
    else
      render_exit=0
    fi
    duration_us=$((($(date +%s%N) - start_ns) / 1000))
    if [[ "$render_exit" -eq 0 ]]; then
      append_event "gate.render" "pass" "deterministic Markdown rendered" "" "$duration_us"
    else
      append_event "gate.render" "fail" "$render_contract_error" "FE-TRUTH-GATE-1004" "$duration_us"
    fi

    if [[ "$render_exit" -eq 0 ]]; then
      printf 'diff -u %q %q\n' "$markdown_path" "$generated_markdown_path" >>"$commands_path"
      start_ns="$(date +%s%N)"
      set +e
      diff -u "$markdown_path" "$generated_markdown_path" >"$render_diff_path"
      diff_exit="$?"
      set -e
      duration_us=$((($(date +%s%N) - start_ns) / 1000))
      if [[ "$diff_exit" -eq 0 ]]; then
        append_event "gate.render_drift" "pass" "committed Markdown matches generated output" "" "$duration_us"
      else
        append_event "gate.render_drift" "fail" "committed Markdown differs from renderer output" "FE-TRUTH-GATE-1005" "$duration_us"
      fi
    else
      diff_exit=2
      append_event "gate.render_drift" "fail" "render comparison skipped because no trustworthy generated document existed" "FE-TRUTH-GATE-1005"
    fi
  fi
fi

final_ledger_sha="$(proof_contract_sha256_file "$ledger_path")"
if [[ -z "$preflight_error" && "$final_ledger_sha" != "$input_ledger_sha" ]]; then
  validate_exit=2
  render_exit=2
  diff_exit=2
  append_event "gate.source_identity" "fail" "ledger bytes changed during validation" "FE-TRUTH-GATE-1007"
else
  append_event "gate.source_identity" "pass" "ledger bytes remained stable during validation"
fi

git_revision="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
rustc_version="$(rustc --version 2>/dev/null || printf 'unavailable')"
ledger_sha="$final_ledger_sha"
matrix_sha="$(proof_contract_sha256_file docs/claim_to_proof_matrix_v1.json)"
tracker_sha="$(proof_contract_sha256_file .beads/issues.jsonl)"
markdown_sha="$(proof_contract_sha256_file "$markdown_path")"
tool_manifest_sha="$(proof_contract_sha256_file "$tool_manifest")"
tool_lock_sha="$(proof_contract_sha256_file "$tool_lock")"
tool_bin_source_sha="$(proof_contract_sha256_file "$tool_bin_source")"
tool_lib_source_sha="$(proof_contract_sha256_file "$tool_lib_source")"
tool_binary_sha="$(proof_contract_sha256_file "$tool_binary")"
denominator_sha="$(proof_contract_sha256_file docs/perf/e2_denominator_bundle_v1/denominator.json)"
test262_sha="$(proof_contract_sha256_file docs/test262_real_corpus_pass_rate_v1.json)"
coverage_sha="$(proof_contract_sha256_file docs/coverage/es2020_coverage_summary_bundle_v1/coverage_summary.json)"
perf_pass1_sha="$(proof_contract_sha256_file tests/artifacts/perf/20260520T214829Z-prof-pass1/baseline_summary.json)"
track_g_lean_sha="$(proof_contract_sha256_file artifacts/dw_proof_spine/20260710T090949Z/proof_spine_e2e/FE-CLAIM-016.proof.json)"

jq -n \
  --arg schema_version "franken-engine.execution-truth-ledger.env.v1" \
  --arg platform "$platform" \
  --arg rustc "$rustc_version" \
  --arg toolchain "$toolchain" \
  --arg target_dir "$target_dir" \
  --arg git_revision "$git_revision" \
  '{
    schema_version: $schema_version,
    platform: $platform,
    rustc: $rustc,
    rustup_toolchain: $toolchain,
    cargo_target_dir: $target_dir,
    git_revision: $git_revision,
    redaction: "allowlisted fields only; no ambient environment captured"
  }' >"$env_path"

jq -n \
  --arg schema_version "franken-engine.execution-truth-ledger.source-lock.v1" \
  --arg ledger_sha "$ledger_sha" \
  --arg matrix_sha "$matrix_sha" \
  --arg tracker_sha "$tracker_sha" \
  --arg markdown_sha "$markdown_sha" \
  --arg tool_manifest_sha "$tool_manifest_sha" \
  --arg tool_lock_sha "$tool_lock_sha" \
  --arg tool_bin_source_sha "$tool_bin_source_sha" \
  --arg tool_lib_source_sha "$tool_lib_source_sha" \
  --arg tool_binary_path "$tool_binary" \
  --arg tool_binary_sha "$tool_binary_sha" \
  --arg denominator_sha "$denominator_sha" \
  --arg test262_sha "$test262_sha" \
  --arg coverage_sha "$coverage_sha" \
  --arg perf_pass1_sha "$perf_pass1_sha" \
  --arg track_g_lean_sha "$track_g_lean_sha" \
  '{
    schema_version: $schema_version,
    inputs: [
      {path:"docs/execution_truth_ledger_v1.json", sha256:$ledger_sha, role:"machine_crosswalk"},
      {path:"docs/EXECUTION_TRUTH_LEDGER_V1.md", sha256:$markdown_sha, role:"generated_human_report"},
      {path:"docs/claim_to_proof_matrix_v1.json", sha256:$matrix_sha, role:"claim_authority"},
      {path:".beads/issues.jsonl", sha256:$tracker_sha, role:"tracker_authority"},
      {path:"tools/execution-truth-ledger/Cargo.toml", sha256:$tool_manifest_sha, role:"independent_validator_manifest"},
      {path:"tools/execution-truth-ledger/Cargo.lock", sha256:$tool_lock_sha, role:"independent_validator_lock"},
      {path:"crates/franken-engine/src/bin/franken_execution_truth_ledger.rs", sha256:$tool_bin_source_sha, role:"validator_binary_source"},
      {path:"crates/franken-engine/src/execution_truth_ledger.rs", sha256:$tool_lib_source_sha, role:"validator_library_source"},
      {path:$tool_binary_path, sha256:$tool_binary_sha, role:"strict_rch_built_validator_binary"},
      {path:"docs/perf/e2_denominator_bundle_v1/denominator.json", sha256:$denominator_sha, role:"performance_observation"},
      {path:"docs/test262_real_corpus_pass_rate_v1.json", sha256:$test262_sha, role:"conformance_observation"},
      {path:"docs/coverage/es2020_coverage_summary_bundle_v1/coverage_summary.json", sha256:$coverage_sha, role:"coverage_observation"},
      {path:"tests/artifacts/perf/20260520T214829Z-prof-pass1/baseline_summary.json", sha256:$perf_pass1_sha, role:"ignored_local_historical_observation"},
      {path:"artifacts/dw_proof_spine/20260710T090949Z/proof_spine_e2e/FE-CLAIM-016.proof.json", sha256:$track_g_lean_sha, role:"ignored_local_lean_observation"}
    ]
  }' >"$source_lock_path"

jq '{
  schema_version:"franken-engine.execution-truth-ledger.review-record.v1",
  owning_bead,
  source_cutoff_utc,
  governed_subject_ids:[.subjects[].subject_id],
  findings,
  independent_challenge_owner:"bd-performance-conformance-bridge-tu32j.22.6"
}' "$ledger_path" >"$review_record_path" 2>/dev/null || printf '{}\n' >"$review_record_path"

jq '{
  schema_version:"franken-engine.execution-truth-ledger.provenance-graph.v1",
  nodes:([.subjects[].subject_id] | unique),
  edges:.provenance_edges
}' "$ledger_path" >"$provenance_graph_path" 2>/dev/null || printf '{}\n' >"$provenance_graph_path"

{
  printf '# Legal and Corpus Record\n\n'
  printf 'Generated from `%s`; this bundle redistributes no external corpus or runtime binary.\n\n' "$ledger_path"
  jq -r '.legal.external_corpora[] | "- \(.name) @ \(.revision): \(.license); \(.redistribution)"' "$ledger_path"
} >"$legal_path"

{
  printf '# Rollback and Recovery\n\n'
  printf 'This gate never overwrites the committed ledger or Markdown. A failed or interrupted run leaves a recoverable prefix at `%s`.\n\n' "$run_dir"
  printf 'Rollback means retaining the prior tracked `docs/execution_truth_ledger_v1.json` and `docs/EXECUTION_TRUTH_LEDGER_V1.md`, preserving this failed bundle, and rerunning the exact commands in `commands.txt` after correction.\n'
} >"$rollback_path"

verdict="pass"
if [[ "$test_exit" -ne 0 || "$tool_build_exit" -ne 0 || "$validate_exit" -ne 0 \
  || "$render_exit" -ne 0 || "$diff_exit" -ne 0 ]]; then
  verdict="fail"
fi
append_event "gate.end" "$verdict" "test=${test_exit}; tool_build=${tool_build_exit}; validate_process=${validate_process_exit}; validate=${validate_exit}; render_process=${render_process_exit}; render=${render_exit}; diff=${diff_exit}"

events_sha="$(proof_contract_sha256_file "$events_path")"
validator_events_sha="$(proof_contract_sha256_file "$validator_events_path")"
validation_report_sha="$(proof_contract_sha256_file "$validation_report_path")"
commands_sha="$(proof_contract_sha256_file "$commands_path")"
generated_markdown_sha="$(proof_contract_sha256_file "$generated_markdown_path")"

jq -n \
  --arg schema_version "franken-engine.execution-truth-ledger.run-manifest.v1" \
  --arg run_id "$run_id" \
  --arg trace_id "$trace_id" \
  --arg scenario_id "$scenario_id" \
  --arg mode "$mode" \
  --arg verdict "$verdict" \
  --arg source_cutoff "$source_cutoff" \
  --arg git_revision "$git_revision" \
  --arg target_dir "$target_dir" \
  --argjson seed "$seed" \
  --argjson attempt "$attempt" \
  --argjson test_exit "$test_exit" \
  --argjson tool_build_exit "$tool_build_exit" \
  --argjson validate_process_exit "$validate_process_exit" \
  --argjson validate_exit "$validate_exit" \
  --argjson render_process_exit "$render_process_exit" \
  --argjson render_exit "$render_exit" \
  --argjson diff_exit "$diff_exit" \
  --arg events_sha "$events_sha" \
  --arg validator_events_sha "$validator_events_sha" \
  --arg validation_report_sha "$validation_report_sha" \
  --arg commands_sha "$commands_sha" \
  --arg generated_markdown_sha "$generated_markdown_sha" \
  --arg tool_binary_sha "$tool_binary_sha" \
  '{
    schema_version:$schema_version,
    run_id:$run_id,
    trace_id:$trace_id,
    scenario_id:$scenario_id,
    seed:$seed,
    attempt:$attempt,
    mode:$mode,
    verdict:$verdict,
    source_cutoff:$source_cutoff,
    git_revision:$git_revision,
    cargo_target_dir:$target_dir,
    exit_codes:{
      tests:$test_exit,
      tool_build:$tool_build_exit,
      validate_process:$validate_process_exit,
      validate:$validate_exit,
      render_process:$render_process_exit,
      render:$render_exit,
      diff:$diff_exit
    },
    artifacts:{
      commands:"commands.txt",
      events:"events.jsonl",
      validator_events:"validator_events.jsonl",
      validation_report:"validation_report.json",
      generated_markdown:"EXECUTION_TRUTH_LEDGER_V1.generated.md",
      render_diff:"render.diff",
      env:"env.json",
      source_lock:"source_lock.json",
      review_record:"review_record.json",
      provenance_graph:"provenance_graph.json",
      repro_lock:"repro.lock",
      legal:"LEGAL.md",
      rollback:"ROLLBACK.md",
      logs:"logs/"
    },
    artifact_hashes:{
      "commands.txt":$commands_sha,
      "events.jsonl":$events_sha,
      "validator_events.jsonl":$validator_events_sha,
      "validation_report.json":$validation_report_sha,
      "EXECUTION_TRUTH_LEDGER_V1.generated.md":$generated_markdown_sha,
      "validator_binary":$tool_binary_sha
    },
    recovery:{atomicity:"unique-prefix; committed files are read-only",rollback:"ROLLBACK.md"},
    owning_bead:"bd-performance-conformance-bridge-tu32j.1.1"
  }' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.execution-truth-ledger.repro-lock.v1" \
  --arg git_revision "$git_revision" \
  --arg source_lock_sha "$(proof_contract_sha256_file "$source_lock_path")" \
  --arg command "./scripts/run_execution_truth_ledger_gate.sh ${mode}" \
  '{
    schema_version:$schema_version,
    git_revision:$git_revision,
    source_lock_sha256:$source_lock_sha,
    reproduction_command:$command,
    result_contract:"same validation decisions and artifact input hashes; durations and timestamps may differ"
  }' >"$repro_lock_path"

proof_contract_write_standard_bundle \
  "$run_dir" \
  "execution_truth_ledger" \
  "$verdict" \
  "./scripts/run_execution_truth_ledger_gate.sh ${mode}" \
  "$validation_report_path" \
  "$events_path" \
  "$commands_path" \
  "bd-performance-conformance-bridge-tu32j.1.1,bd-1lsy.7.3,bd-1lsy.7.10,bd-6a61n.1.8,bd-cixqu.7.17,bd-11p,bd-w2dov,bd-o4cbn" \
  "FE-CLAIM-001,FE-CLAIM-009,FE-CLAIM-010,FE-CLAIM-016,FE-CLAIM-017,FE-CLAIM-018,FE-CLAIM-019,FE-CLAIM-020,FE-CLAIM-021,FE-CLAIM-025,FE-CLAIM-026,FE-CLAIM-TEST262"

echo "execution_truth_ledger_run_dir=${run_dir}"
echo "execution_truth_ledger_manifest=${manifest_path}"
echo "execution_truth_ledger_verdict=${verdict}"

if [[ "$verdict" == "pass" ]]; then
  exit 0
fi
exit 1
