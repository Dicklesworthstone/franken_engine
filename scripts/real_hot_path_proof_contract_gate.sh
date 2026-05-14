#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${REAL_HOT_PATH_PROOF_CONTRACT_ARTIFACT_ROOT:-artifacts/real_hot_path_proof_contract_gate}"
run_id="${REAL_HOT_PATH_PROOF_CONTRACT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
bundle_dir=""
output_dir="${REAL_HOT_PATH_PROOF_CONTRACT_OUTPUT_DIR:-${artifact_root}/${run_id}}"
expected_source_revision="${REAL_HOT_PATH_PROOF_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/real_hot_path_proof_contract_gate.sh --bundle-dir DIR [--output-dir DIR] [--source-revision REV]

Validates a real hot-path proof artifact bundle emitted by:

  ./scripts/run_real_hot_path_proof.sh smoke

The gate writes diagnostics.json and report.md. It exits 42 when the bundle is
well-formed enough to inspect but violates the proof contract.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bundle_dir="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      output_dir="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      expected_source_revision="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      if [[ -z "$bundle_dir" ]]; then
        bundle_dir="$1"
        shift
      else
        printf 'unexpected positional argument: %s\n' "$1" >&2
        usage
        exit 64
      fi
      ;;
  esac
done

if [[ -z "$bundle_dir" ]]; then
  usage
  exit 64
fi

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s is required for real hot-path proof contract validation\n' "$tool" >&2
    exit 2
  fi
}

require_tool jq
require_tool realpath

if command -v sha256sum >/dev/null 2>&1; then
  sha256_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  sha256_cmd=(shasum -a 256)
else
  sha256_cmd=(openssl dgst -sha256)
fi

sha256_text() {
  local text="$1"
  printf '%s' "$text" | "${sha256_cmd[@]}" | awk '{print $1}'
}

repo_relative_path() {
  local path="$1"
  local absolute

  absolute="$(realpath -m "$path")"
  case "$absolute" in
    "$root_dir") printf '.\n' ;;
    "$root_dir"/*) printf '%s\n' "${absolute#"$root_dir"/}" ;;
    *) printf '%s\n' "$absolute" ;;
  esac
}

resolve_path() {
  local path="$1"

  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  elif [[ "$path" == scripts/* || "$path" == artifacts/* ]]; then
    printf '%s/%s\n' "$root_dir" "${path#./}"
  else
    printf '%s/%s\n' "$bundle_abs" "${path#./}"
  fi
}

bundle_abs="$(resolve_path "$bundle_dir")"
bundle_rel="$(repo_relative_path "$bundle_abs")"
output_abs="$(resolve_path "$output_dir")"
mkdir -p "$output_abs"

diagnostics_path="${output_abs}/diagnostics.json"
report_path="${output_abs}/report.md"
failures_jsonl="${output_abs}/failures.jsonl"
checked_artifacts_jsonl="${output_abs}/checked_artifacts.jsonl"
: >"$failures_jsonl"
: >"$checked_artifacts_jsonl"

emit_failure() {
  local code="$1"
  local path="$2"
  local message="$3"
  local remediation="$4"

  jq -nc \
    --arg code "$code" \
    --arg path "$path" \
    --arg message "$message" \
    --arg remediation "$remediation" \
    '{code: $code, path: $path, message: $message, remediation: $remediation}' >>"$failures_jsonl"
}

record_checked_artifact() {
  local key="$1"
  local path="$2"
  local kind="$3"
  local exists=false

  if [[ "$kind" == "dir" ]]; then
    [[ -d "$path" ]] && exists=true
  else
    [[ -f "$path" ]] && exists=true
  fi

  jq -nc \
    --arg key "$key" \
    --arg path "$(repo_relative_path "$path")" \
    --arg kind "$kind" \
    --argjson exists "$exists" \
    '{key: $key, path: $path, kind: $kind, exists: $exists}' >>"$checked_artifacts_jsonl"
}

detect_synthetic_contamination() {
  local candidate
  while IFS= read -r candidate; do
    if grep -Eq 'hot_paths_simulation|MockCertificate' "$candidate"; then
      emit_failure \
        "FE-REAL-HOT-PATH-CONTRACT-SYNTHETIC-CONTAMINATION" \
        "$(repo_relative_path "$candidate")" \
        "proof bundle contains fixture-only simulated hot-path evidence markers" \
        "Discard contaminated evidence and re-run scripts/run_real_hot_path_proof.sh against real_runtime_hot_paths."
      return 0
    fi
  done < <(
    find "$bundle_abs" -type f \
      \( -name "*.json" -o -name "*.jsonl" -o -name "*.md" -o -name "*.txt" -o -name "*.log" \) \
      | sort
  )

  return 1
}

assert_file_exists() {
  local key="$1"
  local path="$2"

  record_checked_artifact "$key" "$path" file
  if [[ ! -f "$path" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-MISSING-ARTIFACT" \
      "$(repo_relative_path "$path")" \
      "${key} is required but was not found" \
      "Regenerate the proof bundle and preserve every path declared by run_manifest.json."
    return 1
  fi
}

manifest_path="${bundle_abs}/run_manifest.json"
trace_ids_path="${bundle_abs}/trace_ids.json"
events_path="${bundle_abs}/events.jsonl"
commands_path="${bundle_abs}/commands.txt"

assert_file_exists "run_manifest" "$manifest_path" || true
assert_file_exists "trace_ids" "$trace_ids_path" || true
assert_file_exists "events" "$events_path" || true
assert_file_exists "commands" "$commands_path" || true
detect_synthetic_contamination || true

manifest_valid=false
trace_ids_valid=false
events_valid=false

if [[ -f "$manifest_path" ]]; then
  if jq empty "$manifest_path" >/dev/null 2>&1; then
    manifest_valid=true
  else
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-MALFORMED-MANIFEST" \
      "$(repo_relative_path "$manifest_path")" \
      "run_manifest.json is not valid JSON" \
      "Rewrite the manifest through scripts/run_real_hot_path_proof.sh instead of editing it by hand."
  fi
fi

if [[ -f "$trace_ids_path" ]]; then
  if jq empty "$trace_ids_path" >/dev/null 2>&1; then
    trace_ids_valid=true
  else
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-MALFORMED-TRACE-IDS" \
      "$(repo_relative_path "$trace_ids_path")" \
      "trace_ids.json is not valid JSON" \
      "Regenerate trace_ids.json from the wrapper so trace and decision ids stay machine-readable."
  fi
fi

if [[ -f "$events_path" ]]; then
  events_valid=true
  events_rel="$(repo_relative_path "$events_path")"
  line_no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    [[ -z "$line" ]] && continue
    if ! jq empty <<<"$line" >/dev/null 2>&1; then
      events_valid=false
      emit_failure \
        "FE-REAL-HOT-PATH-CONTRACT-MALFORMED-EVENT" \
        "${events_rel}:${line_no}" \
        "events.jsonl contains a non-JSON event line" \
        "Emit every event as a single compact JSON object."
    fi
  done <"$events_path"
fi

manifest_string() {
  local filter="$1"
  if [[ "$manifest_valid" != true ]]; then
    printf ''
    return 0
  fi
  jq -r "($filter) | if . == null then \"\" else tostring end" "$manifest_path"
}

manifest_json() {
  local filter="$1"
  local fallback="$2"
  if [[ "$manifest_valid" != true ]]; then
    printf '%s\n' "$fallback"
    return 0
  fi
  jq -c "$filter // ${fallback}" "$manifest_path"
}

manifest_schema="$(manifest_string '.schema_version')"
manifest_bead_id="$(manifest_string '.bead_id')"
manifest_component="$(manifest_string '.component')"
manifest_mode="$(manifest_string '.mode')"
manifest_source_revision="$(manifest_string '.git_commit')"
manifest_trace_id="$(manifest_string '.trace_id')"
manifest_decision_id="$(manifest_string '.decision_id')"
manifest_policy_id="$(manifest_string '.policy_id')"
manifest_target_dir="$(manifest_string '.cargo_target_dir')"
manifest_incremental="$(manifest_string '.cargo_incremental')"
manifest_rustflags="$(manifest_string '.rustflags')"
manifest_outcome="$(manifest_string '.outcome')"
manifest_command="$(manifest_string '.commands[0]')"
manifest_remote_exit="$(manifest_string '.rch.remote_exit_code')"
manifest_worker_id="$(manifest_string '.rch.selected_worker.id')"
manifest_local_fallback="$(manifest_string '.rch.local_fallback_detected')"
manifest_queue_when_busy="$(manifest_string '.rch.queue_when_busy')"
metric_fields_json="$(manifest_json '{remote_exit_code: .rch.remote_exit_code, local_fallback_detected: .rch.local_fallback_detected, queue_when_busy: .rch.queue_when_busy}' '{}')"

require_manifest_string() {
  local value="$1"
  local json_path="$2"
  if [[ -z "$value" || "$value" == "null" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-MISSING-FIELD" \
      "run_manifest.json:${json_path}" \
      "${json_path} is required by the real hot-path proof contract" \
      "Regenerate the bundle with the wrapper so required contract fields are populated."
  fi
}

if [[ "$manifest_valid" == true ]]; then
  if [[ "$manifest_schema" != "franken-engine.real-hot-path-proof.run-manifest.v1" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-SCHEMA-MISMATCH" \
      "run_manifest.json:.schema_version" \
      "expected franken-engine.real-hot-path-proof.run-manifest.v1, got ${manifest_schema:-<missing>}" \
      "Use scripts/run_real_hot_path_proof.sh to produce the v1 contract."
  fi

  require_manifest_string "$manifest_bead_id" ".bead_id"
  require_manifest_string "$manifest_component" ".component"
  require_manifest_string "$manifest_mode" ".mode"
  require_manifest_string "$manifest_source_revision" ".git_commit"
  require_manifest_string "$manifest_trace_id" ".trace_id"
  require_manifest_string "$manifest_decision_id" ".decision_id"
  require_manifest_string "$manifest_policy_id" ".policy_id"
  require_manifest_string "$manifest_target_dir" ".cargo_target_dir"
  require_manifest_string "$manifest_command" ".commands[0]"

  if [[ "$manifest_component" != "real_hot_path_proof" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-SCHEMA-MISMATCH" \
      "run_manifest.json:.component" \
      "component must be real_hot_path_proof" \
      "Keep real hot-path proof bundles separate from generic benchmark artifacts."
  fi

  if [[ ! "$manifest_mode" =~ ^(check|smoke|ci)$ ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-PROOF-STATE" \
      "run_manifest.json:.mode" \
      "mode must be check, smoke, or ci for accepted proof evidence" \
      "Use dry-run only for planning; accepted proof evidence must exercise rch."
  fi

  if [[ "$manifest_outcome" != "pass" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-PROOF-STATE" \
      "run_manifest.json:.outcome" \
      "outcome must be pass for reusable real hot-path evidence" \
      "Repair the failing proof command before publishing this bundle as evidence."
  fi

  if [[ -n "$expected_source_revision" && "$manifest_source_revision" != "$expected_source_revision" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-STALE-SOURCE-REVISION" \
      "run_manifest.json:.git_commit" \
      "source revision ${manifest_source_revision:-<missing>} does not match expected ${expected_source_revision}" \
      "Re-run the real hot-path proof after the source revision changes."
  fi

  if [[ "$manifest_target_dir" != /tmp/* || "$manifest_target_dir" == "$root_dir"/* ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-TARGET-DIR-POLICY" \
      "run_manifest.json:.cargo_target_dir" \
      "cargo_target_dir must be an off-repo /tmp rch target" \
      "Set CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_real_hot_path_proof_... before invoking rch."
  fi

  if [[ "$manifest_incremental" != "0" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY" \
      "run_manifest.json:.cargo_incremental" \
      "CARGO_INCREMENTAL must be 0 for replayable hot-path proof evidence" \
      "Disable incremental compilation in the wrapper environment."
  fi

  if [[ "$manifest_rustflags" != *"-Cdebuginfo=0"* ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY" \
      "run_manifest.json:.rustflags" \
      "RUSTFLAGS must include -Cdebuginfo=0 for bounded artifact retrieval" \
      "Use the wrapper default RUSTFLAGS or record an explicit reviewed policy change."
  fi

  if [[ "$manifest_command" != *"rch exec --"* ||
        "$manifest_command" != *"RCH_QUEUE_WHEN_BUSY=1"* ||
        "$manifest_command" != *"CARGO_TARGET_DIR="* ||
        "$manifest_command" != *"--no-default-features"* ||
        "$manifest_command" != *"--bench hot_paths"* ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-COMMAND-POLICY" \
      "run_manifest.json:.commands[0]" \
      "command must route the hot_paths proof through rch with target isolation" \
      "Use scripts/run_real_hot_path_proof.sh instead of hand-written cargo commands."
  fi

  if [[ "$manifest_queue_when_busy" != "true" ||
        "$manifest_local_fallback" != "false" ||
        "$manifest_remote_exit" != "0" ||
        -z "$manifest_worker_id" ||
        "$manifest_worker_id" == "null" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY" \
      "run_manifest.json:.rch" \
      "rch proof must queue when busy, reject local fallback, record remote exit 0, and name the worker" \
      "Re-run through rch and keep the selected-worker and remote-exit log lines."
  fi

  while IFS=$'\t' read -r key raw_path; do
    [[ -z "$key" || -z "$raw_path" || "$raw_path" == "null" ]] && continue
    resolved_path="$(resolve_path "$raw_path")"
    if [[ "$key" == "step_logs_dir" ]]; then
      record_checked_artifact "manifest.artifacts.${key}" "$resolved_path" dir
      if [[ ! -d "$resolved_path" ]]; then
        emit_failure \
          "FE-REAL-HOT-PATH-CONTRACT-MISSING-ARTIFACT" \
          "$(repo_relative_path "$resolved_path")" \
          "declared artifact directory ${key} is missing" \
          "Preserve the complete proof bundle directory, including step log folders."
      fi
    else
      record_checked_artifact "manifest.artifacts.${key}" "$resolved_path" file
      if [[ ! -f "$resolved_path" ]]; then
        emit_failure \
          "FE-REAL-HOT-PATH-CONTRACT-MISSING-ARTIFACT" \
          "$(repo_relative_path "$resolved_path")" \
          "declared artifact ${key} is missing" \
          "Preserve the complete proof bundle directory and every path declared by run_manifest.json."
      fi
    fi
  done < <(jq -r '.artifacts // {} | to_entries[] | [.key, (.value | tostring)] | @tsv' "$manifest_path")
fi

if [[ "$manifest_valid" == true && "$trace_ids_valid" == true ]]; then
  trace_schema="$(jq -r '.schema_version // ""' "$trace_ids_path")"
  if [[ "$trace_schema" != "franken-engine.real-hot-path-proof.trace-ids.v1" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-SCHEMA-MISMATCH" \
      "trace_ids.json:.schema_version" \
      "expected franken-engine.real-hot-path-proof.trace-ids.v1, got ${trace_schema:-<missing>}" \
      "Regenerate trace_ids.json with the real hot-path proof wrapper."
  fi

  if ! jq -e \
    --arg trace_id "$manifest_trace_id" \
    --arg decision_id "$manifest_decision_id" \
    --arg policy_id "$manifest_policy_id" \
    '.policy_id == $policy_id
      and (.trace_ids | index($trace_id) != null)
      and (.decision_ids | index($decision_id) != null)' \
    "$trace_ids_path" >/dev/null; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-TRACE-MISMATCH" \
      "trace_ids.json" \
      "trace_ids.json must contain the manifest trace, decision, and policy ids" \
      "Regenerate the trace-id artifact with the same wrapper invocation as the manifest."
  fi
fi

event_runtime_lane=""
if [[ "$manifest_valid" == true && "$events_valid" == true && -f "$events_path" ]]; then
  event_count="$(jq -s 'length' "$events_path")"
  if [[ "$event_count" -eq 0 ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-MISSING-FIELD" \
      "events.jsonl" \
      "events.jsonl must contain at least one proof event" \
      "Emit the real_hot_path_proof_completed event before publishing the bundle."
  fi

  if ! jq -s -e \
    --arg trace_id "$manifest_trace_id" \
    --arg decision_id "$manifest_decision_id" \
    --arg policy_id "$manifest_policy_id" \
    'all(.[]; .schema_version == "franken-engine.real-hot-path-proof.event.v1")
      and any(.[]; .trace_id == $trace_id and .decision_id == $decision_id and .policy_id == $policy_id)
      and any(.[]; .event == "real_hot_path_proof_completed" and .outcome == "pass" and .runtime_lane == "real_runtime_hot_paths")' \
    "$events_path" >/dev/null; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-TRACE-MISMATCH" \
      "events.jsonl" \
      "events must use the v1 schema, match manifest ids, and include a passing real_runtime_hot_paths completion event" \
      "Regenerate events.jsonl from the wrapper so the proof state and runtime lane are auditable."
  fi

  event_runtime_lane="$(jq -s -r '[.[] | .runtime_lane // empty] | first // ""' "$events_path")"
fi

if [[ "$manifest_valid" == true && -f "$commands_path" ]]; then
  command_file_text="$(tr -d '\n' <"$commands_path")"
  if [[ "$command_file_text" != "$manifest_command" ]]; then
    emit_failure \
      "FE-REAL-HOT-PATH-CONTRACT-COMMAND-POLICY" \
      "commands.txt" \
      "commands.txt must exactly match run_manifest.json commands[0]" \
      "Keep command provenance single-sourced so the digest is stable."
  fi
fi

if [[ "$manifest_valid" == true ]]; then
  rch_log_declared="$(jq -r '.artifacts.rch_log // ""' "$manifest_path")"
  if [[ -n "$rch_log_declared" && "$rch_log_declared" != "null" ]]; then
    rch_log_path="$(resolve_path "$rch_log_declared")"
    if [[ -f "$rch_log_path" ]]; then
      if ! grep -Fq "Remote command finished: exit=0" "$rch_log_path"; then
        emit_failure \
          "FE-REAL-HOT-PATH-CONTRACT-LOG-MISMATCH" \
          "$(repo_relative_path "$rch_log_path")" \
          "rch log must include a remote exit 0 marker" \
          "Preserve the rch transcript from the accepted remote run."
      fi
      if ! grep -Fq "Selected worker:" "$rch_log_path"; then
        emit_failure \
          "FE-REAL-HOT-PATH-CONTRACT-LOG-MISMATCH" \
          "$(repo_relative_path "$rch_log_path")" \
          "rch log must include the selected worker line" \
          "Preserve the rch transcript from the accepted remote run."
      fi
      if grep -Eiq 'falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|RCH-E326|selection error: queue_timeout' "$rch_log_path"; then
        emit_failure \
          "FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY" \
          "$(repo_relative_path "$rch_log_path")" \
          "rch log contains a local-fallback marker" \
          "Discard contaminated evidence and re-run until the proof finishes remotely."
      fi
    fi
  fi
fi

target_dir_policy="unknown"
if [[ -n "$manifest_target_dir" && "$manifest_target_dir" == /tmp/* && "$manifest_target_dir" != "$root_dir"/* ]]; then
  target_dir_policy="off_repo_tmp_required"
elif [[ -n "$manifest_target_dir" ]]; then
  target_dir_policy="invalid"
fi

correctness_digest=""
if [[ "$manifest_valid" == true && "$trace_ids_valid" == true && "$events_valid" == true && -f "$commands_path" ]]; then
  digest_payload="$(
    jq -S '{
      schema_version,
      bead_id,
      component,
      mode,
      git_commit,
      trace_id,
      decision_id,
      policy_id,
      toolchain,
      cargo_target_dir,
      cargo_incremental,
      cargo_build_jobs,
      rustflags,
      rch,
      outcome,
      commands,
      artifacts
    }' "$manifest_path"
    jq -S . "$trace_ids_path"
    jq -s -S . "$events_path"
    printf '%s' "$(tr -d '\n' <"$commands_path")"
  )"
  correctness_digest="$(sha256_text "$digest_payload")"
fi

remote_execution_verified=false
if [[ "$manifest_remote_exit" == "0" &&
      "$manifest_local_fallback" == "false" &&
      -n "$manifest_worker_id" &&
      "$manifest_worker_id" != "null" ]]; then
  remote_execution_verified=true
fi

contract_summary_json="$(
  jq -n \
    --arg workload_id "${event_runtime_lane:-real_runtime_hot_paths}" \
    --arg source_revision "$manifest_source_revision" \
    --arg command "$manifest_command" \
    --arg rch_worker "$manifest_worker_id" \
    --arg target_dir_policy "$target_dir_policy" \
    --arg correctness_digest "$correctness_digest" \
    --arg outcome "$manifest_outcome" \
    --argjson remote_execution_verified "$remote_execution_verified" \
    --argjson metric_fields "$metric_fields_json" \
    '{
      workload_id: (if $workload_id == "" then null else $workload_id end),
      source_revision: (if $source_revision == "" then null else $source_revision end),
      command: (if $command == "" then null else $command end),
      rch_worker: (if $rch_worker == "" or $rch_worker == "null" then null else $rch_worker end),
      target_dir_policy: $target_dir_policy,
      correctness_digest: (if $correctness_digest == "" then null else $correctness_digest end),
      metric_fields: $metric_fields,
      proof_state: {
        outcome: (if $outcome == "" then null else $outcome end),
        remote_execution_verified: $remote_execution_verified
      }
    }'
)"

failures_json="$(jq -s 'sort_by(.code, .path, .message)' "$failures_jsonl")"
checked_artifacts_json="$(jq -s 'sort_by(.key, .path)' "$checked_artifacts_jsonl")"
failure_count="$(jq 'length' <<<"$failures_json")"
status="pass"
if [[ "$failure_count" -gt 0 ]]; then
  status="fail"
fi

jq -n \
  --arg schema_version "franken-engine.real-hot-path-proof-contract-gate.v1" \
  --arg status "$status" \
  --arg bundle_dir "$bundle_rel" \
  --arg expected_source_revision "$expected_source_revision" \
  --argjson checked_artifacts "$checked_artifacts_json" \
  --argjson failure_count "$failure_count" \
  --argjson failures "$failures_json" \
  --argjson contract "$contract_summary_json" \
  '{
    schema_version: $schema_version,
    status: $status,
    bundle_dir: $bundle_dir,
    expected_source_revision: (if $expected_source_revision == "" then null else $expected_source_revision end),
    failure_count: $failure_count,
    checked_artifacts: $checked_artifacts,
    contract: $contract,
    failures: $failures,
    remediation: [
      "Use scripts/run_real_hot_path_proof.sh to generate the bundle.",
      "Keep all manifest-declared artifacts with the bundle before publishing proof evidence.",
      "Reject stale source revisions and any rch local-fallback contamination."
    ]
  }' >"$diagnostics_path"

{
  printf '# Real Hot Path Proof Contract Gate\n\n'
  printf 'status: %s\n' "$status"
  printf 'bundle: %s\n' "$bundle_rel"
  printf 'failure_count: %s\n' "$failure_count"
  printf 'correctness_digest: %s\n\n' "${correctness_digest:-<unavailable>}"
  printf '## Contract Summary\n\n'
  jq -r '.contract | to_entries[] | "- \(.key): \(.value | @json)"' "$diagnostics_path"
  printf '\n## Failures\n\n'
  if [[ "$failure_count" -eq 0 ]]; then
    printf '%s\n' '- none'
  else
    jq -r '.failures[] | "- \(.code) \(.path): \(.message)\n  remediation: \(.remediation)"' "$diagnostics_path"
  fi
} >"$report_path"

if [[ "$status" != "pass" ]]; then
  printf 'real_hot_path_proof_contract_gate=%s status=fail failures=%s\n' "$diagnostics_path" "$failure_count" >&2
  exit 42
fi

printf 'real_hot_path_proof_contract_gate=%s status=pass\n' "$diagnostics_path"
