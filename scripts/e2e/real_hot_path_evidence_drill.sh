#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-smoke}"
case "$mode" in
  smoke) ;;
  *)
    printf 'usage: %s [smoke]\n' "$0" >&2
    exit 64
    ;;
esac

wrapper="${root_dir}/scripts/run_real_hot_path_proof.sh"
gate="${root_dir}/scripts/real_hot_path_proof_contract_gate.sh"
artifact_root="${REAL_HOT_PATH_EVIDENCE_DRILL_ARTIFACT_ROOT:-artifacts/real_hot_path_evidence_drill}"
run_id="${REAL_HOT_PATH_EVIDENCE_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

if [[ "$artifact_root" = /* ]]; then
  run_dir="${artifact_root}/${run_id}"
else
  run_dir="${root_dir}/${artifact_root}/${run_id}"
fi

logs_dir="${run_dir}/logs"
positive_dir="${run_dir}/positive"
negative_dir="${run_dir}/negative"
proof_root="${run_dir}/proof_bundles"
mkdir -p "$logs_dir" "$positive_dir" "$negative_dir" "$proof_root"

case_results_path="${run_dir}/case_results.jsonl"
artifact_digests_path="${run_dir}/artifact_digests.json"
summary_json_path="${run_dir}/summary.json"
summary_md_path="${run_dir}/summary.md"
rch_summary_path="${logs_dir}/rch_summary.log"
: >"$case_results_path"

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s is required for the real hot-path evidence drill\n' "$tool" >&2
    exit 2
  fi
}

require_tool awk
require_tool cp
require_tool find
require_tool jq
require_tool realpath
require_tool sed

if command -v sha256sum >/dev/null 2>&1; then
  sha256_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  sha256_cmd=(shasum -a 256)
else
  sha256_cmd=(openssl dgst -sha256)
fi

sha256_file() {
  local path="$1"
  "${sha256_cmd[@]}" "$path" | awk '{print $1}'
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

record_case() {
  local name="$1"
  local status="$2"
  local expected="$3"
  local diagnostics="$4"
  local stdout_log="$5"
  local stderr_log="$6"

  jq -nc \
    --arg name "$name" \
    --arg status "$status" \
    --arg expected "$expected" \
    --arg diagnostics "$(repo_relative_path "$diagnostics")" \
    --arg stdout_log "$(repo_relative_path "$stdout_log")" \
    --arg stderr_log "$(repo_relative_path "$stderr_log")" \
    '{
      name: $name,
      status: $status,
      expected: $expected,
      diagnostics: $diagnostics,
      stdout_log: $stdout_log,
      stderr_log: $stderr_log
    }' >>"$case_results_path"
}

write_failure_summary() {
  local message="$1"
  jq -n \
    --arg schema_version "franken-engine.real-hot-path-evidence-drill.v1" \
    --arg status "fail" \
    --arg message "$message" \
    --arg run_dir "$(repo_relative_path "$run_dir")" \
    '{
      schema_version: $schema_version,
      status: $status,
      failure_reason: $message,
      run_dir: $run_dir
    }' >"$summary_json_path"
  printf 'real_hot_path_evidence_drill=%s status=fail reason=%s\n' "$summary_json_path" "$message" >&2
}

fail() {
  local message="$1"
  write_failure_summary "$message"
  exit 1
}

run_gate() {
  local bundle_dir="$1"
  local output_dir="$2"
  local source_revision="$3"
  local stdout_log="$4"
  local stderr_log="$5"
  local exit_code

  mkdir -p "$output_dir"
  set +e
  "$gate" \
    --bundle-dir "$bundle_dir" \
    --output-dir "$output_dir" \
    --source-revision "$source_revision" >"$stdout_log" 2>"$stderr_log"
  exit_code=$?
  set -e
  return "$exit_code"
}

copy_bundle() {
  local source_dir="$1"
  local destination_dir="$2"

  mkdir -p "$destination_dir"
  cp -a "${source_dir}/." "$destination_dir/"
}

assert_diagnostics_failure() {
  local diagnostics="$1"
  local expected_code="$2"

  jq -e --arg expected_code "$expected_code" '
    .status == "fail"
    and .failure_count >= 1
    and (.failures | map(.code) | index($expected_code) != null)
  ' "$diagnostics" >/dev/null
}

run_negative_gate_case() {
  local name="$1"
  local bundle_dir="$2"
  local source_revision="$3"
  local expected_code="$4"
  local output_dir="${negative_dir}/${name}-output"
  local stdout_log="${logs_dir}/${name}.stdout.log"
  local stderr_log="${logs_dir}/${name}.stderr.log"
  local exit_code

  if run_gate "$bundle_dir" "$output_dir" "$source_revision" "$stdout_log" "$stderr_log"; then
    exit_code=0
  else
    exit_code=$?
  fi

  if [[ "$exit_code" -ne 42 ]]; then
    record_case "$name" "fail" "$expected_code" "${output_dir}/diagnostics.json" "$stdout_log" "$stderr_log"
    fail "negative case ${name} exited ${exit_code}; expected contract failure 42"
  fi

  if ! assert_diagnostics_failure "${output_dir}/diagnostics.json" "$expected_code"; then
    record_case "$name" "fail" "$expected_code" "${output_dir}/diagnostics.json" "$stdout_log" "$stderr_log"
    fail "negative case ${name} did not report ${expected_code}"
  fi

  record_case "$name" "pass" "$expected_code" "${output_dir}/diagnostics.json" "$stdout_log" "$stderr_log"
}

write_artifact_digests() {
  local bundle_dir="$1"
  local digest_jsonl="${run_dir}/artifact_digests.jsonl"
  : >"$digest_jsonl"

  while IFS= read -r path; do
    jq -nc \
      --arg path "$(repo_relative_path "$path")" \
      --arg sha256 "$(sha256_file "$path")" \
      --argjson bytes "$(wc -c <"$path")" \
      '{path: $path, sha256: $sha256, bytes: $bytes}' >>"$digest_jsonl"
  done < <(find "$bundle_dir" -type f | sort)

  jq -s . "$digest_jsonl" >"$artifact_digests_path"
}

write_rch_summary() {
  local wrapper_stdout="$1"
  local rch_log="$2"

  {
    grep -E '^\[RCH\]|Selected worker:|Remote command finished:' "$wrapper_stdout" || true
    if [[ -f "$rch_log" ]]; then
      grep -E '^\[RCH\]|Selected worker:|Remote command finished:' "$rch_log" || true
    fi
  } | awk '!seen[$0]++' >"$rch_summary_path"
}

bundle_contains_forbidden_markers() {
  local bundle_dir="$1"
  local candidate

  while IFS= read -r candidate; do
    if grep -Eiq 'hot_paths_simulation|MockCertificate|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|RCH-E326|selection error: queue_timeout' "$candidate"; then
      return 0
    fi
  done < <(
    find "$bundle_dir" -type f \
      \( -name "*.json" -o -name "*.jsonl" -o -name "*.md" -o -name "*.txt" -o -name "*.log" \) \
      | sort
  )

  return 1
}

write_success_summary() {
  local bundle_dir="$1"
  local manifest_path="$2"
  local diagnostics_path="$3"
  local report_path="$4"
  local source_revision="$5"
  local correctness_digest="$6"
  local cases_json

  cases_json="$(jq -s . "$case_results_path")"

  jq -n \
    --arg schema_version "franken-engine.real-hot-path-evidence-drill.v1" \
    --arg status "pass" \
    --arg run_dir "$(repo_relative_path "$run_dir")" \
    --arg proof_bundle "$(repo_relative_path "$bundle_dir")" \
    --arg source_revision "$source_revision" \
    --arg manifest "$(repo_relative_path "$manifest_path")" \
    --arg diagnostics "$(repo_relative_path "$diagnostics_path")" \
    --arg report "$(repo_relative_path "$report_path")" \
    --arg artifact_digests "$(repo_relative_path "$artifact_digests_path")" \
    --arg rch_summary "$(repo_relative_path "$rch_summary_path")" \
    --arg correctness_digest "$correctness_digest" \
    --argjson cases "$cases_json" \
    '{
      schema_version: $schema_version,
      status: $status,
      run_dir: $run_dir,
      proof_bundle: $proof_bundle,
      source_revision: $source_revision,
      manifest: $manifest,
      contract_gate: {
        diagnostics: $diagnostics,
        report: $report,
        correctness_digest: $correctness_digest
      },
      artifact_digests: $artifact_digests,
      rch_summary: $rch_summary,
      negative_cases: $cases
    }' >"$summary_json_path"

  {
    printf '# Real Hot Path Evidence Drill\n\n'
    printf 'status: pass\n'
    printf 'proof_bundle: %s\n' "$(repo_relative_path "$bundle_dir")"
    printf 'source_revision: %s\n' "$source_revision"
    printf 'correctness_digest: %s\n' "$correctness_digest"
    printf 'contract_diagnostics: %s\n' "$(repo_relative_path "$diagnostics_path")"
    printf 'artifact_digests: %s\n' "$(repo_relative_path "$artifact_digests_path")"
    printf 'rch_summary: %s\n\n' "$(repo_relative_path "$rch_summary_path")"
    printf '## Replay\n\n'
    printf "1. Run \`%s smoke\`.\n" "$(repo_relative_path "$wrapper")"
    printf "2. Run \`%s --bundle-dir %s --source-revision %s\`.\n" \
      "$(repo_relative_path "$gate")" \
      "$(repo_relative_path "$bundle_dir")" \
      "$source_revision"
    printf '\n## Negative Cases\n\n'
    jq -r '.negative_cases[] | "- \(.name): \(.status) expected \(.expected)"' "$summary_json_path"
  } >"$summary_md_path"
}

wrapper_stdout="${logs_dir}/wrapper.stdout.log"
wrapper_stderr="${logs_dir}/wrapper.stderr.log"

set +e
REAL_HOT_PATH_PROOF_ARTIFACT_ROOT="$proof_root" "$wrapper" smoke >"$wrapper_stdout" 2>"$wrapper_stderr"
wrapper_exit=$?
set -e

if [[ "$wrapper_exit" -ne 0 ]]; then
  fail "real hot-path proof wrapper exited ${wrapper_exit}; see $(repo_relative_path "$wrapper_stdout")"
fi

manifest_path="$(sed -n 's/^real hot-path proof manifest: //p' "$wrapper_stdout" | tail -n 1)"
if [[ -z "$manifest_path" || ! -f "$manifest_path" ]]; then
  fail "wrapper did not emit a readable manifest path"
fi

bundle_dir="$(dirname "$manifest_path")"
source_revision="$(jq -r '.git_commit // empty' "$manifest_path")"
[[ -n "$source_revision" ]] || fail "manifest does not record git_commit"

positive_stdout="${logs_dir}/contract-positive.stdout.log"
positive_stderr="${logs_dir}/contract-positive.stderr.log"
if ! run_gate "$bundle_dir" "$positive_dir" "$source_revision" "$positive_stdout" "$positive_stderr"; then
  fail "contract gate rejected the live proof bundle; see $(repo_relative_path "$positive_stderr")"
fi

positive_diagnostics="${positive_dir}/diagnostics.json"
positive_report="${positive_dir}/report.md"

jq -e '
  .status == "pass"
  and .contract.workload_id == "real_runtime_hot_paths"
  and .contract.proof_state.remote_execution_verified == true
  and (.contract.rch_worker | type == "string" and length > 0)
  and .contract.target_dir_policy == "off_repo_tmp_required"
  and (.contract.correctness_digest | type == "string" and length == 64)
' "$positive_diagnostics" >/dev/null || fail "contract diagnostics did not prove remote real_runtime_hot_paths execution"

jq -e '
  .mode == "smoke"
  and .outcome == "pass"
  and .rch.local_fallback_detected == false
  and .rch.remote_exit_code == 0
  and (.rch.selected_worker.id | type == "string" and length > 0)
  and (.commands[0] | contains("rch exec --") and contains("--bench hot_paths"))
' "$manifest_path" >/dev/null || fail "run manifest does not prove the expected rch hot_paths smoke command"

events_path="$(jq -r '.artifacts.events // empty' "$manifest_path")"
rch_log_path="$(jq -r '.artifacts.rch_log // empty' "$manifest_path")"
step_log_path="$(jq -r '.artifacts.first_step_log // empty' "$manifest_path")"
[[ -f "$events_path" ]] || fail "events artifact is missing"
[[ -f "$rch_log_path" ]] || fail "rch log artifact is missing"
[[ -f "$step_log_path" ]] || fail "step log artifact is missing"

jq -s -e '
  any(.[]; .event == "real_hot_path_proof_completed"
    and .outcome == "pass"
    and .runtime_lane == "real_runtime_hot_paths")
' "$events_path" >/dev/null || fail "events do not include a passing real_runtime_hot_paths completion"

grep -Fq "Selected worker:" "$rch_log_path" || fail "rch log does not name the selected worker"
grep -Fq "Remote command finished: exit=0" "$rch_log_path" || fail "rch log does not contain remote exit 0"
if bundle_contains_forbidden_markers "$bundle_dir"; then
  fail "live proof bundle contains synthetic or local-fallback contamination"
fi

write_artifact_digests "$bundle_dir"
write_rch_summary "$wrapper_stdout" "$rch_log_path"

missing_worker_bundle="${negative_dir}/missing-worker-proof-bundle"
copy_bundle "$bundle_dir" "$missing_worker_bundle"
jq '.rch.selected_worker.id = null' "${missing_worker_bundle}/run_manifest.json" >"${missing_worker_bundle}/run_manifest.json.tmp"
mv "${missing_worker_bundle}/run_manifest.json.tmp" "${missing_worker_bundle}/run_manifest.json"
run_negative_gate_case \
  "missing-worker-proof" \
  "$missing_worker_bundle" \
  "$source_revision" \
  "FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY"

malformed_bundle="${negative_dir}/malformed-output-bundle"
copy_bundle "$bundle_dir" "$malformed_bundle"
printf '{not valid json\n' >"${malformed_bundle}/run_manifest.json"
run_negative_gate_case \
  "malformed-output" \
  "$malformed_bundle" \
  "$source_revision" \
  "FE-REAL-HOT-PATH-CONTRACT-MALFORMED-MANIFEST"

run_negative_gate_case \
  "stale-source-revision" \
  "$bundle_dir" \
  "stale-source-${run_id}" \
  "FE-REAL-HOT-PATH-CONTRACT-STALE-SOURCE-REVISION"

synthetic_bundle="${negative_dir}/synthetic-contamination-bundle"
copy_bundle "$bundle_dir" "$synthetic_bundle"
printf '{"benchmark_group":"hot_paths_simulation","certificate_fixture":"MockCertificate"}\n' >"${synthetic_bundle}/synthetic_contamination.json"
run_negative_gate_case \
  "synthetic-contamination" \
  "$synthetic_bundle" \
  "$source_revision" \
  "FE-REAL-HOT-PATH-CONTRACT-SYNTHETIC-CONTAMINATION"

correctness_digest="$(jq -r '.contract.correctness_digest' "$positive_diagnostics")"
write_success_summary \
  "$bundle_dir" \
  "$manifest_path" \
  "$positive_diagnostics" \
  "$positive_report" \
  "$source_revision" \
  "$correctness_digest"

printf 'real_hot_path_evidence_drill=%s status=pass\n' "$summary_json_path"
