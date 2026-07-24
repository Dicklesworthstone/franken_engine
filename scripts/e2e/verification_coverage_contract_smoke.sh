#!/usr/bin/env bash
# Mock-free end-to-end smoke and adversarial drill for the verification
# coverage contract.  Every mutation is made in a new retained copy; the
# canonical evidence bundle is never edited or deleted.
set -Eeuo pipefail
set -o noclobber

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
smoke_root="${VERIFICATION_COVERAGE_CONTRACT_SMOKE_ROOT:-artifacts/verification_coverage_contract_smoke}"
smoke_dir="${smoke_root}/${timestamp}-$$"
case "$smoke_dir" in
  /*) ;;
  *) smoke_dir="${root_dir}/${smoke_dir}" ;;
esac
canonical_dir="${smoke_dir}/canonical"
reports_dir="${smoke_dir}/reports"
events_path="${smoke_dir}/smoke_events.jsonl"
gate="${root_dir}/scripts/run_verification_coverage_contract_gate.sh"
runtime_timeout_seconds="${VCC_SMOKE_RUNTIME_TIMEOUT_SECONDS:-300}"
gate_timeout_seconds="${VCC_SMOKE_GATE_TIMEOUT_SECONDS:-5400}"
seed=991827
run_id="run-vcc-smoke-${timestamp}-$$"
trace_id="trace-vcc-smoke-${timestamp}-$$"
sequence=0
first_failure=""

for required_tool in \
  bash cargo cmp cp find git grep head jq ln mkdir ps python3 rch rustc sed sha256sum \
  sleep sort tail timeout uname; do
  command -v "$required_tool" >/dev/null 2>&1 || {
    echo "missing required smoke tool: ${required_tool}" >&2
    exit 2
  }
done
[[ -f "$gate" && ! -L "$gate" ]] || {
  echo "missing public gate: ${gate}" >&2
  exit 2
}
[[ "$runtime_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  echo "VCC_SMOKE_RUNTIME_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
}
[[ "$gate_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  echo "VCC_SMOKE_GATE_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
}
if [[ -e "$smoke_dir" ]]; then
  echo "refusing to overwrite smoke prefix: ${smoke_dir}" >&2
  exit 2
fi
mkdir -p "$reports_dir"

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

redact_text() {
  sed -E \
    's/(authorization:|bearer[[:space:]]+|api_key=|apikey=|password=|secret=|token=|private_key=|--token[[:space:]]+|--password[[:space:]]+|--secret[[:space:]]+|--api-key[[:space:]]+)[^[:space:],;]+/\1<redacted>/Ig'
}

append_event() {
  local phase="$1"
  local decision="$2"
  local exit_code="$3"
  local reason="$4"
  local report_path="${5:-}"
  local report_sha=""
  local redacted_reason
  sequence=$((sequence + 1))
  redacted_reason="$(printf '%s' "$reason" | redact_text)"
  if [[ -n "$report_path" && -f "$report_path" ]]; then
    report_sha="$(sha256_file "$report_path")"
  fi
  jq -nc \
    --arg schema_version "franken-engine.verification-coverage-contract.smoke-event.v1" \
    --arg run_id "$run_id" \
    --arg trace_id "$trace_id" \
    --argjson seed "$seed" \
    --arg phase "$phase" \
    --argjson sequence "$sequence" \
    --arg decision "$decision" \
    --argjson exit_code "$exit_code" \
    --arg reason "${redacted_reason:0:768}" \
    --arg report_path "$report_path" \
    --arg report_sha "$report_sha" \
    --arg observed_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      trace_id:$trace_id,
      seed:$seed,
      attempt:1,
      phase:$phase,
      sequence:$sequence,
      decision:$decision,
      exit_code:$exit_code,
      reason:$reason,
      observed_at_utc:$observed_at_utc,
      report:(if $report_path == "" then null else {
        path:$report_path,
        sha256:(if $report_sha == "" then null else $report_sha end)
      } end)
    }' >>"$events_path"
}

fail_smoke() {
  local phase="$1"
  local exit_code="$2"
  local reason="$3"
  local report_path="${4:-}"
  if [[ -z "$first_failure" ]]; then
    first_failure="${phase}:${exit_code}"
  fi
  append_event "$phase" "fail" "$exit_code" "$reason" "$report_path"
  echo "verification coverage smoke failed at ${phase}: ${reason}" >&2
  echo "first_failure=${first_failure}" >&2
  echo "recoverable_smoke_dir=${smoke_dir}" >&2
  exit "$exit_code"
}

assert_no_jobs() {
  local phase="$1"
  if [[ -n "$(jobs -p)" ]]; then
    fail_smoke "$phase" 120 "a child process remained active after the scenario"
  fi
}

stop_live_validator() {
  local pid="$1"
  local observed_command=""
  local observed_state=""
  local attempt_index
  for ((attempt_index = 0; attempt_index < 2000; attempt_index += 1)); do
    kill -0 "$pid" 2>/dev/null || return 1
    observed_command="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    if [[ "$observed_command" == "${validator_bin} "* ]]; then
      if kill -STOP "$pid" 2>/dev/null; then
        observed_command="$(ps -p "$pid" -o args= 2>/dev/null || true)"
        observed_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
        if [[ "$observed_command" == "${validator_bin} "* \
          && "$observed_state" == *T* ]]; then
          return 0
        fi
        kill -CONT "$pid" 2>/dev/null || true
      fi
    fi
    sleep 0.001
  done
  return 1
}

wait_for_stopped_child_terminal_status() {
  local pid="$1"
  local observed_state=""
  local stop_status
  local terminal_observed=false
  local forced_kill=false
  local poll_index
  local wait_index
  stop_status=$((128 + $(kill -l STOP)))
  child_terminal_status=127
  for ((poll_index = 0; poll_index < 5000; poll_index += 1)); do
    observed_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
    if [[ -z "$observed_state" || "$observed_state" == *Z* ]]; then
      terminal_observed=true
      break
    fi
    sleep 0.001
  done
  if [[ "$terminal_observed" == false ]]; then
    forced_kill=true
    kill -KILL "$pid" 2>/dev/null || true
    for ((poll_index = 0; poll_index < 5000; poll_index += 1)); do
      observed_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
      if [[ -z "$observed_state" || "$observed_state" == *Z* ]]; then
        terminal_observed=true
        break
      fi
      sleep 0.001
    done
  fi
  if [[ "$terminal_observed" == false ]]; then
    return 1
  fi
  for ((wait_index = 0; wait_index < 3; wait_index += 1)); do
    wait "$pid"
    child_terminal_status="$?"
    if [[ "$child_terminal_status" -ne "$stop_status" ]]; then
      [[ "$forced_kill" == false ]]
      return
    fi
  done
  return 1
}

clone_bundle_except() {
  local destination="$1"
  shift
  local excluded
  local is_excluded
  local source_path
  local relative_path
  local destination_path
  mkdir "$destination"
  while IFS= read -r -d '' source_path; do
    relative_path="${source_path#"${canonical_dir}/"}"
    is_excluded=false
    for excluded in "$@"; do
      if [[ "$relative_path" == "$excluded" ]]; then
        is_excluded=true
        break
      fi
    done
    if [[ "$is_excluded" == true ]]; then
      continue
    fi
    destination_path="${destination}/${relative_path}"
    mkdir -p "${destination_path%/*}"
    cp --no-clobber --preserve=mode,timestamps "$source_path" \
      "$destination_path"
  done < <(find "$canonical_dir" -mindepth 1 -type f -print0)
}

validate_expected_rejection() {
  local scenario="$1"
  local bundle="$2"
  local expected_error_regex="$3"
  local report_path="${reports_dir}/${scenario}.report.json"
  local stderr_path="${reports_dir}/${scenario}.stderr.log"
  local status=0
  set +e
  timeout "$runtime_timeout_seconds" \
    "$validator_bin" validate-bundle --bundle "$bundle" \
    >"$report_path" 2>"$stderr_path"
  status="$?"
  set -e
  if [[ "$status" -eq 0 ]]; then
    fail_smoke "$scenario" 121 \
      "adversarial bundle was incorrectly accepted" "$report_path"
  fi
  if ! jq -se '
    length == 1
    and (.[0] | .status == "fail" and .error_count > 0)
  ' \
    "$report_path" >/dev/null; then
    fail_smoke "$scenario" 122 \
      "validator rejection did not retain a structured failing report" "$report_path"
  fi
  if ! jq -se --arg pattern "$expected_error_regex" \
    'length == 1
     and (.[0] | [.findings[].error_code] | any(test($pattern)))' \
    "$report_path" >/dev/null; then
    fail_smoke "$scenario" 123 \
      "validator report omitted expected typed error ${expected_error_regex}" \
      "$report_path"
  fi
  append_event "$scenario" "deny" "$status" \
    "mutated bundle was rejected with typed evidence" "$report_path"
}

append_event "smoke.preflight" "pass" 0 \
  "required tools and unique retained output prefix are present"

gate_stdout="${smoke_dir}/gate.stdout.log"
gate_stderr="${smoke_dir}/gate.stderr.log"
gate_status=0
set +e
VERIFICATION_COVERAGE_CONTRACT_CARGO_TARGET_BASE="/tmp/rch_target_vcc_smoke_${timestamp}_$$" \
  timeout "$gate_timeout_seconds" bash "$gate" ci "$canonical_dir" \
  >"$gate_stdout" 2>"$gate_stderr"
gate_status="$?"
set -e
if [[ "$gate_status" -ne 0 ]]; then
  fail_smoke "canonical.gate" "$gate_status" \
    "public certifying gate did not produce a passing canonical bundle" \
    "$gate_stderr"
fi
append_event "canonical.gate" "pass" 0 \
  "public gate ran locked tests, live generation/render/validation, replay, and the real provisional reference probe" \
  "$gate_stdout"

validator_bin="$(sed -n \
  's/^verification_coverage_contract_validator=//p' "$gate_stdout" | tail -n 1)"
[[ "$validator_bin" == "${canonical_dir}/verification_coverage_contract_validator" \
  && -x "$validator_bin" && ! -L "$validator_bin" ]] \
  || fail_smoke "canonical.validator" 124 \
    "gate did not expose its retained, bundle-local validator executable" "$gate_stdout"
[[ -f "${canonical_dir}/artifact_manifest.json" ]] \
  || fail_smoke "canonical.manifest" 125 \
    "canonical gate omitted artifact_manifest.json"

if ! jq -e '
  .schema_version == "franken-engine.verification-run-manifest.v2"
  and .observed_outcome == "pass"
  and .exit_code == 0
  and .first_failure == null
  and .tier_r_source_manifest == "tier_r_source_manifest.json"
  and .tier_r_build_environment == "tier_r_build_environment.json"
  and .sample_artifact == {kind:"raw_samples",path:"samples.jsonl"}
  and (.required_files | index("artifact_manifest.json") != null)
  and (.required_files | index("tier_r_source_manifest.json") != null)
  and (.required_files | index("tier_r_build_environment.json") != null)
  and (.required_files | index("verification_coverage_contract_validator") != null)
  and (.required_files | index("build.rch_diagnose.json") != null)
  and (.required_files | index("tests.rch_diagnose.json") != null)
  and (.required_files | index("minimized_seed.json") == null)
  and (.required_files == (.required_files | sort))
  and ((.required_files | length) == (.required_files | unique | length))
' "${canonical_dir}/run_manifest.json" >/dev/null; then
  fail_smoke "canonical.manifest_contract" 126 \
    "canonical run manifest does not select exactly the required raw-sample alternative"
fi
if [[ -s "${canonical_dir}/guest.stdout.log" \
  || -s "${canonical_dir}/guest.stderr.log" ]]; then
  fail_smoke "canonical.guest_isolation" 127 \
    "wrapper or structured evidence leaked into guest stdout/stderr"
fi
if [[ ! -s "${canonical_dir}/reproduction.stdout.log" \
  || ! -s "${canonical_dir}/tier_r_probe.json" \
  || ! -s "${canonical_dir}/tier_r_source_manifest.json" \
  || ! -s "${canonical_dir}/tier_r_build_environment.json" \
  || ! -s "${canonical_dir}/build.rch_diagnose.json" \
  || ! -s "${canonical_dir}/tests.rch_diagnose.json" ]]; then
  fail_smoke "canonical.guest_isolation" 128 \
    "validator, Tier-R, build-environment, or RCH-admission evidence is unexpectedly empty"
fi
source_manifest_sha="$(
  sha256_file "${canonical_dir}/tier_r_source_manifest.json"
)"
build_environment_sha="$(
  sha256_file "${canonical_dir}/tier_r_build_environment.json"
)"
if ! jq -e \
  --arg source_manifest_sha "$source_manifest_sha" \
  --arg build_environment_sha "$build_environment_sha" \
  '
    .schema_version == "franken-engine.provisional-tier-r-probe.v2"
    and .reference_source_sha256 == $source_manifest_sha
    and .build_environment_sha256 == $build_environment_sha
  ' "${canonical_dir}/tier_r_probe.json" >/dev/null; then
  fail_smoke "canonical.tier_r_bindings" 128 \
    "Tier-R report does not bind the retained source manifest and build environment"
fi
if ! jq -e \
  --arg source_manifest_sha "$source_manifest_sha" \
  --arg target "$(jq -r '.target' "${canonical_dir}/run_manifest.json")" \
  '
    .schema_version == "franken-engine.tier-r-build-environment.v1"
    and .source_manifest_sha256 == $source_manifest_sha
    and .target == $target
    and .profile == "release"
    and .opt_level == "3"
    and (.active_features | index("CARGO_FEATURE_TIER_R_PROBE") != null)
    and (.builder_identity_source
      | IN("RCH_WORKER_ID", "RCH_WORKER", "HOSTNAME"))
    and (.builder_identity_sha256 | type == "string" and length == 64)
  ' "${canonical_dir}/tier_r_build_environment.json" >/dev/null; then
  fail_smoke "canonical.tier_r_build_environment" 128 \
    "Tier-R build environment is not a typed source/target/profile/builder binding"
fi
if ! jq -e \
  --arg build_environment_sha "$build_environment_sha" \
  '.tier_r_build_environment_sha256 == $build_environment_sha' \
  "${canonical_dir}/repro.lock" >/dev/null; then
  fail_smoke "canonical.repro_lock" 128 \
    "repro.lock does not bind the retained Tier-R build environment"
fi
if ! jq -e '
  .schema_version == "franken-engine.verification-environment.v2"
  and .toolchain_role == "local_orchestrator"
' "${canonical_dir}/env.json" >/dev/null; then
  fail_smoke "canonical.environment" 128 \
    "environment manifest does not distinguish the local orchestrator toolchain"
fi
for admission_report in build.rch_diagnose.json tests.rch_diagnose.json; do
  if ! jq -e '
    .api_version == "1.0"
    and .command == "diagnose"
    and .success == true
    and .data.classification.is_compilation == true
    and .data.decision.would_intercept == true
    and (.data.worker_selection.worker.id | type == "string" and length > 0)
  ' "${canonical_dir}/${admission_report}" >/dev/null; then
    fail_smoke "canonical.rch_admission" 128 \
      "${admission_report} does not retain a typed eligible-worker admission decision"
  fi
done
if ! grep -Eq 'CARGO_TARGET_DIR=[^[:space:]]*_build_[^[:space:]]+[[:space:]].*cargo[[:space:]]+build' \
  "${canonical_dir}/commands.txt" \
  || ! grep -Eq 'CARGO_TARGET_DIR=[^[:space:]]*_test_[^[:space:]]+[[:space:]].*cargo[[:space:]]+test' \
    "${canonical_dir}/commands.txt"; then
  fail_smoke "canonical.target_isolation" 128 \
    "recorded build and test commands do not use distinct role-qualified Cargo target directories"
fi
if ! jq -e --arg validator_sha "$(sha256_file "$validator_bin")" '
  .files
  | any(
      .path == "verification_coverage_contract_validator"
      and .sha256 == $validator_sha
      and .bytes > 0
    )
' "${canonical_dir}/artifact_manifest.json" >/dev/null; then
  fail_smoke "canonical.validator_binding" 128 \
    "artifact manifest does not hash-bind the retained validator executable"
fi
append_event "canonical.guest_isolation" "pass" 0 \
  "empty guest streams are isolated from typed validator, RCH-admission, source, and build-environment evidence"

canonical_report="${reports_dir}/canonical.report.json"
canonical_stderr="${reports_dir}/canonical.stderr.log"
if ! timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate-bundle --bundle "$canonical_dir" \
  >"$canonical_report" 2>"$canonical_stderr"; then
  fail_smoke "canonical.revalidate" 129 \
    "canonical bundle failed an independent post-gate validation" \
    "$canonical_report"
fi
jq -se '
  length == 1
  and (.[0] | .status == "pass" and .error_count == 0 and .event_count > 1)
' \
  "$canonical_report" >/dev/null \
  || fail_smoke "canonical.revalidate" 130 \
    "canonical bundle report was not a nonempty pass" "$canonical_report"
append_event "canonical.revalidate" "pass" 0 \
  "canonical bundle independently revalidated" "$canonical_report"

baseline_hashes="${smoke_dir}/canonical.before.sha256"
(
  cd "$canonical_dir"
  find . -mindepth 1 -type f -print0 \
    | LC_ALL=C sort -z \
    | while IFS= read -r -d '' path; do
        sha256sum "$path"
      done
) >"$baseline_hashes"

# Exercise the CLI's alternate no-replace --output envelope path.
output_envelope="${smoke_dir}/validation-output-envelope.json"
output_stderr="${reports_dir}/validation-output.stderr.log"
if ! timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate \
    --repo-root "$root_dir" \
    --contract docs/verification_coverage_contract_v1.json \
    --output "$output_envelope" \
    --run-id "${run_id}-output" \
    --trace-id "${trace_id}-output" \
    --test-id verification-coverage-contract-smoke \
    --scenario-id output-envelope \
    --seed "$seed" \
    --attempt 1 \
    --platform "$(uname -s)-$(uname -m)" \
    --target "$(rustc -vV | sed -n 's/^host: //p')" \
    --tier verification-control-plane \
    --profile evidence-on \
    >"${reports_dir}/validation-output.stdout.log" 2>"$output_stderr"; then
  fail_smoke "cli.output_envelope" 131 \
    "CLI --output validation failed" "$output_stderr"
fi
jq -se '
  length == 1
  and (.[0] |
    (keys | sort) == ["events","report"]
    and .report.status == "pass"
    and (.events | length > 1)
  )
' "$output_envelope" >/dev/null \
  || fail_smoke "cli.output_envelope" 132 \
    "CLI --output did not retain one report/events envelope" "$output_envelope"
output_envelope_sha="$(sha256_file "$output_envelope")"
set +e
timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate \
    --repo-root "$root_dir" \
    --contract docs/verification_coverage_contract_v1.json \
    --output "$output_envelope" \
    --run-id "${run_id}-output" \
    --trace-id "${trace_id}-output" \
    --test-id verification-coverage-contract-smoke \
    --scenario-id output-envelope \
    --seed "$seed" \
    --attempt 1 \
    --platform "$(uname -s)-$(uname -m)" \
    --target "$(rustc -vV | sed -n 's/^host: //p')" \
    --tier verification-control-plane \
    --profile evidence-on \
    >"${reports_dir}/validation-output-repeat.stdout.log" \
    2>"${reports_dir}/validation-output-repeat.stderr.log"
output_repeat_status="$?"
set -e
if [[ "$output_repeat_status" -eq 0 \
  || "$(sha256_file "$output_envelope")" != "$output_envelope_sha" ]]; then
  fail_smoke "cli.output_no_replace" 133 \
    "second --output invocation did not fail closed while preserving the first envelope"
fi
append_event "cli.output_no_replace" "deny" "$output_repeat_status" \
  "CLI refused to replace an existing report/events envelope"

missing_dir="${smoke_dir}/mutation-missing-artifact"
clone_bundle_except "$missing_dir" "events.jsonl"
validate_expected_rejection \
  "mutation.missing_artifact" "$missing_dir" 'FE-VCC-1022'

truncated_dir="${smoke_dir}/mutation-truncated-events"
clone_bundle_except "$truncated_dir" "events.jsonl"
head -c 97 "${canonical_dir}/events.jsonl" >"${truncated_dir}/events.jsonl"
validate_expected_rejection \
  "mutation.truncated_events" "$truncated_dir" 'FE-VCC-(1008|1012)'

secret_dir="${smoke_dir}/mutation-secret"
clone_bundle_except "$secret_dir" "guest.stderr.log"
printf 'api_key=smoke-canary-not-a-credential\n' >"${secret_dir}/guest.stderr.log"
validate_expected_rejection \
  "mutation.secret" "$secret_dir" 'FE-VCC-1014'

symlink_dir="${smoke_dir}/mutation-symlink"
clone_bundle_except "$symlink_dir"
ln -s "../canonical/contract.json" "${symlink_dir}/unsafe-link"
validate_expected_rejection \
  "mutation.symlink" "$symlink_dir" 'FE-VCC-1007'

path_dir="${smoke_dir}/mutation-manifest-path"
clone_bundle_except "$path_dir" "artifact_manifest.json"
jq '.files[0].path = "../escape"' \
  "${canonical_dir}/artifact_manifest.json" \
  >"${path_dir}/artifact_manifest.json"
validate_expected_rejection \
  "mutation.manifest_path" "$path_dir" 'FE-VCC-1007'

# Recompute the outer artifact manifest after changing one retained Tier-R
# source.  Acceptance here would mean the inner build-source commitment is not
# independently enforced.
tier_source_relative="$(
  jq -er '.files[0].path' "${canonical_dir}/tier_r_source_manifest.json"
)"
tier_source_tamper_dir="${smoke_dir}/mutation-tier-r-source"
clone_bundle_except "$tier_source_tamper_dir" "artifact_manifest.json"
tier_source_tamper_path="${tier_source_tamper_dir}/tier_r_source/${tier_source_relative}"
[[ -f "$tier_source_tamper_path" && ! -L "$tier_source_tamper_path" ]] \
  || fail_smoke "mutation.tier_r_source_fixture" 134 \
    "selected retained Tier-R source is not a regular non-symlink file"
printf '\n' >>"$tier_source_tamper_path"
tier_source_manifest_stdout="${reports_dir}/tier-r-source-manifest.stdout.log"
tier_source_manifest_stderr="${reports_dir}/tier-r-source-manifest.stderr.log"
if ! timeout "$runtime_timeout_seconds" \
  "$validator_bin" artifact-manifest --bundle "$tier_source_tamper_dir" \
  >"$tier_source_manifest_stdout" 2>"$tier_source_manifest_stderr"; then
  fail_smoke "mutation.tier_r_source_fixture" 134 \
    "could not regenerate the outer manifest for the retained-source tamper" \
    "$tier_source_manifest_stderr"
fi
if ! jq -se '
  length == 1
  and (.[0] |
    .schema_version == "franken-engine.verification-artifact-manifest.v1"
    and .hash_algorithm == "sha256"
    and (.files | length > 0)
  )
' "$tier_source_manifest_stdout" >/dev/null; then
  fail_smoke "mutation.tier_r_source_fixture" 134 \
    "regenerated outer manifest did not emit one structured manifest" \
    "$tier_source_manifest_stdout"
fi
validate_expected_rejection \
  "mutation.tier_r_source" "$tier_source_tamper_dir" 'FE-VCC-1018'

# Keep the replacement build environment structurally valid and regenerate the
# outer manifest. Acceptance would prove that the probe/repro-lock inner
# commitment can be bypassed by merely rehashing the enclosing bundle.
tier_build_tamper_dir="${smoke_dir}/mutation-tier-r-build-environment"
clone_bundle_except "$tier_build_tamper_dir" \
  "artifact_manifest.json" "tier_r_build_environment.json"
jq --indent 2 '
  .builder_identity_sha256 |=
    (if startswith("0") then "1" + .[1:] else "0" + .[1:] end)
' \
  "${canonical_dir}/tier_r_build_environment.json" \
  >"${tier_build_tamper_dir}/tier_r_build_environment.json"
tier_build_manifest_stdout="${reports_dir}/tier-r-build-environment-manifest.stdout.log"
tier_build_manifest_stderr="${reports_dir}/tier-r-build-environment-manifest.stderr.log"
if ! timeout "$runtime_timeout_seconds" \
  "$validator_bin" artifact-manifest --bundle "$tier_build_tamper_dir" \
  >"$tier_build_manifest_stdout" 2>"$tier_build_manifest_stderr"; then
  fail_smoke "mutation.tier_r_build_environment_fixture" 134 \
    "could not regenerate the outer manifest for the build-environment tamper" \
    "$tier_build_manifest_stderr"
fi
if ! jq -se '
  length == 1
  and (.[0] |
    .schema_version == "franken-engine.verification-artifact-manifest.v1"
    and .hash_algorithm == "sha256"
    and (.files | length > 0)
  )
' "$tier_build_manifest_stdout" >/dev/null; then
  fail_smoke "mutation.tier_r_build_environment_fixture" 134 \
    "regenerated build-environment outer manifest was not one typed manifest" \
    "$tier_build_manifest_stdout"
fi
validate_expected_rejection \
  "mutation.tier_r_build_environment" "$tier_build_tamper_dir" 'FE-VCC-1018'

# The manifest command itself must refuse a second publication without changing
# the first manifest.
manifest_before="$(sha256_file "${canonical_dir}/artifact_manifest.json")"
set +e
timeout "$runtime_timeout_seconds" \
  "$validator_bin" artifact-manifest --bundle "$canonical_dir" \
  >"${reports_dir}/manifest-repeat.stdout.log" \
  2>"${reports_dir}/manifest-repeat.stderr.log"
manifest_repeat_status="$?"
set -e
if [[ "$manifest_repeat_status" -eq 0 \
  || "$(sha256_file "${canonical_dir}/artifact_manifest.json")" != "$manifest_before" ]]; then
  fail_smoke "publication.no_replace" 134 \
    "artifact-manifest repeat did not fail closed while preserving the first manifest"
fi
append_event "publication.no_replace" "deny" "$manifest_repeat_status" \
  "second manifest publication was rejected and the first manifest remained byte-identical"

# Exercise a real RCH local-execution decision with a non-compilation Cargo
# command, then prove the same detector used by the gate refuses that log.
fallback_log="${reports_dir}/rch-local-execution.log"
set +e
RCH_NO_SELF_HEALING=1 \
  RCH_FORCE_REMOTE=1 \
  RCH_LOG_LEVEL=info \
  RCH_LOG_FORMAT=compact \
  RCH_VISIBILITY=verbose \
  timeout 30 rch --no-self-healing exec -- \
    cargo metadata --locked \
      --manifest-path tools/execution-truth-ledger/Cargo.toml \
      --no-deps --format-version 1 \
  >"$fallback_log" 2>&1
fallback_command_status="$?"
set -e
set +e
bash "$gate" audit-rch-log "$fallback_log" \
  >"${reports_dir}/rch-fallback-audit.stdout.log" \
  2>"${reports_dir}/rch-fallback-audit.stderr.log"
fallback_audit_status="$?"
set -e
if [[ "$fallback_command_status" -ne 0 ]]; then
  fail_smoke "rch.silent_fallback_fixture" 135 \
    "real RCH local-execution probe did not complete" "$fallback_log"
fi
if [[ "$fallback_audit_status" -eq 0 ]]; then
  fail_smoke "rch.silent_fallback" 136 \
    "gate failed to reject real RCH output that executed a non-compilation Cargo command locally" \
    "$fallback_log"
fi
append_event "rch.silent_fallback" "deny" "$fallback_audit_status" \
  "gate rejected an actual RCH local-execution decision instead of silently accepting it" \
  "$fallback_log"

process_argv=(
  "$validator_bin" validate
  --repo-root "$root_dir"
  --contract docs/verification_coverage_contract_v1.json
  --run-id "${run_id}-signal"
  --trace-id "${trace_id}-signal"
  --test-id verification-coverage-contract-smoke
  --scenario-id signal-lifecycle
  --seed "$seed"
  --attempt 1
  --platform "$(uname -s)-$(uname -m)"
  --target "$(rustc -vV | sed -n 's/^host: //p')"
  --tier verification-control-plane
  --profile evidence-on
)

set +e
"${process_argv[@]}" \
  >"${reports_dir}/cancel.stdout.log" \
  2>"${reports_dir}/cancel.stderr.log" &
cancel_pid="$!"
if ! stop_live_validator "$cancel_pid"; then
  kill -KILL "$cancel_pid" 2>/dev/null
  wait "$cancel_pid" 2>/dev/null
  set -e
  fail_smoke "lifecycle.cancel.precondition" 137 \
    "could not prove the live process was the validator executable before TERM"
fi
term_signal_status=0
continue_status=0
kill -TERM "$cancel_pid" 2>/dev/null || term_signal_status="$?"
kill -CONT "$cancel_pid" 2>/dev/null || continue_status="$?"
wait_terminal_status=0
wait_for_stopped_child_terminal_status "$cancel_pid" \
  || wait_terminal_status="$?"
cancel_status="$child_terminal_status"
set -e
if [[ "$term_signal_status" -ne 0 || "$continue_status" -ne 0 \
  || "$wait_terminal_status" -ne 0 || "$cancel_status" -ne 143 ]]; then
  fail_smoke "lifecycle.cancel" 137 \
    "TERM lifecycle returned signal=${term_signal_status}, continue=${continue_status}, wait_helper=${wait_terminal_status}, wait=${cancel_status}; expected 0, 0, 0, 143"
fi
assert_no_jobs "lifecycle.cancel.cleanup"
append_event "lifecycle.cancel" "cancel" "$cancel_status" \
  "real validator process observed TERM and was reaped without an orphan"

set +e
"${process_argv[@]}" \
  >"${reports_dir}/crash.stdout.log" \
  2>"${reports_dir}/crash.stderr.log" &
crash_pid="$!"
if ! stop_live_validator "$crash_pid"; then
  kill -KILL "$crash_pid" 2>/dev/null
  wait "$crash_pid" 2>/dev/null
  set -e
  fail_smoke "lifecycle.crash.precondition" 138 \
    "could not prove the live process was the validator executable before KILL"
fi
kill_signal_status=0
kill -KILL "$crash_pid" 2>/dev/null || kill_signal_status="$?"
wait_terminal_status=0
wait_for_stopped_child_terminal_status "$crash_pid" \
  || wait_terminal_status="$?"
crash_status="$child_terminal_status"
set -e
if [[ "$kill_signal_status" -ne 0 || "$wait_terminal_status" -ne 0 \
  || "$crash_status" -ne 137 ]]; then
  fail_smoke "lifecycle.crash" 138 \
    "KILL lifecycle returned signal=${kill_signal_status}, wait_helper=${wait_terminal_status}, wait=${crash_status}; expected 0, 0, 137"
fi
assert_no_jobs "lifecycle.crash.cleanup"
append_event "lifecycle.crash" "crash" "$crash_status" \
  "real validator process observed KILL and was reaped without an orphan"

after_hashes="${smoke_dir}/canonical.after.sha256"
(
  cd "$canonical_dir"
  find . -mindepth 1 -type f -print0 \
    | LC_ALL=C sort -z \
    | while IFS= read -r -d '' path; do
        sha256sum "$path"
      done
) >"$after_hashes"
if ! cmp -s "$baseline_hashes" "$after_hashes"; then
  fail_smoke "rollback.canonical" 139 \
    "adversarial drills changed the canonical evidence bundle"
fi
assert_no_jobs "cleanup.final"
append_event "rollback.canonical" "rollback" 0 \
  "all adversarial copies are retained, the canonical bundle is byte-identical, and no child process remains"

final_report="${reports_dir}/canonical.final.report.json"
if ! timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate-bundle --bundle "$canonical_dir" \
  >"$final_report" 2>"${reports_dir}/canonical.final.stderr.log"; then
  fail_smoke "canonical.final" 140 \
    "canonical bundle no longer validates after adversarial drills" "$final_report"
fi
jq -se '
  length == 1
  and (.[0] | .status == "pass" and .error_count == 0)
' "$final_report" >/dev/null \
  || fail_smoke "canonical.final" 141 \
    "final canonical validation report was not a pass" "$final_report"
append_event "canonical.final" "pass" 0 \
  "canonical evidence remains valid after all fault, denial, lifecycle, and rollback scenarios" \
  "$final_report"

echo "verification_coverage_contract_smoke_dir=${smoke_dir}"
echo "verification_coverage_contract_smoke_events=${events_path}"
echo "verification_coverage_contract_canonical_bundle=${canonical_dir}"
echo "verification_coverage_contract_smoke_verdict=pass"
