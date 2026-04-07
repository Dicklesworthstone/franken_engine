#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

bead_id="bd-6a61n.7"
component="pipeline_integration_verification"
trace_id="trace-pipeline-integration-verification"
decision_id="decision-pipeline-integration-verification"
policy_id="policy-pipeline-integration-verification"
toolchain="${RUSTUP_TOOLCHAIN:-nightly-x86_64-unknown-linux-gnu}"
case "${toolchain}" in
  *-x86_64-unknown-linux-gnu)
    toolchain_bin_dir="${RUSTUP_HOME:-${HOME}/.rustup}/toolchains/${toolchain}/bin"
    ;;
  *)
    toolchain_bin_dir="${RUSTUP_HOME:-${HOME}/.rustup}/toolchains/${toolchain}-x86_64-unknown-linux-gnu/bin"
    ;;
esac
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_pipeline_integration_verification_$$}"
artifact_root_input="${PIPELINE_INTEGRATION_VERIFICATION_ARTIFACT_ROOT:-artifacts/pipeline_integration_verification}"

if [[ "${artifact_root_input}" = /* ]]; then
  artifact_root="${artifact_root_input}"
else
  artifact_root="${root_dir}/${artifact_root_input}"
fi

run_dir="${artifact_root}/${timestamp}"
specimens_dir="${run_dir}/specimens"
reports_dir="${run_dir}/reports"
step_logs_dir="${run_dir}/step_logs"
jsonl_log_path="${run_dir}/pipeline_verification.jsonl"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_path="${run_dir}/pipeline_verification_report.json"
summary_path="${run_dir}/summary.md"

mkdir -p "${run_dir}" "${specimens_dir}" "${reports_dir}" "${step_logs_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for pipeline integration verification" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for pipeline integration verification" >&2
  exit 2
fi

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "${remote_exit_line}" ]]; then
    return 1
  fi

  printf '%s\n' "${remote_exit_line##*=}"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    return 1
  fi
}

extract_json_report_from_step_log() {
  local log_path="$1"
  local report_path="$2"
  local stripped_log
  local extracted_json

  stripped_log="$(mktemp)"
  extracted_json="$(mktemp)"
  rch_strip_ansi "${log_path}" >"${stripped_log}"

  awk '
    function count_open(line, tmp) {
      tmp = line
      return gsub(/\{/, "", tmp)
    }

    function count_close(line, tmp) {
      tmp = line
      return gsub(/\}/, "", tmp)
    }

    {
      if (!capturing && $0 ~ /^[[:space:]]*\{[[:space:]]*$/) {
        capturing = 1
        depth = 0
      }

      if (!capturing) {
        next
      }

      print
      depth += count_open($0) - count_close($0)
      if (depth == 0) {
        exit
      }
    }
  ' "${stripped_log}" >"${extracted_json}"

  rm -f "${stripped_log}"

  if [[ -s "${extracted_json}" ]] && jq -e . "${extracted_json}" >/dev/null 2>&1; then
    mv "${extracted_json}" "${report_path}"
    return 0
  fi

  rm -f "${extracted_json}"
  return 1
}

step_index=0
pass_count=0
fail_count=0
error_count=0
declare -a commands_run=()
declare -a failed_tests=()
declare -a errored_tests=()

cat >"${jsonl_log_path}" <<EOF
{"suite":"pipeline_verification","schema_version":"franken-engine.pipeline-integration-verification.log.v1","bead_id":"${bead_id}","started":"$(date -Iseconds)","component":"${component}"}
EOF

jq -nc \
  --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg component "${component}" \
  --arg bead_id "${bead_id}" \
  --arg started_at "$(date -Iseconds)" \
  '{
    schema_version: $schema_version,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component,
    bead_id: $bead_id,
    event: "suite_started",
    outcome: "running",
    started_at: $started_at
  }' >"${events_path}"
printf '\n' >>"${events_path}"

tests_json="$(cat <<'JSON'
[
  {
    "name": "arithmetic",
    "expected_contains": "42",
    "source": "const x = 40 + 2; x;"
  },
  {
    "name": "let_const",
    "expected_contains": "3",
    "source": "let x = 1; const y = 2; x + y;"
  },
  {
    "name": "function_call",
    "expected_contains": "7",
    "source": "function add(a, b) { return a + b; } add(3, 4);"
  },
  {
    "name": "arrow_fn",
    "expected_contains": "11",
    "source": "const add = (a, b) => a + b; add(5, 6);"
  },
  {
    "name": "closure",
    "expected_contains": "10",
    "source": "function outer() { let x = 10; return function() { return x; }; } outer()();"
  },
  {
    "name": "closure_mutation",
    "expected_contains": "3",
    "source": "function counter() { let n = 0; return function() { n += 1; return n; }; } const inc = counter(); inc(); inc(); inc();"
  },
  {
    "name": "destructure_obj",
    "expected_contains": "3",
    "source": "const { a, b } = { a: 1, b: 2 }; a + b;"
  },
  {
    "name": "destructure_arr",
    "expected_contains": "60",
    "source": "const [x, y, z] = [10, 20, 30]; x + y + z;"
  },
  {
    "name": "template_literal",
    "expected_contains": "hello world",
    "source": "const name = 'world'; `hello ${name}`;"
  },
  {
    "name": "try_catch",
    "expected_contains": "err",
    "source": "let r; try { throw 'err'; } catch(e) { r = e; } r;"
  },
  {
    "name": "try_finally",
    "expected_contains": "2",
    "source": "let x = 0; try { x = 1; } finally { x = 2; } x;"
  },
  {
    "name": "switch",
    "expected_contains": "b",
    "source": "let r; switch(2) { case 1: r = 'a'; break; case 2: r = 'b'; break; default: r = 'c'; } r;"
  },
  {
    "name": "for_loop",
    "expected_contains": "10",
    "source": "let s = 0; for (let i = 0; i < 5; i++) { s += i; } s;"
  },
  {
    "name": "while_loop",
    "expected_contains": "10",
    "source": "let i = 0; let s = 0; while (i < 5) { s += i; i++; } s;"
  },
  {
    "name": "for_of",
    "expected_contains": "6",
    "source": "let s = 0; for (const x of [1, 2, 3]) { s += x; } s;"
  },
  {
    "name": "optional_chain",
    "expected_contains": "42",
    "source": "const obj = { a: { b: 42 } }; obj.a?.b;"
  },
  {
    "name": "nullish_coalesce",
    "expected_contains": "42",
    "source": "const x = null ?? 42; x;"
  },
  {
    "name": "ternary",
    "expected_contains": "yes",
    "source": "const x = true ? 'yes' : 'no'; x;"
  },
  {
    "name": "array_map",
    "expected_contains": "[2,4,6]",
    "source": "[1,2,3].map(x => x * 2);"
  },
  {
    "name": "json_roundtrip",
    "expected_contains": "{a:1}",
    "source": "JSON.parse(JSON.stringify({a: 1}));"
  },
  {
    "name": "promise_resolve",
    "expected_contains": "42",
    "source": "Promise.resolve(42);"
  }
]
JSON
)"

mapfile -t test_rows < <(printf '%s\n' "${tests_json}" | jq -cr '.[]')

run_test() {
  local test_json="$1"
  local name expected_contains source specimen_path report_file step_log stdout_log command_text
  local status remote_exit_code actual_execution_value lane containment_action status_label
  local report_exists report_source error_excerpt step_log_rel stdout_log_rel report_rel specimen_rel

  name="$(jq -r '.name' <<<"${test_json}")"
  expected_contains="$(jq -r '.expected_contains' <<<"${test_json}")"
  source="$(jq -r '.source' <<<"${test_json}")"

  specimen_path="${specimens_dir}/${name}.js"
  report_file="${reports_dir}/${name}.json"
  step_log="${step_logs_dir}/step_$(printf '%03d' "${step_index}")_${name}.log"
  stdout_log="${step_logs_dir}/step_$(printf '%03d' "${step_index}")_${name}.stdout.log"
  step_index=$((step_index + 1))

  specimen_rel="specimens/${name}.js"
  report_rel="reports/${name}.json"
  step_log_rel="step_logs/$(basename "${step_log}")"
  stdout_log_rel="step_logs/$(basename "${stdout_log}")"

  printf '%s\n' "${source}" >"${specimen_path}"

  command_text="cargo run -p frankenengine-engine --bin frankenctl -- run --input ${specimen_path} --extension-id pipeline-verification-${name} --out ${report_file}"
  commands_run+=("${command_text}")

  set +e
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "PATH=${toolchain_bin_dir}:${PATH}" \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    cargo run -p frankenengine-engine --bin frankenctl -- \
    run \
    --input "${specimen_path}" \
    --extension-id "pipeline-verification-${name}" \
    --out "${report_file}" \
    > >(tee "${stdout_log}") \
    2> >(tee "${step_log}" >&2)
  status=$?
  set -e

  if ! rch_reject_local_fallback "${step_log}"; then
    status_label="error"
    error_count=$((error_count + 1))
    errored_tests+=("${name}")
    error_excerpt="$(rch_strip_ansi "${step_log}" | tail -n 40 | tr '\n' ' ' | head -c 400)"
    jq -nc \
      --arg test "${name}" \
      --arg status "${status_label}" \
      --arg expected_contains "${expected_contains}" \
      --arg error "rch reported local fallback" \
      --arg error_excerpt "${error_excerpt}" \
      --arg step_log "${step_log_rel}" \
      --arg stdout_log "${stdout_log_rel}" \
      --arg report_path "${report_rel}" \
      --arg specimen_path "${specimen_rel}" \
      --arg time "$(date -Iseconds)" \
      '{
        test: $test,
        status: $status,
        expected_contains: $expected_contains,
        error: $error,
        error_excerpt: $error_excerpt,
        step_log: $step_log,
        stdout_log: $stdout_log,
        report_path: $report_path,
        specimen_path: $specimen_path,
        time: $time
      }' >>"${jsonl_log_path}"
    printf '\n' >>"${jsonl_log_path}"

    jq -nc \
      --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
      --arg trace_id "${trace_id}" \
      --arg decision_id "${decision_id}" \
      --arg policy_id "${policy_id}" \
      --arg component "${component}" \
      --arg test "${name}" \
      --arg outcome "${status_label}" \
      --arg error_code "rch_local_fallback" \
      --arg step_log "${step_log_rel}" \
      --arg report_path "${report_rel}" \
      '{
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id,
        component: $component,
        event: "test_completed",
        test: $test,
        outcome: $outcome,
        error_code: $error_code,
        step_log: $step_log,
        report_path: $report_path
      }' >>"${events_path}"
    printf '\n' >>"${events_path}"
    return
  fi

  remote_exit_code="$(rch_remote_exit_code "${step_log}" || true)"
  if [[ "${status}" -ne 0 || -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    status_label="error"
    error_count=$((error_count + 1))
    errored_tests+=("${name}")
    error_excerpt="$(rch_strip_ansi "${step_log}" | tail -n 40 | tr '\n' ' ' | head -c 400)"
    jq -nc \
      --arg test "${name}" \
      --arg status "${status_label}" \
      --arg expected_contains "${expected_contains}" \
      --arg error "frankenctl run exited with an error" \
      --arg error_excerpt "${error_excerpt}" \
      --arg remote_exit_code "${remote_exit_code}" \
      --arg step_log "${step_log_rel}" \
      --arg stdout_log "${stdout_log_rel}" \
      --arg report_path "${report_rel}" \
      --arg specimen_path "${specimen_rel}" \
      --arg time "$(date -Iseconds)" \
      '{
        test: $test,
        status: $status,
        expected_contains: $expected_contains,
        error: $error,
        error_excerpt: $error_excerpt,
        remote_exit_code: $remote_exit_code,
        step_log: $step_log,
        stdout_log: $stdout_log,
        report_path: $report_path,
        specimen_path: $specimen_path,
        time: $time
      }' >>"${jsonl_log_path}"
    printf '\n' >>"${jsonl_log_path}"

    jq -nc \
      --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
      --arg trace_id "${trace_id}" \
      --arg decision_id "${decision_id}" \
      --arg policy_id "${policy_id}" \
      --arg component "${component}" \
      --arg test "${name}" \
      --arg outcome "${status_label}" \
      --arg error_code "run_error" \
      --arg step_log "${step_log_rel}" \
      --arg report_path "${report_rel}" \
      '{
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id,
        component: $component,
        event: "test_completed",
        test: $test,
        outcome: $outcome,
        error_code: $error_code,
        step_log: $step_log,
        report_path: $report_path
      }' >>"${events_path}"
    printf '\n' >>"${events_path}"
    return
  fi

  report_exists="false"
  report_source=""
  actual_execution_value=""
  lane=""
  containment_action=""
  if [[ -f "${report_file}" ]] && jq -e . "${report_file}" >/dev/null 2>&1; then
    report_exists="true"
    report_source="${report_rel}"
  elif [[ -f "${stdout_log}" ]] && jq -e . "${stdout_log}" >/dev/null 2>&1; then
    cp "${stdout_log}" "${report_file}"
    report_exists="true"
    report_source="${stdout_log_rel}"
  elif extract_json_report_from_step_log "${step_log}" "${report_file}"; then
    report_exists="true"
    report_source="${step_log_rel}"
  fi

  if [[ "${report_exists}" == "true" ]]; then
    actual_execution_value="$(jq -r '.execution_value // empty' "${report_file}")"
    lane="$(jq -r '.lane // empty' "${report_file}")"
    containment_action="$(jq -r '.containment_action // empty' "${report_file}")"
  fi

  if [[ "${report_exists}" != "true" ]]; then
    status_label="error"
    error_count=$((error_count + 1))
    errored_tests+=("${name}")
    error_excerpt="$(rch_strip_ansi "${step_log}" | tail -n 40 | tr '\n' ' ' | head -c 400)"
    jq -nc \
      --arg test "${name}" \
      --arg status "${status_label}" \
      --arg expected_contains "${expected_contains}" \
      --arg error "missing or invalid report json" \
      --arg error_excerpt "${error_excerpt}" \
      --arg step_log "${step_log_rel}" \
      --arg stdout_log "${stdout_log_rel}" \
      --arg report_path "${report_rel}" \
      --arg specimen_path "${specimen_rel}" \
      --arg time "$(date -Iseconds)" \
      '{
        test: $test,
        status: $status,
        expected_contains: $expected_contains,
        error: $error,
        error_excerpt: $error_excerpt,
        step_log: $step_log,
        stdout_log: $stdout_log,
        report_path: $report_path,
        specimen_path: $specimen_path,
        time: $time
      }' >>"${jsonl_log_path}"
    printf '\n' >>"${jsonl_log_path}"

    jq -nc \
      --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
      --arg trace_id "${trace_id}" \
      --arg decision_id "${decision_id}" \
      --arg policy_id "${policy_id}" \
      --arg component "${component}" \
      --arg test "${name}" \
      --arg outcome "${status_label}" \
      --arg error_code "missing_report" \
      --arg step_log "${step_log_rel}" \
      --arg report_path "${report_rel}" \
      '{
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id,
        component: $component,
        event: "test_completed",
        test: $test,
        outcome: $outcome,
        error_code: $error_code,
        step_log: $step_log,
        report_path: $report_path
      }' >>"${events_path}"
    printf '\n' >>"${events_path}"
    return
  fi

  if [[ "${actual_execution_value}" == *"${expected_contains}"* ]]; then
    status_label="pass"
    pass_count=$((pass_count + 1))
  else
    status_label="fail"
    fail_count=$((fail_count + 1))
    failed_tests+=("${name}")
  fi

  jq -nc \
    --arg test "${name}" \
    --arg status "${status_label}" \
    --arg expected_contains "${expected_contains}" \
    --arg execution_value "${actual_execution_value}" \
    --arg lane "${lane}" \
    --arg containment_action "${containment_action}" \
    --arg step_log "${step_log_rel}" \
    --arg stdout_log "${stdout_log_rel}" \
    --arg report_path "${report_rel}" \
    --arg report_source "${report_source}" \
    --arg specimen_path "${specimen_rel}" \
    --arg time "$(date -Iseconds)" \
    '{
      test: $test,
      status: $status,
      expected_contains: $expected_contains,
      execution_value: $execution_value,
      lane: $lane,
      containment_action: $containment_action,
      step_log: $step_log,
      stdout_log: $stdout_log,
      report_path: $report_path,
      report_source: $report_source,
      specimen_path: $specimen_path,
      time: $time
    }' >>"${jsonl_log_path}"
  printf '\n' >>"${jsonl_log_path}"

  jq -nc \
    --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg test "${name}" \
    --arg outcome "${status_label}" \
    --arg error_code "$([[ "${status_label}" = "fail" ]] && printf '%s' "expected_mismatch" || printf '%s' "")" \
    --arg step_log "${step_log_rel}" \
    --arg report_path "${report_rel}" \
    --arg execution_value "${actual_execution_value}" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: "test_completed",
      test: $test,
      outcome: $outcome,
      error_code: ($error_code | select(length > 0)),
      step_log: $step_log,
      report_path: $report_path,
      execution_value: $execution_value
    }' >>"${events_path}"
  printf '\n' >>"${events_path}"
}

for test_json in "${test_rows[@]}"; do
  run_test "${test_json}"
done

total_count=$((pass_count + fail_count + error_count))
overall_outcome="pass"
if [[ "${fail_count}" -gt 0 || "${error_count}" -gt 0 ]]; then
  overall_outcome="attention_required"
fi

jq -nc \
  --arg schema_version "franken-engine.pipeline-integration-verification.event.v1" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg component "${component}" \
  --arg outcome "${overall_outcome}" \
  --arg completed_at "$(date -Iseconds)" \
  --argjson pass_count "${pass_count}" \
  --argjson fail_count "${fail_count}" \
  --argjson error_count "${error_count}" \
  --argjson total_count "${total_count}" \
  '{
    schema_version: $schema_version,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component,
    event: "suite_completed",
    outcome: $outcome,
    completed_at: $completed_at,
    summary: {
      pass: $pass_count,
      fail: $fail_count,
      error: $error_count,
      total: $total_count
    }
  }' >>"${events_path}"
printf '\n' >>"${events_path}"

jq -nc \
  --arg summary_status "${overall_outcome}" \
  --arg time "$(date -Iseconds)" \
  --argjson pass_count "${pass_count}" \
  --argjson fail_count "${fail_count}" \
  --argjson error_count "${error_count}" \
  --argjson total_count "${total_count}" \
  '{
    summary: {
      status: $summary_status,
      pass: $pass_count,
      fail: $fail_count,
      error: $error_count,
      total: $total_count
    },
    time: $time
  }' >>"${jsonl_log_path}"
printf '\n' >>"${jsonl_log_path}"

{
  printf 'bead_id=%s\n' "${bead_id}"
  printf 'component=%s\n' "${component}"
  printf 'toolchain=%s\n' "${toolchain}"
  printf './scripts/e2e/pipeline_integration_verification_replay.sh\n'
  printf '%s\n' "${commands_run[@]}"
} >"${commands_path}"

jq -nc \
  --arg schema_version "franken-engine.pipeline-integration-verification.trace-ids.v1" \
  --arg bead_id "${bead_id}" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg component "${component}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component
  }' >"${trace_ids_path}"

jq -nc \
  --arg schema_version "franken-engine.pipeline-integration-verification.manifest.v1" \
  --arg bead_id "${bead_id}" \
  --arg component "${component}" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg toolchain "${toolchain}" \
  --arg target_dir "${target_dir}" \
  --arg replay_command "./scripts/e2e/pipeline_integration_verification_replay.sh" \
  --argjson suite_size "$(printf '%s\n' "${tests_json}" | jq 'length')" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    component: $component,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    toolchain: $toolchain,
    target_dir: $target_dir,
    suite_size: $suite_size,
    artifact_paths: {
      jsonl_log: "pipeline_verification.jsonl",
      run_manifest: "run_manifest.json",
      events_jsonl: "events.jsonl",
      commands_txt: "commands.txt",
      trace_ids: "trace_ids.json",
      suite_report: "pipeline_verification_report.json",
      summary_md: "summary.md",
      specimens_dir: "specimens",
      reports_dir: "reports",
      step_logs_dir: "step_logs"
    },
    replay_command: $replay_command
  }' >"${manifest_path}"

jq -s \
  --arg schema_version "franken-engine.pipeline-integration-verification.report.v1" \
  --arg bead_id "${bead_id}" \
  --arg component "${component}" \
  --arg outcome "${overall_outcome}" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg toolchain "${toolchain}" \
  --argjson pass_count "${pass_count}" \
  --argjson fail_count "${fail_count}" \
  --argjson error_count "${error_count}" \
  --argjson total_count "${total_count}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    component: $component,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    toolchain: $toolchain,
    outcome: $outcome,
    summary: {
      pass: $pass_count,
      fail: $fail_count,
      error: $error_count,
      total: $total_count
    },
    test_results: [ .[] | select(has("test")) ]
  }' "${jsonl_log_path}" >"${report_path}"

failed_line="none"
if [[ "${#failed_tests[@]}" -gt 0 ]]; then
  failed_line="$(printf '%s, ' "${failed_tests[@]}")"
  failed_line="${failed_line%, }"
fi

errored_line="none"
if [[ "${#errored_tests[@]}" -gt 0 ]]; then
  errored_line="$(printf '%s, ' "${errored_tests[@]}")"
  errored_line="${errored_line%, }"
fi

cat >"${summary_path}" <<EOF
# Pipeline Integration Verification Summary

- Bead: \`${bead_id}\`
- Component: \`${component}\`
- Toolchain: \`${toolchain}\`
- Outcome: \`${overall_outcome}\`
- Totals: pass=${pass_count}, fail=${fail_count}, error=${error_count}, total=${total_count}
- Failures: ${failed_line}
- Errors: ${errored_line}
- Artifact log: \`pipeline_verification.jsonl\`
- Replay: \`./scripts/e2e/pipeline_integration_verification_replay.sh\`
EOF

echo "pipeline integration verification manifest: ${manifest_path}"
echo "pipeline integration verification report: ${report_path}"
echo "pipeline integration verification events: ${events_path}"
echo "pipeline integration verification jsonl: ${jsonl_log_path}"
echo "pipeline integration verification summary: ${summary_path}"

if [[ "${fail_count}" -gt 0 || "${error_count}" -gt 0 ]]; then
  exit 1
fi
