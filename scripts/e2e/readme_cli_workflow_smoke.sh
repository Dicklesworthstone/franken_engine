#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readme_path="${root_dir}/README.md"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

workflow_id="readme-cli-workflow-smoke-v1"
manifest_schema="franken-engine.readme-cli-workflow-smoke.v1"
frankenctl_schema="franken-engine.frankenctl.v1"
compile_artifact_schema="franken-engine.frankenctl.compile-artifact.v1"
fixture_schema="franken-engine.readme-cli-workflow.fixture.v1"
version_stdout_schema="franken-engine.frankenctl.version.stdout.v1"
readme_section="README.md#cli-contract"

artifact_root="${README_CLI_WORKFLOW_ARTIFACT_ROOT:-${root_dir}/artifacts/readme_cli_workflow_smoke}"
run_id="${README_CLI_WORKFLOW_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${README_CLI_WORKFLOW_RUN_DIR:-${artifact_root}/${run_id}}"
workspace_dir="${run_dir}/workspace"
step_logs_dir="${run_dir}/step_logs"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: ${tool}" >&2
    exit 2
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    openssl dgst -sha256 "$path" | awk '{print $NF}'
  fi
}

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    openssl dgst -sha256 | awk '{print $NF}'
  fi
}

json_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
  else
    printf '%s\n' "$@" | jq -R . | jq -s .
  fi
}

readme_line_for() {
  local needle="$1"
  if command -v rg >/dev/null 2>&1; then
    rg -n -F "$needle" "$readme_path" | head -n 1 | cut -d: -f1 || true
  else
    grep -n -F "$needle" "$readme_path" | head -n 1 | cut -d: -f1 || true
  fi
}

resolve_cargo_target_dir() {
  local target_dir="${CARGO_TARGET_DIR:-target}"
  if [[ "$target_dir" = /* ]]; then
    printf '%s\n' "$target_dir"
  else
    printf '%s/%s\n' "$root_dir" "$target_dir"
  fi
}

assert_readme_contains() {
  local needle="$1"
  if [[ -z "$(readme_line_for "$needle")" ]]; then
    echo "README CLI contract drift: missing command: ${needle}" >&2
    exit 3
  fi
}

resolve_frankenctl_bin() {
  local candidate="${FRANKENCTL_BIN:-}"
  if [[ -z "$candidate" ]]; then
    candidate="$(resolve_cargo_target_dir)/debug/frankenctl"
  fi
  if [[ ! -x "$candidate" ]]; then
    cat >&2 <<EOF
frankenctl binary is not executable: ${candidate}
Set FRANKENCTL_BIN=/path/to/frankenctl or build it first, for example:
  CARGO_TARGET_DIR=/data/projects/franken_engine/target_<agent> cargo build -p frankenengine-engine --bin frankenctl
EOF
    exit 4
  fi
  local candidate_dir
  local candidate_base
  candidate_dir="$(cd "$(dirname "$candidate")" && pwd)"
  candidate_base="$(basename "$candidate")"
  printf '%s/%s\n' "$candidate_dir" "$candidate_base"
}

write_event() {
  local step_name="$1"
  local readme_command="$2"
  local command_name="$3"
  local args_json="$4"
  local cwd="$5"
  local artifact_path="$6"
  local artifact_schema="$7"
  local exit_code="$8"
  local expected_exit_code="$9"
  local stdout_path="${10}"
  local stderr_path="${11}"
  local duration_ms="${12}"
  local decision="${13}"
  local error_code="${14}"
  local remediation="${15}"
  local readme_line="${16}"
  local artifact_sha256="${17}"
  local link_signature="${18}"
  local signed_link="${19}"
  local readme_line_json="null"
  local severity="info"

  if [[ -n "$readme_line" ]]; then
    readme_line_json="$readme_line"
  fi
  if [[ "$decision" != "passed" ]]; then
    severity="error"
  fi

  jq -nc \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg event_name "readme_cli_workflow.step_completed" \
    --arg severity "$severity" \
    --arg workflow_id "$workflow_id" \
    --arg step_name "$step_name" \
    --arg readme_section "$readme_section" \
    --arg readme_command "$readme_command" \
    --arg command "$command_name" \
    --argjson args "$args_json" \
    --arg cwd "$cwd" \
    --arg artifact_path "$artifact_path" \
    --arg schema_id "$artifact_schema" \
    --argjson exit_code "$exit_code" \
    --argjson expected_exit_code "$expected_exit_code" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson duration_ms "$duration_ms" \
    --arg decision "$decision" \
    --arg error_code "$error_code" \
    --arg remediation "$remediation" \
    --argjson readme_line "$readme_line_json" \
    --arg artifact_sha256 "$artifact_sha256" \
    --arg link_signature "$link_signature" \
    --arg signed_link "$signed_link" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      severity: $severity,
      step_id: $step_name,
      command_id: $step_name,
      workflow_id: $workflow_id,
      step_name: $step_name,
      readme_section: $readme_section,
      readme_line: $readme_line,
      readme_command: $readme_command,
      command: $command,
      args: $args,
      cwd: $cwd,
      artifact_path: $artifact_path,
      schema_id: $schema_id,
      exit_code: $exit_code,
      expected_exit_code: $expected_exit_code,
      exit_code_matches_expectation: ($exit_code == $expected_exit_code),
      stdout_path: $stdout_path,
      stderr_path: $stderr_path,
      duration_ms: $duration_ms,
      decision: $decision,
      error_code: (if $error_code == "" then null else $error_code end),
      remediation: (if $remediation == "" then null else $remediation end),
      artifact_sha256: (if $artifact_sha256 == "" then null else $artifact_sha256 end),
      link_signature: $link_signature,
      signed_link: $signed_link
    }' >>"$events_path"
}

validate_step_artifact() {
  local step_name="$1"
  local artifact_path="$2"
  local stdout_path="$3"

  case "$step_name" in
    setup_demo_source)
      [[ -s "$artifact_path" ]]
      ;;
    setup_artifacts_dir)
      [[ -d "$artifact_path" ]]
      ;;
    prepare_replay_trace)
      jq -e '.session_id and (.events | length > 0)' "$artifact_path" >/dev/null
      ;;
    version)
      grep -Eq '^frankenctl [0-9]+\.[0-9]+\.[0-9]+' "$stdout_path"
      ;;
    compile)
      jq -e --arg schema "$compile_artifact_schema" '.schema_version == $schema' "$artifact_path" >/dev/null
      ;;
    verify_compile_artifact)
      jq -e --arg schema "$frankenctl_schema" '.schema_version == $schema and .passed == true' "$stdout_path" >/dev/null
      ;;
    run)
      jq -e --arg schema "$frankenctl_schema" '.schema_version == $schema and .extension_id == "demo-ext"' "$artifact_path" >/dev/null
      ;;
    replay_run)
      jq -e --arg schema "$frankenctl_schema" '.schema_version == $schema and .complete == true' "$artifact_path" >/dev/null
      ;;
    *)
      [[ -s "$artifact_path" || -s "$stdout_path" ]]
      ;;
  esac
}

run_step() {
  local step_index="$1"
  local step_name="$2"
  local readme_command="$3"
  local artifact_rel="$4"
  local artifact_schema="$5"
  local expected_exit_code="$6"
  local executable="$7"
  shift 7
  local exec_args=("$@")
  local stdout_path="${step_logs_dir}/step_$(printf '%03d' "$step_index")_${step_name}.stdout"
  local stderr_path="${step_logs_dir}/step_$(printf '%03d' "$step_index")_${step_name}.stderr"
  local command_name
  local args_as_json
  local readme_line
  local start_ms
  local end_ms
  local duration_ms
  local exit_code
  local decision="passed"
  local error_code=""
  local remediation=""
  local artifact_path
  local artifact_sha256=""
  local artifact_path_for_event
  local stdout_path_for_event
  local stderr_path_for_event
  local workspace_dir_for_event
  local link_signature
  local signed_link

  if ! [[ "$expected_exit_code" =~ ^-?[0-9]+$ ]]; then
    echo "invalid expected exit code for step ${step_name}: ${expected_exit_code}" >&2
    exit 5
  fi

  if [[ "$executable" == "$frankenctl_bin" ]]; then
    command_name="frankenctl"
  else
    command_name="$(basename "$executable")"
  fi
  args_as_json="$(json_args "${exec_args[@]}")"
  readme_line="$(readme_line_for "$readme_command")"

  if [[ "$artifact_rel" == "__stdout__" ]]; then
    artifact_path="$stdout_path"
  else
    artifact_path="${workspace_dir}/${artifact_rel}"
  fi

  {
    printf '[step %03d] cwd=%s\n' "$step_index" "$workspace_dir"
    printf '  README: %s:%s %s\n' "$readme_path" "${readme_line:-unknown}" "$readme_command"
    printf '  display: %s\n' "$readme_command"
    printf '  expected_exit_code: %s\n' "$expected_exit_code"
    printf '  actual:'
    printf ' %q' "$executable" "${exec_args[@]}"
    printf '\n'
  } >>"$commands_path"

  start_ms="$(date +%s%3N)"
  set +e
  (
    cd "$workspace_dir"
    "$executable" "${exec_args[@]}"
  ) >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  end_ms="$(date +%s%3N)"
  duration_ms=$((end_ms - start_ms))

  if [[ "$exit_code" -ne "$expected_exit_code" ]]; then
    decision="failed"
    error_code="unexpected_exit_code"
    remediation="Expected exit code ${expected_exit_code}; inspect stderr_path and rerun the README command from cwd."
  elif [[ "$expected_exit_code" -eq 0 ]] && ! validate_step_artifact "$step_name" "$artifact_path" "$stdout_path"; then
    decision="failed"
    error_code="artifact_validation_failed"
    remediation="The command exited successfully but did not emit the README contract artifact."
  fi

  if [[ -f "$artifact_path" ]]; then
    artifact_sha256="$(sha256_file "$artifact_path")"
  elif [[ -d "$artifact_path" ]]; then
    artifact_sha256="$(printf '%s' "directory:${artifact_path}" | sha256_text)"
  fi
  artifact_path_for_event="$(proof_contract_repo_relative_path "$artifact_path")"
  stdout_path_for_event="$(proof_contract_repo_relative_path "$stdout_path")"
  stderr_path_for_event="$(proof_contract_repo_relative_path "$stderr_path")"
  workspace_dir_for_event="$(proof_contract_repo_relative_path "$workspace_dir")"
  link_signature="$(
    printf '%s' "${workflow_id}|${step_name}|${readme_section}|${readme_line}|${artifact_path_for_event}|${artifact_sha256}" \
      | sha256_text
  )"
  signed_link="sha256:${link_signature}:${artifact_path_for_event}"

  write_event \
    "$step_name" \
    "$readme_command" \
    "$command_name" \
    "$args_as_json" \
    "$workspace_dir_for_event" \
    "$artifact_path_for_event" \
    "$artifact_schema" \
    "$exit_code" \
    "$expected_exit_code" \
    "$stdout_path_for_event" \
    "$stderr_path_for_event" \
    "$duration_ms" \
    "$decision" \
    "$error_code" \
    "$remediation" \
    "$readme_line" \
    "$artifact_sha256" \
    "$link_signature" \
    "$signed_link"

  if [[ "$decision" != "passed" ]]; then
    echo "README workflow smoke failed at step ${step_name}; see ${stderr_path}" >&2
    return 1
  fi
}

write_manifest() {
  jq -n \
    --arg schema_version "$manifest_schema" \
    --arg workflow_id "$workflow_id" \
    --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg repo_root "$root_dir" \
    --arg readme_path "$readme_path" \
    --arg readme_section "$readme_section" \
    --arg frankenctl_bin "$frankenctl_bin" \
    --arg run_dir "$run_dir" \
    --arg workspace_dir "$workspace_dir" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg manifest_path "$manifest_path" \
    --slurpfile steps "$events_path" \
    '{
      schema_version: $schema_version,
      workflow_id: $workflow_id,
      generated_utc: $generated_utc,
      repo_root: $repo_root,
      frankenctl_bin: $frankenctl_bin,
      source_claims: [
        {
          document: $readme_path,
          section: $readme_section,
          claim: "README CLI Contract end-to-end frankenctl workflow"
        }
      ],
      artifacts: {
        run_dir: $run_dir,
        workspace_dir: $workspace_dir,
        manifest_path: $manifest_path,
        command_transcript_path: $commands_path,
        structured_events_path: $events_path
      },
      steps: $steps,
      signed_artifact_links: [
        $steps[]
        | {
            step_name,
            readme_section,
            readme_line,
            artifact_path,
            artifact_sha256,
            link_signature,
            signed_link
          }
      ]
    }' >"$manifest_path"
}

require_tool jq
require_tool awk
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  require_tool openssl
fi

assert_readme_contains "cargo build --release -p frankenengine-engine --bin frankenctl"
assert_readme_contains "./target/release/frankenctl version"
assert_readme_contains "mkdir -p ./artifacts"
assert_readme_contains "printf 'const answer = 40 + 2;\\n' > ./demo.js"
assert_readme_contains "./target/release/frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script"
assert_readme_contains "./target/release/frankenctl verify compile-artifact --input ./artifacts/demo.compile.json"
assert_readme_contains "./target/release/frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json"
assert_readme_contains "./target/release/frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json"

frankenctl_bin="$(resolve_frankenctl_bin)"

mkdir -p "$workspace_dir" "$step_logs_dir"
: >"$events_path"
: >"$commands_path"

run_step 0 version \
  "./target/release/frankenctl version" \
  "__stdout__" \
  "$version_stdout_schema" \
  0 \
  "$frankenctl_bin" version

run_step 1 setup_artifacts_dir \
  "mkdir -p ./artifacts" \
  "artifacts" \
  "$fixture_schema" \
  0 \
  bash -c "mkdir -p ./artifacts"

run_step 2 setup_demo_source \
  "printf 'const answer = 40 + 2;\\n' > ./demo.js" \
  "demo.js" \
  "$fixture_schema" \
  0 \
  bash -c "printf 'const answer = 40 + 2;\n' > ./demo.js"

run_step 3 compile \
  "./target/release/frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script" \
  "artifacts/demo.compile.json" \
  "$compile_artifact_schema" \
  0 \
  "$frankenctl_bin" compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script

run_step 4 verify_compile_artifact \
  "./target/release/frankenctl verify compile-artifact --input ./artifacts/demo.compile.json" \
  "__stdout__" \
  "$frankenctl_schema" \
  0 \
  "$frankenctl_bin" verify compile-artifact --input ./artifacts/demo.compile.json

run_step 5 run \
  "./target/release/frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json" \
  "artifacts/demo.run.json" \
  "$frankenctl_schema" \
  0 \
  "$frankenctl_bin" run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json

run_step 6 prepare_replay_trace \
  "./target/release/frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json" \
  "examples/05_replay_demo/sample_trace.json" \
  "$fixture_schema" \
  0 \
  bash -c "mkdir -p ./examples/05_replay_demo && cp \"${root_dir}/examples/05_replay_demo/sample_trace.json\" ./examples/05_replay_demo/sample_trace.json"

run_step 7 replay_run \
  "./target/release/frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json" \
  "artifacts/replay_report.json" \
  "$frankenctl_schema" \
  0 \
  "$frankenctl_bin" replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json

write_manifest
frankenctl_bin_rel="$(proof_contract_repo_relative_path "$frankenctl_bin")"
proof_contract_write_standard_bundle \
  "$run_dir" \
  "readme_cli_workflow_smoke" \
  "pass" \
  "FRANKENCTL_BIN=${frankenctl_bin_rel} ./scripts/e2e/readme_cli_workflow_smoke.sh" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "bd-1k59y" \
  "README-CLI-CONTRACT" \
  "0"

echo "README CLI workflow smoke manifest: ${manifest_path}"
echo "README CLI workflow proof manifest: ${run_dir}/manifest.json"
