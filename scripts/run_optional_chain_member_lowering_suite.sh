#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
bead_id="bd-1lsy.2.10.1"
component="optional_chain_member_lowering"
trace_id="trace-optional-chain-member-lowering"
decision_id="decision-optional-chain-member-lowering"
policy_id="policy-optional-chain-member-lowering"
artifact_root="${OPTIONAL_CHAIN_MEMBER_LOWERING_ARTIFACT_ROOT:-artifacts/optional_chain_member_lowering}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_optional_chain_member_lowering_${mode}_$$}"
run_dir="${artifact_root}/${timestamp}"
specimens_dir="${run_dir}/specimens"
step_logs_dir="${run_dir}/step_logs"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_path="${run_dir}/optional_chain_member_lowering_report.json"
summary_path="${run_dir}/summary.md"

mkdir -p "${run_dir}" "${specimens_dir}" "${step_logs_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for optional-chain member lowering verification" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for optional-chain member lowering verification" >&2
  exit 2
fi

member_source_path="${specimens_dir}/member.js"
computed_source_path="${specimens_dir}/computed.js"
nullish_source_path="${specimens_dir}/nullish.js"
member_artifact_path="${run_dir}/member.compile.json"
computed_artifact_path="${run_dir}/computed.compile.json"
nullish_report_path="${run_dir}/nullish.run.json"

cat >"${member_source_path}" <<'EOF'
const obj = { value: 7 };
obj?.value;
EOF

cat >"${computed_source_path}" <<'EOF'
const key = "value";
const obj = { value: 7 };
obj?.[key];
EOF

cat >"${nullish_source_path}" <<'EOF'
let obj = null;
obj?.value;
EOF

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line
  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi
  printf '%s\n' "${remote_exit_line##*=}"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'falling back to local|local fallback|running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    return 1
  fi
}

declare -a commands_run=()
declare -a step_ids=()
declare -a step_logs=()
step_index=0

run_step() {
  local step_id="$1"
  local command_text="$2"
  local log_path status remote_exit_code
  shift 2

  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_index}").log"
  step_index=$((step_index + 1))

  commands_run+=("${command_text}")
  step_ids+=("${step_id}")
  step_logs+=("${log_path}")

  echo "==> ${command_text}"

  set +e
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@" > >(tee "${log_path}") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    echo "optional-chain member lowering step failed: ${command_text}" >&2
    exit "${status}"
  fi

  if ! rch_reject_local_fallback "${log_path}"; then
    echo "rch reported local fallback for: ${command_text}" >&2
    exit 1
  fi

  remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
  if [[ -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    echo "missing or non-zero remote exit marker for: ${command_text}" >&2
    exit 1
  fi
}

run_step \
  "unit-tests" \
  "cargo test -p frankenengine-engine --lib optional_member -- --nocapture" \
  cargo test -p frankenengine-engine --lib optional_member -- --nocapture

run_step \
  "integration-tests" \
  "cargo test -p frankenengine-engine --test optional_chain_member_lowering -- --nocapture" \
  cargo test -p frankenengine-engine --test optional_chain_member_lowering -- --nocapture

run_step \
  "compile-member" \
  "cargo run -p frankenengine-engine --bin frankenctl -- compile --input ${member_source_path} --out ${member_artifact_path} --goal script --trace-id ${trace_id}-member --decision-id ${decision_id}-member --policy-id ${policy_id}" \
  cargo run -p frankenengine-engine --bin frankenctl -- \
  compile \
  --input "${member_source_path}" \
  --out "${member_artifact_path}" \
  --goal script \
  --trace-id "${trace_id}-member" \
  --decision-id "${decision_id}-member" \
  --policy-id "${policy_id}"

run_step \
  "compile-computed" \
  "cargo run -p frankenengine-engine --bin frankenctl -- compile --input ${computed_source_path} --out ${computed_artifact_path} --goal script --trace-id ${trace_id}-computed --decision-id ${decision_id}-computed --policy-id ${policy_id}" \
  cargo run -p frankenengine-engine --bin frankenctl -- \
  compile \
  --input "${computed_source_path}" \
  --out "${computed_artifact_path}" \
  --goal script \
  --trace-id "${trace_id}-computed" \
  --decision-id "${decision_id}-computed" \
  --policy-id "${policy_id}"

run_step \
  "run-nullish" \
  "cargo run -p frankenengine-engine --bin frankenctl -- run --input ${nullish_source_path} --extension-id optional-chain-nullish --out ${nullish_report_path}" \
  cargo run -p frankenengine-engine --bin frankenctl -- \
  run \
  --input "${nullish_source_path}" \
  --extension-id optional-chain-nullish \
  --out "${nullish_report_path}"

jq -e '.. | objects | select(has("JumpIfNullish"))' "${member_artifact_path}" >/dev/null
jq -e '.. | objects | select(has("JumpIfNullish"))' "${computed_artifact_path}" >/dev/null
jq -e '.execution_value == "undefined"' "${nullish_report_path}" >/dev/null

printf '%s\n' "${commands_run[@]}" >"${commands_path}"
: >"${events_path}"
for idx in "${!step_ids[@]}"; do
  jq -nc \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg step_id "${step_ids[$idx]}" \
    --arg step_log "step_logs/$(basename "${step_logs[$idx]}")" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: "step_completed",
      outcome: "pass",
      error_code: null,
      step_id: $step_id,
      step_log: $step_log
    }' >>"${events_path}"
  printf '\n' >>"${events_path}"
done

jq -nc \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg component "${component}" \
  '{
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component,
    event: "gate_completed",
    outcome: "pass",
    error_code: null
  }' >>"${events_path}"
printf '\n' >>"${events_path}"

jq -n \
  --arg schema_version "franken-engine.optional-chain-member-lowering.trace-ids.v1" \
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

jq -n \
  --arg schema_version "franken-engine.optional-chain-member-lowering.manifest.v1" \
  --arg bead_id "${bead_id}" \
  --arg mode "${mode}" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg target_dir "${target_dir}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    mode: $mode,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: "optional_chain_member_lowering",
    target_dir: $target_dir,
    artifact_paths: {
      report: "optional_chain_member_lowering_report.json",
      run_manifest: "run_manifest.json",
      events_jsonl: "events.jsonl",
      commands_txt: "commands.txt",
      trace_ids: "trace_ids.json",
      step_logs_dir: "step_logs",
      member_compile_artifact: "member.compile.json",
      computed_compile_artifact: "computed.compile.json",
      nullish_run_report: "nullish.run.json"
    },
    replay_command: "./scripts/e2e/optional_chain_member_lowering_replay.sh " + $mode
  }' >"${manifest_path}"

jq -n \
  --arg schema_version "franken-engine.optional-chain-member-lowering.report.v1" \
  --arg bead_id "${bead_id}" \
  --arg mode "${mode}" \
  --arg member_artifact "member.compile.json" \
  --arg computed_artifact "computed.compile.json" \
  --arg nullish_report "nullish.run.json" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    mode: $mode,
    component: "optional_chain_member_lowering",
    specimen_results: [
      {
        specimen_id: "member",
        compile_artifact: $member_artifact,
        typed_nullish_guard: true,
        outcome: "pass"
      },
      {
        specimen_id: "computed",
        compile_artifact: $computed_artifact,
        typed_nullish_guard: true,
        outcome: "pass"
      },
      {
        specimen_id: "nullish",
        run_report: $nullish_report,
        expected_execution_value: "undefined",
        outcome: "pass"
      }
    ]
  }' >"${report_path}"

cat >"${summary_path}" <<EOF
# Optional Chain Member Lowering Summary

- Bead: \`${bead_id}\`
- Mode: \`${mode}\`
- Outcome: pass
- Verified library lowering tests for optional member and computed-member paths.
- Verified \`frankenctl compile\` accepts member and computed optional-chain specimens and emits typed nullish-guard IR.
- Verified \`frankenctl run\` short-circuits a nullish optional member to \`undefined\`.
EOF

echo "optional-chain member lowering manifest: ${manifest_path}"
echo "optional-chain member lowering report: ${report_path}"
echo "optional-chain member lowering events: ${events_path}"
