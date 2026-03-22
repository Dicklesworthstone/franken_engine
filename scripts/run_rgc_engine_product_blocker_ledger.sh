#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
artifact_root="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_ARTIFACT_ROOT:-artifacts/rgc_engine_product_blocker_ledger}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
stale_after_hours="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_MAX_SUPPORT_AGE_HOURS:-720}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_engine_product_blocker_ledger_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
ledger_path="${run_dir}/engine_product_blocker_ledger.json"
cohort_rollup_path="${run_dir}/cohort_readiness_rollup.json"
owner_routing_path="${run_dir}/owner_routing_report.json"
gate_report_path="${run_dir}/gate_report.json"
copied_support_contract_path="${run_dir}/support_surface_contract.json"
beads_snapshot_path="${run_dir}/beads_snapshot.json"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_V1.md"
contract_json="docs/engine_product_blocker_ledger_v1.json"
support_contract_json="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_SUPPORT_CONTRACT_PATH:-docs/support_surface_contract.json}"

trace_id="trace-rgc-engine-product-blocker-ledger-${timestamp}"
decision_id="decision-rgc-engine-product-blocker-ledger-${timestamp}"
policy_id="policy-rgc-engine-product-blocker-ledger-v1"
component="rgc_engine_product_blocker_ledger"
replay_command="./scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh show"
dirty_worktree_json="true"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  worktree_status="$(
    git status --short --untracked-files=normal -- . \
      ":(exclude)${artifact_root%/}/" \
      ":(exclude).beads/" \
      ":(exclude).claude/" 2>/dev/null || true
  )"
  if [[ -z "$worktree_status" ]]; then
    dirty_worktree_json="false"
  fi
fi

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-408B-LEDGER-0001: missing blocker-ledger doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-408B-LEDGER-0002: missing blocker-ledger contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-408B-LEDGER-0003: failed to parse blocker-ledger contract JSON (${contract_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC engine-product blocker ledger heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_INCREMENTAL=${cargo_incremental}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

file_age_hours() {
  local path="$1"
  local now modified

  now="$(date -u +%s)"
  modified="$(stat -c %Y "$path" 2>/dev/null || echo 0)"
  if [[ "$modified" == "0" ]]; then
    printf '0\n'
    return
  fi

  printf '%s\n' "$(( (now - modified) / 3600 ))"
}

declare -a commands_run=()
declare -a validation_errors=()
failed_command=""
manifest_written=false
step_log_index=0
last_step_log_path=""

write_validation_step_log() {
  local validation_outcome="$1"
  local log_path

  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  commands_run+=("validate source inputs")

  {
    echo "==> validate source inputs"
    echo "contract_json=${contract_json}"
    echo "support_contract_json=${support_contract_json}"
    echo "beads_snapshot_path=${beads_snapshot_path}"
    echo "stale_after_hours=${stale_after_hours}"
    if [[ "${validation_outcome}" == "pass" ]]; then
      echo "==> validation passed"
    else
      echo "==> validation failed"
      printf '%s\n' "${validation_errors[@]}"
    fi
  } >"$log_path"
}

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  last_step_log_path="${log_path}"

  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
        echo "==> failure: remote exit=${remote_exit_code}" | tee -a "$log_path"
        failed_command="${command_text} (remote-exit=${remote_exit_code})"
      else
        echo "==> failure: no remote exit code recovered" | tee -a "$log_path"
        failed_command="${command_text}"
      fi
      rch_reject_local_fallback "$log_path" || {
        failed_command="${command_text} (local-fallback)"
      }
      return 1
    fi
  fi

  rch_reject_local_fallback "$log_path"
}

hydrate_local_generated_artifacts() {
  local log_path="$1"
  local payload_path="${run_dir}/local_bundle_payload.json"
  local payload

  payload="$(awk '
    /__RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_BUNDLE_JSON_BEGIN__/ {capture=1; next}
    /__RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_BUNDLE_JSON_END__/ {capture=0; exit}
    capture {print}
  ' "${log_path}")"

  if [[ -z "${payload}" ]]; then
    echo "missing local bundle payload in ${log_path}" >&2
    return 1
  fi

  printf '%s\n' "${payload}" >"${payload_path}"
  jq -r '.files[] | @base64' "${payload_path}" | while IFS= read -r entry; do
    local decoded relative_path destination
    decoded="$(printf '%s' "${entry}" | base64 --decode)"
    relative_path="$(printf '%s' "${decoded}" | jq -r '.relative_path')"
    destination="${run_dir}/${relative_path}"
    mkdir -p "$(dirname "${destination}")"
    printf '%s' "$(printf '%s' "${decoded}" | jq -r '.contents')" >"${destination}"
  done
}

validate_inputs() {
  local support_age

  commands_run+=("br list --all --json > ${beads_snapshot_path}")
  if ! br list --all --json >"${beads_snapshot_path}"; then
    validation_errors+=("failed to capture bead snapshot via br list --all --json")
  fi

  if [[ ! -f "${support_contract_json}" ]]; then
    validation_errors+=("missing support-surface contract input: ${support_contract_json}")
  else
    commands_run+=("jq empty ${support_contract_json}")
    if ! jq -e '.' "${support_contract_json}" >/dev/null 2>&1; then
      validation_errors+=("support-surface contract JSON is invalid: ${support_contract_json}")
    fi

    support_age="$(file_age_hours "${support_contract_json}")"
    if (( support_age > stale_after_hours )); then
      validation_errors+=("support-surface contract is stale (${support_age}h > ${stale_after_hours}h): ${support_contract_json}")
    fi

    if ! jq -e '
        .readiness_answer_contract.product_ready_state == "delegated_to_franken_node_handoff"
        and .readiness_answer_contract.product_ready_owner_repo == "franken_node"
        and ((.readiness_answer_contract.product_ready_handoff_bead_id // "") | length > 0)
      ' "${support_contract_json}" >/dev/null; then
      validation_errors+=("support-surface contract does not expose delegated franken-node handoff readiness metadata")
    fi
  fi

  if [[ ! -s "${beads_snapshot_path}" ]]; then
    validation_errors+=("bead snapshot is empty or missing: ${beads_snapshot_path}")
  elif ! jq -e 'type == "array"' "${beads_snapshot_path}" >/dev/null 2>&1; then
    validation_errors+=("bead snapshot is not a JSON array: ${beads_snapshot_path}")
  fi

  if (( ${#validation_errors[@]} > 0 )); then
    write_validation_step_log "fail"
    printf '%s\n' "${validation_errors[@]}" >&2
    return 1
  fi

  cp "${support_contract_json}" "${copied_support_contract_path}"
  write_validation_step_log "pass"
  return 0
}

assert_required_artifacts() {
  local missing=()
  local artifact
  for artifact in \
    "${ledger_path}" \
    "${cohort_rollup_path}" \
    "${owner_routing_path}" \
    "${gate_report_path}" \
    "${copied_support_contract_path}" \
    "${beads_snapshot_path}"; do
    if [[ ! -f "${artifact}" ]]; then
      missing+=("${artifact}")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    printf 'missing required artifacts:\n%s\n' "${missing[*]}" >&2
    return 1
  fi

  return 0
}

write_events() {
  local validation_outcome="$1"
  local mode_outcome="$2"
  local error_code="${3:-null}"

  jq -c -n \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg validation_outcome "${validation_outcome}" \
    --arg mode_outcome "${mode_outcome}" \
    --arg mode "${mode}" \
    --argjson error_code "${error_code}" \
    '[
      {
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id,
        component: $component,
        event: "validation",
        outcome: $validation_outcome,
        error_code: (if $validation_outcome == "pass" then null else $error_code end)
      },
      {
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id,
        component: $component,
        event: "mode_completion",
        outcome: $mode_outcome,
        error_code: $error_code,
        mode: $mode
      }
    ] | .[]' >"${events_path}"
}

write_commands() {
  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
}

write_trace_ids() {
  jq -n \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id
    }' >"${trace_ids_path}"
}

write_manifest() {
  local outcome="$1"
  local error_code_json="${2:-null}"
  local gate_report_exists="false"

  if [[ -f "${gate_report_path}" ]]; then
    gate_report_exists="true"
  fi

  jq -n \
    --arg schema_version "franken-engine.rgc-engine-product-blocker-ledger.run-manifest.v1" \
    --arg bead_id "bd-1lsy.5.10.2" \
    --arg mode "${mode}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg replay_command "${replay_command}" \
    --arg support_contract_path "${copied_support_contract_path}" \
    --arg beads_snapshot_path "${beads_snapshot_path}" \
    --arg ledger_path "${ledger_path}" \
    --arg cohort_rollup_path "${cohort_rollup_path}" \
    --arg owner_routing_path "${owner_routing_path}" \
    --arg gate_report_path "${gate_report_path}" \
    --arg failed_command "${failed_command}" \
    --argjson dirty_worktree "${dirty_worktree_json}" \
    --argjson commands "$(json_array_from_args "${commands_run[@]}")" \
    --argjson error_code "${error_code_json}" \
    --arg outcome "${outcome}" \
    --argjson gate_report_exists "${gate_report_exists}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      mode: $mode,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      outcome: $outcome,
      error_code: $error_code,
      failed_command: (if ($failed_command | length) > 0 then $failed_command else null end),
      dirty_worktree: $dirty_worktree,
      replay_command: $replay_command,
      inputs: {
        support_surface_contract: $support_contract_path,
        beads_snapshot: $beads_snapshot_path
      },
      artifacts: {
        engine_product_blocker_ledger: $ledger_path,
        cohort_readiness_rollup: $cohort_rollup_path,
        owner_routing_report: $owner_routing_path,
        gate_report: (if $gate_report_exists then $gate_report_path else null end),
        support_surface_contract: $support_contract_path,
        beads_snapshot: $beads_snapshot_path,
        events: "events.jsonl",
        commands: "commands.txt",
        trace_ids: "trace_ids.json",
        step_logs: "step_logs/"
      },
      commands: $commands
    }' >"${manifest_path}"
  manifest_written=true
}

run_mode() {
  local mode_exit=0

  case "${mode}" in
  bundle)
    run_step "cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger -- --artifact-dir ${run_dir} --beads-json ${beads_snapshot_path} --support-contract-json ${support_contract_json}" \
      cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger -- \
        --artifact-dir "${run_dir}" \
        --beads-json "${beads_snapshot_path}" \
        --support-contract-json "${support_contract_json}" \
        --trace-id "${trace_id}" \
        --decision-id "${decision_id}" \
        --policy-id "${policy_id}" \
        --generated-at-utc "${generated_at_utc}" \
        --emit-local-bundle-json || mode_exit=$?
    if [[ "${mode_exit}" -eq 0 ]]; then
      hydrate_local_generated_artifacts "${last_step_log_path}" || mode_exit=$?
    fi
    ;;
  check)
    run_step "cargo check -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger" \
      cargo check -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger || mode_exit=$?
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test engine_product_blocker_ledger" \
      cargo test -p frankenengine-engine --test engine_product_blocker_ledger || mode_exit=$?
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger -- -D warnings || mode_exit=$?
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger" \
      cargo check -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger || mode_exit=$?
    if [[ "${mode_exit}" -eq 0 ]]; then
      run_step "cargo test -p frankenengine-engine --test engine_product_blocker_ledger" \
        cargo test -p frankenengine-engine --test engine_product_blocker_ledger || mode_exit=$?
    fi
    if [[ "${mode_exit}" -eq 0 ]]; then
      run_step "cargo clippy -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger -- -D warnings || mode_exit=$?
    fi
    if [[ "${mode_exit}" -eq 0 ]]; then
      run_step "cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger -- --artifact-dir ${run_dir} --beads-json ${beads_snapshot_path} --support-contract-json ${support_contract_json}" \
        cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger -- \
          --artifact-dir "${run_dir}" \
          --beads-json "${beads_snapshot_path}" \
          --support-contract-json "${support_contract_json}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --emit-local-bundle-json || mode_exit=$?
      if [[ "${mode_exit}" -eq 0 ]]; then
        hydrate_local_generated_artifacts "${last_step_log_path}" || mode_exit=$?
      fi
    fi
    ;;
  *)
    echo "unsupported mode: ${mode}" >&2
    exit 1
    ;;
  esac

  return "${mode_exit}"
}

error_code_json="null"
if ! validate_inputs; then
  error_code_json='"FE-RGC-408B-GATE-0001"'
  write_events "fail" "fail" "${error_code_json}"
  write_commands
  write_trace_ids
  write_manifest "fail" "${error_code_json}"
  exit 1
fi

if ! run_mode; then
  error_code_json='"FE-RGC-408B-GATE-0002"'
fi

if [[ "${error_code_json}" == "null" ]] && ! assert_required_artifacts; then
  error_code_json='"FE-RGC-408B-GATE-0003"'
fi

if [[ "${error_code_json}" == "null" ]]; then
  write_events "pass" "pass" "null"
  write_commands
  write_trace_ids
  write_manifest "pass" "null"
  echo "[rgc-engine-product-blocker-ledger] bundle ready at ${run_dir}"
  exit 0
fi

write_events "pass" "fail" "${error_code_json}"
write_commands
write_trace_ids
write_manifest "fail" "${error_code_json}"
exit 1
