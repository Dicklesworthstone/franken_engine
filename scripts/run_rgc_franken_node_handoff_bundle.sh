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
artifact_root="${RGC_FRANKEN_NODE_HANDOFF_ARTIFACT_ROOT:-artifacts/rgc_franken_node_handoff_bundle}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
stale_after_hours="${RGC_HANDOFF_MAX_EVIDENCE_AGE_HOURS:-720}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_franken_node_handoff_bundle_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
handoff_manifest_path="${run_dir}/franken_node_handoff_manifest.json"
smoke_verification_path="${run_dir}/sibling_smoke_verification.json"
summary_path="${run_dir}/support_surface_summary.md"
copied_bundle_contract_path="${run_dir}/franken_node_handoff_bundle_contract.json"
copied_support_contract_path="${run_dir}/support_surface_contract.json"
copied_blocker_ledger_path="${run_dir}/engine_product_blocker_ledger.json"
copied_repo_split_contract_path="${run_dir}/repo_split_contract.md"
step_logs_dir="${run_dir}/step_logs"

bundle_doc="docs/RGC_FRANKEN_NODE_HANDOFF_BUNDLE_V1.md"
bundle_contract_json="docs/franken_node_handoff_bundle_v1.json"
repo_split_contract_doc="docs/REPO_SPLIT_CONTRACT.md"
sibling_repo_path="${RGC_HANDOFF_SIBLING_REPO_PATH:-/dp/franken_node}"

trace_id="trace-rgc-franken-node-handoff-bundle-${timestamp}"
decision_id="decision-rgc-franken-node-handoff-bundle-${timestamp}"
policy_id="policy-rgc-franken-node-handoff-bundle-v1"
component="rgc_franken_node_handoff_bundle"
scenario_id="rgc-408c"
replay_command="./scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh ${mode}"
dirty_worktree_json="true"

resolved_support_contract_path=""
resolved_blocker_ledger_path=""

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

if [[ ! -f "$bundle_doc" ]]; then
  echo "FE-RGC-408C-HANDOFF-0001: missing handoff doc (${bundle_doc})" >&2
  exit 1
fi

if [[ ! -f "$bundle_contract_json" ]]; then
  echo "FE-RGC-408C-HANDOFF-0002: missing handoff contract JSON (${bundle_contract_json})" >&2
  exit 1
fi

if [[ ! -f "$repo_split_contract_doc" ]]; then
  echo "FE-RGC-408C-HANDOFF-0003: missing repo split contract doc (${repo_split_contract_doc})" >&2
  exit 1
fi

if ! jq -e '.' "$bundle_contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-408C-HANDOFF-0004: failed to parse handoff contract JSON (${bundle_contract_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC franken_node handoff bundle heavy commands" >&2
  exit 2
fi

latest_support_contract_artifact() {
  if [[ ! -d "${root_dir}/artifacts/rgc_support_surface_contract" ]]; then
    return 0
  fi

  find "${root_dir}/artifacts/rgc_support_surface_contract" \
    -mindepth 2 -maxdepth 2 -type f -name 'support_surface_contract.json' \
    | sort | tail -n 1
}

latest_blocker_ledger_artifact() {
  if [[ ! -d "${root_dir}/artifacts" ]]; then
    return 0
  fi

  find "${root_dir}/artifacts" -type f -name 'engine_product_blocker_ledger.json' \
    | sort | tail -n 1
}

resolve_support_contract_path() {
  if [[ -n "${RGC_HANDOFF_SUPPORT_CONTRACT_PATH:-}" ]]; then
    printf '%s\n' "${RGC_HANDOFF_SUPPORT_CONTRACT_PATH}"
    return
  fi

  local latest
  latest="$(latest_support_contract_artifact || true)"
  if [[ -n "$latest" ]]; then
    printf '%s\n' "$latest"
    return
  fi

  printf '%s\n' "${root_dir}/docs/support_surface_contract.json"
}

resolve_blocker_ledger_path() {
  if [[ -n "${RGC_HANDOFF_BLOCKER_LEDGER_PATH:-}" ]]; then
    printf '%s\n' "${RGC_HANDOFF_BLOCKER_LEDGER_PATH}"
    return
  fi

  latest_blocker_ledger_artifact || true
}

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

write_validation_step_log() {
  local validation_outcome="$1"
  local log_path

  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  commands_run+=("validate source inputs")

  {
    echo "==> validate source inputs"
    echo "bundle_contract_json=${bundle_contract_json}"
    echo "resolved_support_contract_path=${resolved_support_contract_path:-}"
    echo "resolved_blocker_ledger_path=${resolved_blocker_ledger_path:-}"
    echo "sibling_repo_path=${sibling_repo_path}"
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
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

copy_input_artifacts() {
  resolved_support_contract_path="$(resolve_support_contract_path)"
  resolved_blocker_ledger_path="$(resolve_blocker_ledger_path)"

  commands_run+=("cp ${bundle_contract_json} ${copied_bundle_contract_path}")
  commands_run+=("cp ${repo_split_contract_doc} ${copied_repo_split_contract_path}")
  cp "$bundle_contract_json" "$copied_bundle_contract_path"
  cp "$repo_split_contract_doc" "$copied_repo_split_contract_path"

  if [[ -n "$resolved_support_contract_path" && -f "$resolved_support_contract_path" ]]; then
    commands_run+=("cp ${resolved_support_contract_path} ${copied_support_contract_path}")
    cp "$resolved_support_contract_path" "$copied_support_contract_path"
  fi

  if [[ -n "$resolved_blocker_ledger_path" && -f "$resolved_blocker_ledger_path" ]]; then
    commands_run+=("cp ${resolved_blocker_ledger_path} ${copied_blocker_ledger_path}")
    cp "$resolved_blocker_ledger_path" "$copied_blocker_ledger_path"
  fi
}

validate_source_inputs() {
  local input support_age blocker_age orphaned_count cohort_rollup_count

  commands_run+=("jq empty ${bundle_contract_json}")
  commands_run+=("test -d ${sibling_repo_path}")
  validation_errors=()

  mapfile -t source_inputs < <(jq -r '.source_inputs[]' "$bundle_contract_json")
  for input in "${source_inputs[@]}"; do
    if [[ ! -e "$input" ]]; then
      validation_errors+=("missing source input: ${input}")
    fi
  done

  if [[ -z "$resolved_support_contract_path" || ! -f "$resolved_support_contract_path" ]]; then
    validation_errors+=("missing support-surface contract input")
  else
    commands_run+=("jq empty ${resolved_support_contract_path}")
    if ! jq -e '.' "$resolved_support_contract_path" >/dev/null 2>&1; then
      validation_errors+=("support-surface contract JSON is invalid: ${resolved_support_contract_path}")
    fi

    support_age="$(file_age_hours "$resolved_support_contract_path")"
    if (( support_age > stale_after_hours )); then
      validation_errors+=("support-surface contract is stale (${support_age}h > ${stale_after_hours}h): ${resolved_support_contract_path}")
    fi

    if ! jq -e '
        .readiness_answer_contract.product_ready_owner_repo == "franken_node"
        and .readiness_answer_contract.product_ready_state == "delegated_to_franken_node_handoff"
        and ((.readiness_answer_contract.product_ready_handoff_bead_id // "") | length > 0)
      ' "$resolved_support_contract_path" >/dev/null; then
      validation_errors+=("support-surface contract does not expose delegated franken_node handoff readiness metadata")
    fi

    if ! jq -e '
        .readiness_answer_contract.engine_ready_when_support_status_in as $engine_ready
        | ([.surface_rows[]
            | . as $row
            | select(($engine_ready | index($row.support_status)) != null)]
           | length) > 0
      ' "$resolved_support_contract_path" >/dev/null; then
      validation_errors+=("support-surface contract exposes zero engine-ready surfaces")
    fi
  fi

  if [[ -z "$resolved_blocker_ledger_path" || ! -f "$resolved_blocker_ledger_path" ]]; then
    validation_errors+=("missing engine-product blocker ledger input (set RGC_HANDOFF_BLOCKER_LEDGER_PATH or generate a ledger artifact first)")
  else
    commands_run+=("jq empty ${resolved_blocker_ledger_path}")
    if ! jq -e '.' "$resolved_blocker_ledger_path" >/dev/null 2>&1; then
      validation_errors+=("engine-product blocker ledger JSON is invalid: ${resolved_blocker_ledger_path}")
    fi

    if ! jq -e '.version == "franken-engine.engine-product-blocker-ledger.v1"' "$resolved_blocker_ledger_path" >/dev/null; then
      validation_errors+=("engine-product blocker ledger schema version is invalid: ${resolved_blocker_ledger_path}")
    fi

    blocker_age="$(file_age_hours "$resolved_blocker_ledger_path")"
    if (( blocker_age > stale_after_hours )); then
      validation_errors+=("engine-product blocker ledger is stale (${blocker_age}h > ${stale_after_hours}h): ${resolved_blocker_ledger_path}")
    fi

    orphaned_count="$(jq '
        [.blockers[]
         | select((.severity == "blocking" or .severity == "degraded")
           and (.remediation != "verified" and .remediation != "wont_fix")
           and (((.tracking_bead // "") | length) == 0)
           and (((.owner // "") | length) == 0)
         )]
        | length
      ' "$resolved_blocker_ledger_path")"
    if [[ "$orphaned_count" != "0" ]]; then
      validation_errors+=("engine-product blocker ledger contains orphaned unresolved blocking/degraded entries: ${orphaned_count}")
    fi

    cohort_rollup_count="$(jq '.cohort_rollups | length' "$resolved_blocker_ledger_path")"
    if [[ "$cohort_rollup_count" == "0" ]]; then
      validation_errors+=("engine-product blocker ledger exposes zero cohort rollups")
    fi
  fi

  if [[ ! -d "$sibling_repo_path" ]]; then
    validation_errors+=("missing sibling repo path: ${sibling_repo_path}")
  fi

  if ! grep -Fq -- '- `franken_node` -> `frankenengine-engine`' "$repo_split_contract_doc"; then
    validation_errors+=("repo split contract missing allowed franken_node -> frankenengine-engine dependency line")
  fi

  if ! grep -Fq -- '- `franken_engine` -> `franken_node`' "$repo_split_contract_doc"; then
    validation_errors+=("repo split contract missing forbidden franken_engine -> franken_node dependency line")
  fi

  if ! grep -Fq -- 'Both must pass before product release.' "$repo_split_contract_doc"; then
    validation_errors+=("repo split contract missing CI matrix release condition")
  fi

  if (( ${#validation_errors[@]} > 0 )); then
    write_validation_step_log "fail"
    printf '%s\n' "${validation_errors[@]}" >&2
    return 1
  fi

  write_validation_step_log "pass"
  return 0
}

run_mode() {
  local mode_exit=0

  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test franken_node_handoff_bundle" \
      cargo check -p frankenengine-engine --test franken_node_handoff_bundle || mode_exit=$?
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test franken_node_handoff_bundle" \
      cargo test -p frankenengine-engine --test franken_node_handoff_bundle || mode_exit=$?
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test franken_node_handoff_bundle -- -D warnings" \
      cargo clippy -p frankenengine-engine --test franken_node_handoff_bundle -- -D warnings || mode_exit=$?
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test franken_node_handoff_bundle" \
      cargo check -p frankenengine-engine --test franken_node_handoff_bundle || mode_exit=$?
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo test -p frankenengine-engine --test franken_node_handoff_bundle" \
        cargo test -p frankenengine-engine --test franken_node_handoff_bundle || mode_exit=$?
    fi
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo clippy -p frankenengine-engine --test franken_node_handoff_bundle -- -D warnings" \
        cargo clippy -p frankenengine-engine --test franken_node_handoff_bundle -- -D warnings || mode_exit=$?
    fi
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac

  return "$mode_exit"
}

write_smoke_verification() {
  local outcome="$1"
  local sibling_repo_exists_json="false"
  local split_contract_ok_json="false"
  local support_delegate_ok_json="false"
  local non_orphaned_blockers_json="false"
  local cohort_rollups_present_json="false"
  local support_contract_available_json="false"
  local blocker_ledger_available_json="false"
  local orphaned_blocker_count="null"
  local cohort_rollup_count="null"
  local ready_cohort_count="null"
  local smoke_outcome="pass"

  if [[ -d "$sibling_repo_path" ]]; then
    sibling_repo_exists_json="true"
  fi

  if grep -Fq -- '- `franken_node` -> `frankenengine-engine`' "$repo_split_contract_doc" \
    && grep -Fq -- '- `franken_engine` -> `franken_node`' "$repo_split_contract_doc"; then
    split_contract_ok_json="true"
  fi

  if [[ -f "$copied_support_contract_path" ]]; then
    support_contract_available_json="true"
    if jq -e '
        .readiness_answer_contract.product_ready_owner_repo == "franken_node"
        and .readiness_answer_contract.product_ready_state == "delegated_to_franken_node_handoff"
      ' "$copied_support_contract_path" >/dev/null; then
      support_delegate_ok_json="true"
    fi
  fi

  if [[ -f "$copied_blocker_ledger_path" ]]; then
    blocker_ledger_available_json="true"
    orphaned_blocker_count="$(jq '
        [.blockers[]
         | select((.severity == "blocking" or .severity == "degraded")
           and (.remediation != "verified" and .remediation != "wont_fix")
           and (((.tracking_bead // "") | length) == 0)
           and (((.owner // "") | length) == 0)
         )]
        | length
      ' "$copied_blocker_ledger_path")"
    cohort_rollup_count="$(jq '.cohort_rollups | length' "$copied_blocker_ledger_path")"
    ready_cohort_count="$(jq '
        [.cohort_rollups[]
         | select(.readiness == "ready" or .readiness == "ready_with_advisories")]
        | length
      ' "$copied_blocker_ledger_path")"

    if [[ "$orphaned_blocker_count" == "0" ]]; then
      non_orphaned_blockers_json="true"
    fi
    if [[ "$cohort_rollup_count" != "0" ]]; then
      cohort_rollups_present_json="true"
    fi
  fi

  for check in \
    "$sibling_repo_exists_json" \
    "$split_contract_ok_json" \
    "$support_delegate_ok_json" \
    "$non_orphaned_blockers_json" \
    "$cohort_rollups_present_json"; do
    if [[ "$check" != "true" ]]; then
      smoke_outcome="fail"
    fi
  done
  if [[ "$outcome" != "pass" ]]; then
    smoke_outcome="fail"
  fi

  jq -n \
    --arg schema_version "franken-engine.rgc-franken-node-sibling-smoke.v1" \
    --arg bead_id "bd-1lsy.5.10.3" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg sibling_repo_path "$sibling_repo_path" \
    --arg support_contract_path "$copied_support_contract_path" \
    --arg blocker_ledger_path "$copied_blocker_ledger_path" \
    --arg repo_split_contract_path "$copied_repo_split_contract_path" \
    --arg outcome "$smoke_outcome" \
    --argjson support_contract_available "$support_contract_available_json" \
    --argjson blocker_ledger_available "$blocker_ledger_available_json" \
    --argjson sibling_repo_exists "$sibling_repo_exists_json" \
    --argjson split_contract_ok "$split_contract_ok_json" \
    --argjson support_delegate_ok "$support_delegate_ok_json" \
    --argjson non_orphaned_blockers "$non_orphaned_blockers_json" \
    --argjson cohort_rollups_present "$cohort_rollups_present_json" \
    --argjson orphaned_blocker_count "$orphaned_blocker_count" \
    --argjson cohort_rollup_count "$cohort_rollup_count" \
    --argjson ready_cohort_count "$ready_cohort_count" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      sibling_repo_path: $sibling_repo_path,
      inputs: {
        support_surface_contract: (if $support_contract_available then $support_contract_path else null end),
        engine_product_blocker_ledger: (if $blocker_ledger_available then $blocker_ledger_path else null end),
        repo_split_contract: $repo_split_contract_path
      },
      outcome: $outcome,
      checks: [
        {
          check_id: "sibling_repo_exists",
          outcome: (if $sibling_repo_exists then "pass" else "fail" end),
          error_code: (if $sibling_repo_exists then null else "FE-RGC-408C-SMOKE-0001" end),
          detail: (if $sibling_repo_exists then ("found " + $sibling_repo_path) else ("missing " + $sibling_repo_path) end)
        },
        {
          check_id: "one_way_dependency_contract",
          outcome: (if $split_contract_ok then "pass" else "fail" end),
          error_code: (if $split_contract_ok then null else "FE-RGC-408C-SMOKE-0002" end),
          detail: (if $split_contract_ok then "repo split contract preserves one-way dependency direction" else "repo split contract drift detected" end)
        },
        {
          check_id: "support_contract_delegates_product_ready",
          outcome: (if $support_delegate_ok then "pass" else "fail" end),
          error_code: (if $support_delegate_ok then null else "FE-RGC-408C-SMOKE-0003" end),
          detail: (if $support_delegate_ok then "support contract keeps product-ready state delegated to franken_node handoff" else (if $support_contract_available then "support contract readiness delegation is missing or malformed" else "support contract unavailable" end) end)
        },
        {
          check_id: "unresolved_blockers_not_orphaned",
          outcome: (if $non_orphaned_blockers then "pass" else "fail" end),
          error_code: (if $non_orphaned_blockers then null else "FE-RGC-408C-SMOKE-0004" end),
          detail: (if $non_orphaned_blockers then "all unresolved blocking/degraded blockers retain a bead or owner" else (if $blocker_ledger_available then ("orphaned unresolved blocking/degraded blockers: " + ($orphaned_blocker_count | tostring)) else "blocker ledger unavailable" end) end)
        },
        {
          check_id: "cohort_rollups_present",
          outcome: (if $cohort_rollups_present then "pass" else "fail" end),
          error_code: (if $cohort_rollups_present then null else "FE-RGC-408C-SMOKE-0005" end),
          detail: (if $cohort_rollups_present then ("cohort rollups present: " + ($cohort_rollup_count | tostring) + "; ready cohorts: " + ($ready_cohort_count | tostring)) else (if $blocker_ledger_available then "cohort rollups missing from blocker ledger" else "blocker ledger unavailable" end) end)
        }
      ]
    }' >"$smoke_verification_path"
}

write_summary() {
  local outcome="$1"
  local status_counts_summary engine_ready_surfaces blocked_surfaces readiness_rule_summary
  local product_ready_state product_ready_owner_repo product_ready_handoff_bead_id
  local blocker_summary orphaned_summary

  if [[ -f "$copied_support_contract_path" ]]; then
    status_counts_summary="$(jq -r '
        [.surface_rows[].support_status]
        | sort
        | group_by(.)
        | map("- `\(.[0])`: \(length)")
        | join("\n")
      ' "$copied_support_contract_path")"
    engine_ready_surfaces="$(jq -r '
        .readiness_answer_contract.engine_ready_when_support_status_in as $engine_ready
        | [.surface_rows[]
           | . as $row
           | select(($engine_ready | index($row.support_status)) != null)
           | "- `\(.surface_id)` — \(.entry_surface)"]
        | if length == 0 then "- None" else join("\n") end
      ' "$copied_support_contract_path")"
    blocked_surfaces="$(jq -r '
        .readiness_answer_contract.engine_blocked_when_support_status_in as $engine_blocked
        | [.surface_rows[]
           | . as $row
           | select(($engine_blocked | index($row.support_status)) != null)
           | "- `\(.surface_id)` — \(.support_status)"]
        | if length == 0 then "- None" else join("\n") end
      ' "$copied_support_contract_path")"
    readiness_rule_summary="$(jq -r '.readiness_answer_contract.operator_rule_summary' "$copied_support_contract_path")"
    product_ready_state="$(jq -r '.readiness_answer_contract.product_ready_state' "$copied_support_contract_path")"
    product_ready_owner_repo="$(jq -r '.readiness_answer_contract.product_ready_owner_repo' "$copied_support_contract_path")"
    product_ready_handoff_bead_id="$(jq -r '.readiness_answer_contract.product_ready_handoff_bead_id' "$copied_support_contract_path")"
  else
    status_counts_summary="- support-surface contract unavailable"
    engine_ready_surfaces="- unavailable"
    blocked_surfaces="- unavailable"
    readiness_rule_summary="support-surface contract unavailable"
    product_ready_state="unknown"
    product_ready_owner_repo="unknown"
    product_ready_handoff_bead_id="unknown"
  fi

  if [[ -f "$copied_blocker_ledger_path" ]]; then
    blocker_summary="$(jq -r '
        [
          "- total blockers: \(.blockers | length)",
          "- unresolved release blockers: ([.blockers[] | select(.severity == "blocking" and (.remediation != "verified" and .remediation != "wont_fix"))] | length)",
          "- unresolved degraded blockers: ([.blockers[] | select(.severity == "degraded" and (.remediation != "verified" and .remediation != "wont_fix"))] | length)",
          "- cohort rollups: \(.cohort_rollups | length)",
          "- ready cohorts: ([.cohort_rollups[] | select(.readiness == "ready" or .readiness == "ready_with_advisories")] | length)"
        ] | join("\n")
      ' "$copied_blocker_ledger_path")"
    orphaned_summary="$(jq -r '
        [.blockers[]
         | select((.severity == "blocking" or .severity == "degraded")
           and (.remediation != "verified" and .remediation != "wont_fix")
           and (((.tracking_bead // "") | length) == 0)
           and (((.owner // "") | length) == 0)
         )
         | "- `\(.id)` — \(.title)"]
        | if length == 0 then "- None" else join("\n") end
      ' "$copied_blocker_ledger_path")"
  else
    blocker_summary="- blocker ledger unavailable"
    orphaned_summary="- blocker ledger unavailable"
  fi

  cat >"$summary_path" <<EOF
# FrankenNode Handoff Bundle Summary

- Outcome: ${outcome}
- Trace ID: \`${trace_id}\`
- Decision ID: \`${decision_id}\`
- Policy ID: \`${policy_id}\`
- Sibling repo path: \`${sibling_repo_path}\`

## Engine Readiness Rule

${readiness_rule_summary}

## Support Status Counts

${status_counts_summary}

## Engine-Ready Surfaces

${engine_ready_surfaces}

## Engine-Blocked Surfaces

${blocked_surfaces}

## Blocker Ledger Summary

${blocker_summary}

## Orphaned Unresolved Blocking/Degraded Entries

${orphaned_summary}

## Downstream Product Note

- Product-ready state: \`${product_ready_state}\`
- Product-ready owner repo: \`${product_ready_owner_repo}\`
- Product-ready handoff bead id from support contract: \`${product_ready_handoff_bead_id}\`
- Repo split contract: \`${copied_repo_split_contract_path}\`
EOF
}

write_handoff_manifest() {
  local outcome="$1"
  local support_status_counts_json engine_ready_surfaces_json engine_blocked_surfaces_json
  local blocker_summary_json
  local support_contract_input_path=""
  local blocker_ledger_input_path=""
  local product_ready_state="unknown"
  local product_ready_owner_repo="unknown"
  local product_ready_handoff_bead_id="unknown"
  local smoke_outcome="fail"

  if [[ -f "$copied_support_contract_path" ]]; then
    support_contract_input_path="$copied_support_contract_path"
    support_status_counts_json="$(jq '[.surface_rows[].support_status] | reduce .[] as $status ({}; .[$status] = ((.[$status] // 0) + 1))' "$copied_support_contract_path")"
    engine_ready_surfaces_json="$(jq '
        .readiness_answer_contract.engine_ready_when_support_status_in as $engine_ready
        | [.surface_rows[]
           | . as $row
           | select(($engine_ready | index($row.support_status)) != null)
           | .surface_id]
      ' "$copied_support_contract_path")"
    engine_blocked_surfaces_json="$(jq '
        .readiness_answer_contract.engine_blocked_when_support_status_in as $engine_blocked
        | [.surface_rows[]
           | . as $row
           | select(($engine_blocked | index($row.support_status)) != null)
           | .surface_id]
      ' "$copied_support_contract_path")"
    product_ready_state="$(jq -r '.readiness_answer_contract.product_ready_state' "$copied_support_contract_path")"
    product_ready_owner_repo="$(jq -r '.readiness_answer_contract.product_ready_owner_repo' "$copied_support_contract_path")"
    product_ready_handoff_bead_id="$(jq -r '.readiness_answer_contract.product_ready_handoff_bead_id' "$copied_support_contract_path")"
  else
    support_status_counts_json='{}'
    engine_ready_surfaces_json='[]'
    engine_blocked_surfaces_json='[]'
  fi

  if [[ -f "$copied_blocker_ledger_path" ]]; then
    blocker_ledger_input_path="$copied_blocker_ledger_path"
    blocker_summary_json="$(jq '
        {
          total_blockers: (.blockers | length),
          unresolved_release_blockers: ([.blockers[] | select(.severity == "blocking" and (.remediation != "verified" and .remediation != "wont_fix"))] | length),
          unresolved_degraded: ([.blockers[] | select(.severity == "degraded" and (.remediation != "verified" and .remediation != "wont_fix"))] | length),
          cohort_rollup_count: (.cohort_rollups | length),
          ready_cohort_count: ([.cohort_rollups[] | select(.readiness == "ready" or .readiness == "ready_with_advisories")] | length)
        }
      ' "$copied_blocker_ledger_path")"
  else
    blocker_summary_json='null'
  fi

  if [[ -f "$smoke_verification_path" ]]; then
    smoke_outcome="$(jq -r '.outcome' "$smoke_verification_path")"
  fi

  jq -n \
    --arg schema_version "franken-engine.rgc-franken-node-handoff-manifest.v1" \
    --arg bead_id "bd-1lsy.5.10.3" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg generated_at_utc "$timestamp" \
    --arg outcome "$outcome" \
    --arg bundle_contract_path "$copied_bundle_contract_path" \
    --arg support_contract_path "$support_contract_input_path" \
    --arg blocker_ledger_path "$blocker_ledger_input_path" \
    --arg repo_split_contract_path "$copied_repo_split_contract_path" \
    --arg sibling_repo_path "$sibling_repo_path" \
    --arg smoke_verification_path "$smoke_verification_path" \
    --arg smoke_outcome "$smoke_outcome" \
    --arg summary_path "$summary_path" \
    --arg product_ready_state "$product_ready_state" \
    --arg product_ready_owner_repo "$product_ready_owner_repo" \
    --arg product_ready_handoff_bead_id "$product_ready_handoff_bead_id" \
    --argjson support_status_counts "$support_status_counts_json" \
    --argjson engine_ready_surfaces "$engine_ready_surfaces_json" \
    --argjson engine_blocked_surfaces "$engine_blocked_surfaces_json" \
    --argjson blocker_summary "$blocker_summary_json" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      generated_at_utc: $generated_at_utc,
      outcome: $outcome,
      inputs: {
        handoff_bundle_contract: $bundle_contract_path,
        support_surface_contract: (if ($support_contract_path | length) > 0 then $support_contract_path else null end),
        engine_product_blocker_ledger: (if ($blocker_ledger_path | length) > 0 then $blocker_ledger_path else null end),
        repo_split_contract: $repo_split_contract_path,
        sibling_repo_path: $sibling_repo_path
      },
      engine_readiness: {
        support_status_counts: $support_status_counts,
        engine_ready_surface_ids: $engine_ready_surfaces,
        engine_blocked_surface_ids: $engine_blocked_surfaces,
        product_ready_state: $product_ready_state,
        product_ready_owner_repo: $product_ready_owner_repo,
        product_ready_handoff_bead_id: $product_ready_handoff_bead_id
      },
      blocker_summary: $blocker_summary,
      sibling_smoke: {
        verification_artifact: $smoke_verification_path,
        outcome: $smoke_outcome,
        sibling_repo_path: $sibling_repo_path
      },
      summary_artifact: $summary_path,
      rollback_guidance: [
        "Blocked, deferred, unsupported, and candidate surfaces remain target-only in downstream claims.",
        "franken_node must pin an engine revision and pass its own CI matrix before product-ready claims are made.",
        "If blocker-ledger input is missing or stale, regenerate upstream evidence before rebuilding this handoff bundle."
      ]
    }' >"$handoff_manifest_path"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit error_code_json bundle_operator_verification_json
  local support_contract_artifact_path="$copied_support_contract_path"
  local blocker_ledger_artifact_path=""

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ -f "$copied_blocker_ledger_path" ]]; then
    blocker_ledger_artifact_path="$copied_blocker_ledger_path"
  fi

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-408C-GATE-0001"'
  fi

  write_smoke_verification "$outcome"
  write_summary "$outcome"
  write_handoff_manifest "$outcome"
  jq -n --arg trace_id "$trace_id" '[$trace_id]' >"$trace_ids_path"
  bundle_operator_verification_json="$(jq '.operator_verification' "$bundle_contract_json")"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  jq -cn \
    --arg schema_version "franken-engine.rgc-franken-node-handoff-bundle.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "handoff_bundle_completed" \
    --arg outcome "$outcome" \
    --argjson error_code "$error_code_json" \
    '{schema_version: $schema_version, trace_id: $trace_id, decision_id: $decision_id, policy_id: $policy_id, component: $component, event: $event, outcome: $outcome, error_code: $error_code}' \
    >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.rgc-franken-node-handoff-bundle.run-manifest.v1" \
    --arg bead_id "bd-1lsy.5.10.3" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg mode "$mode" \
    --arg toolchain "$toolchain" \
    --arg cargo_target_dir "$target_dir" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg git_commit "$git_commit" \
    --arg generated_at_utc "$timestamp" \
    --arg outcome "$outcome" \
    --arg replay_command "$replay_command" \
    --arg manifest "$manifest_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg trace_ids "$trace_ids_path" \
    --arg handoff_manifest "$handoff_manifest_path" \
    --arg smoke_verification "$smoke_verification_path" \
    --arg summary "$summary_path" \
    --arg bundle_contract_path "$copied_bundle_contract_path" \
    --arg support_contract_path "$support_contract_artifact_path" \
    --arg blocker_ledger_path "$blocker_ledger_artifact_path" \
    --arg repo_split_contract_path "$copied_repo_split_contract_path" \
    --arg step_logs "$step_logs_dir" \
    --arg failed_command "$failed_command" \
    --argjson dirty_worktree "$dirty_worktree_json" \
    --argjson rch_exec_timeout_seconds "$rch_timeout_seconds" \
    --argjson stale_after_hours "$stale_after_hours" \
    --argjson bundle_operator_verification "$bundle_operator_verification_json" \
    --argjson validation_errors "$(json_array_from_args "${validation_errors[@]}")" \
    --argjson commands_run "$(json_array_from_args "${commands_run[@]}")" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      scenario_id: $scenario_id,
      mode: $mode,
      toolchain: $toolchain,
      cargo_target_dir: $cargo_target_dir,
      rch_exec_timeout_seconds: $rch_exec_timeout_seconds,
      stale_after_hours: $stale_after_hours,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      generated_at_utc: $generated_at_utc,
      outcome: $outcome,
      failed_command: (if ($failed_command | length) > 0 then $failed_command else null end),
      validation_errors: $validation_errors,
      replay_command: $replay_command,
      commands: $commands_run,
      artifacts: {
        manifest: $manifest,
        events: $events,
        commands: $commands,
        trace_ids: $trace_ids,
        franken_node_handoff_manifest: $handoff_manifest,
        sibling_smoke_verification: $smoke_verification,
        support_surface_summary: $summary,
        handoff_bundle_contract: $bundle_contract_path,
        support_surface_contract: $support_contract_path,
        engine_product_blocker_ledger: (if ($blocker_ledger_path | length) > 0 then $blocker_ledger_path else null end),
        repo_split_contract: $repo_split_contract_path,
        step_logs: $step_logs,
        contract_test: "crates/franken-engine/tests/franken_node_handoff_bundle.rs"
      },
      operator_verification: [
        ("cat " + $manifest),
        ("cat " + $events),
        ("cat " + $commands),
        ("cat " + $trace_ids),
        ("cat " + $handoff_manifest),
        ("cat " + $smoke_verification),
        ("cat " + $summary)
      ] + $bundle_operator_verification
    }' >"$manifest_path"

  echo "rgc franken_node handoff manifest: ${manifest_path}"
  echo "rgc franken_node handoff events: ${events_path}"
}

main_exit=0
copy_input_artifacts
validate_source_inputs || main_exit=$?
if [[ "$main_exit" -eq 0 ]]; then
  run_mode || main_exit=$?
fi
write_manifest "$main_exit"
exit "$main_exit"
