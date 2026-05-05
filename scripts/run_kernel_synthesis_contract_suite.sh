#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-1800}}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-${rch_build_timeout_sec}}"
artifact_root="${KERNEL_SYNTHESIS_CONTRACT_ARTIFACT_ROOT:-artifacts/kernel_synthesis_contract}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/tmp/rch_target_franken_engine_kernel_synthesis_contract"
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  target_dir="${CARGO_TARGET_DIR}"
  target_dir_strategy="env_override"
else
  target_dir="${default_target_dir}"
  target_dir_strategy="stable_data_tmp_default"
fi
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_dir="${artifact_root}/${timestamp}"
suite_manifest_path="${run_dir}/suite_run_manifest.json"
trace_id="${KERNEL_SYNTHESIS_CONTRACT_TRACE_ID:-trace.rgc.613a}"
decision_id="${KERNEL_SYNTHESIS_CONTRACT_DECISION_ID:-decision.rgc.613a}"
policy_id="${KERNEL_SYNTHESIS_CONTRACT_POLICY_ID:-policy.rgc.613a}"
run_id="run-kernel-synthesis-contract-${timestamp}"
source_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
suite_commands_path="${run_dir}/suite_commands.txt"
suite_target_text="--bin franken_kernel_synthesis_contract --test kernel_synthesis_contract_integration --test kernel_synthesis_contract_enrichment_integration --test synthesis_eligibility_envelope_integration --test synthesis_eligibility_envelope_enrichment_integration --test superoptimization_gate_integration"
suite_target_args=(
  --bin franken_kernel_synthesis_contract
  --test kernel_synthesis_contract_integration
  --test kernel_synthesis_contract_enrichment_integration
  --test synthesis_eligibility_envelope_integration
  --test synthesis_eligibility_envelope_enrichment_integration
  --test superoptimization_gate_integration
)

mkdir -p "$run_dir"

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required to fail closed on kernel synthesis contract rch steps" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_exec_timeout_seconds}" \
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
  RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_exec_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

verify_bundle() {
  local artifact
  for artifact in \
    kernel_schema_catalog.json \
    synthesis_eligibility_report.json \
    kernel_synth_evidence_manifest.json \
    superoptimization_report.json \
    run_manifest.json \
    events.jsonl \
    commands.txt \
    trace_ids.json \
    env.json \
    manifest.json \
    repro.lock \
    summary.md; do
    [[ -f "${run_dir}/${artifact}" ]] || {
      echo "missing required artifact: ${artifact}" >&2
      return 1
    }
  done

  jq -e '.schemas | length >= 10' "${run_dir}/kernel_schema_catalog.json" >/dev/null
  jq -e '.decisions | length >= 10' "${run_dir}/kernel_schema_catalog.json" >/dev/null
  jq -e '.schema_version == "franken-engine.kernel-synthesis-eligibility-report.v1"' \
    "${run_dir}/synthesis_eligibility_report.json" >/dev/null
  jq -e '.eligible_count >= 1 and .forbidden_count >= 1' \
    "${run_dir}/synthesis_eligibility_report.json" >/dev/null
  jq -e '.schema_version == "franken-engine.kernel-synthesis-contract.run-manifest.v1"' \
    "${run_dir}/run_manifest.json" >/dev/null
  jq -e '.certificates | length >= 10' \
    "${run_dir}/kernel_synth_evidence_manifest.json" >/dev/null
  jq -e '.schema_version == "franken-engine.budgeted-superoptimization-report.v1"' \
    "${run_dir}/superoptimization_report.json" >/dev/null
  jq -e '.admitted_candidate_count >= 1 and .refuted_candidate_count >= 1 and .timed_out_candidate_count >= 1 and .total_counterexamples >= 1' \
    "${run_dir}/superoptimization_report.json" >/dev/null
  jq -e '.deterministic_rollback.fallback_path == "baseline_compiled_code" and .deterministic_rollback.deterministic == true' \
    "${run_dir}/superoptimization_report.json" >/dev/null
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine ${suite_target_text}" \
        cargo check -p frankenengine-engine "${suite_target_args[@]}"
      ;;
    test)
      run_step "cargo test -p frankenengine-engine ${suite_target_text}" \
        cargo test -p frankenengine-engine "${suite_target_args[@]}"
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine ${suite_target_text} -- -D warnings" \
        cargo clippy -p frankenengine-engine "${suite_target_args[@]}" -- -D warnings
      ;;
    run)
      run_step "cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine ${suite_target_text}" \
        cargo check -p frankenengine-engine "${suite_target_args[@]}"
      run_step "cargo test -p frankenengine-engine ${suite_target_text}" \
        cargo test -p frankenengine-engine "${suite_target_args[@]}"
      run_step "cargo clippy -p frankenengine-engine ${suite_target_text} -- -D warnings" \
        cargo clippy -p frankenengine-engine "${suite_target_args[@]}" -- -D warnings
      run_step "cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    *)
      echo "usage: $0 [check|test|clippy|run|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome dirty_worktree idx comma
  if [[ "${manifest_written}" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${suite_commands_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-kernel-synthesis-contract-suite.v1",'
    echo '  "component": "kernel_synthesis_contract_suite",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir_strategy\": \"${target_dir_strategy}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"git_commit\": \"${source_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${generated_at_utc}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$((${#commands_run[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"suite_command_log\": \"${suite_commands_path}\","
    echo "    \"kernel_schema_catalog\": \"${run_dir}/kernel_schema_catalog.json\","
    echo "    \"synthesis_eligibility_report\": \"${run_dir}/synthesis_eligibility_report.json\","
    echo "    \"kernel_synth_evidence_manifest\": \"${run_dir}/kernel_synth_evidence_manifest.json\","
    echo "    \"superoptimization_report\": \"${run_dir}/superoptimization_report.json\","
    echo "    \"runner_manifest\": \"${run_dir}/run_manifest.json\","
    echo "    \"suite_manifest\": \"${suite_manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${run_dir}/kernel_schema_catalog.json\","
    echo "    \"cat ${run_dir}/synthesis_eligibility_report.json\","
    echo "    \"cat ${run_dir}/kernel_synth_evidence_manifest.json\","
    echo "    \"cat ${run_dir}/superoptimization_report.json\","
    echo "    \"cat ${run_dir}/run_manifest.json\","
    echo "    \"cat ${suite_manifest_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${suite_manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
