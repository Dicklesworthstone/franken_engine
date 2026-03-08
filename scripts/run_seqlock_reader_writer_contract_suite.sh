#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-1800}"
artifact_root="${SEQLOCK_READER_WRITER_ARTIFACT_ROOT:-artifacts/seqlock_reader_writer_contract}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_seqlock_reader_writer_contract_${timestamp}}"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/suite_run_manifest.json"
trace_id="${SEQLOCK_READER_WRITER_TRACE_ID:-trace.rgc.621b}"
decision_id="${SEQLOCK_READER_WRITER_DECISION_ID:-decision.rgc.621b}"
policy_id="${SEQLOCK_READER_WRITER_POLICY_ID:-policy.rgc.621b}"
run_id="run-seqlock-reader-writer-contract-${timestamp}"
source_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
suite_commands_path="${run_dir}/suite_commands.txt"

mkdir -p "$run_dir"

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
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
    seqlock_reader_writer_contract.json \
    retry_budget_policy.json \
    incumbent_fallback_matrix.json \
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

  jq -e '.schema_version == "franken-engine.rgc-seqlock-reader-writer-contract.v1"' \
    "${run_dir}/seqlock_reader_writer_contract.json" >/dev/null
  jq -e '.accepted_candidates | length >= 1' \
    "${run_dir}/seqlock_reader_writer_contract.json" >/dev/null
  jq -e '.schema_version == "franken-engine.rgc-seqlock-rw-run-manifest.v1"' \
    "${run_dir}/run_manifest.json" >/dev/null
  jq -e '.contract_hash != null and .retry_policy_hash != null and .fallback_matrix_hash != null' \
    "${run_dir}/run_manifest.json" >/dev/null
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract" \
        cargo check -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract" \
        cargo test -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract -- -D warnings
      ;;
    run)
      run_step "cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- \
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
      run_step "cargo check -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract" \
        cargo check -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract
      run_step "cargo test -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract" \
        cargo test -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract
      run_step "cargo clippy -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test seqlock_reader_writer_contract --bin franken_seqlock_reader_writer_contract -- -D warnings
      run_step "cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- \
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
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
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
    echo '  "schema_version": "franken-engine.rgc-seqlock-rw-run-manifest.v1",'
    echo '  "component": "seqlock_reader_writer_contract",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"toolchain\": \"${toolchain}\","
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
      if [[ "$idx" == "$((${#commands_run[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${suite_commands_path}\","
    echo "    \"contract\": \"${run_dir}/seqlock_reader_writer_contract.json\","
    echo "    \"retry_budget_policy\": \"${run_dir}/retry_budget_policy.json\","
    echo "    \"incumbent_fallback_matrix\": \"${run_dir}/incumbent_fallback_matrix.json\","
    echo "    \"runner_manifest\": \"${run_dir}/run_manifest.json\","
    echo "    \"suite_manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${run_dir}/seqlock_reader_writer_contract.json\","
    echo "    \"cat ${run_dir}/run_manifest.json\","
    echo "    \"cat ${manifest_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
