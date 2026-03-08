#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-1800}"
artifact_root="${LAW_MINING_ARTIFACT_ROOT:-artifacts/law_mining}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_law_mining_${timestamp}}"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/suite_run_manifest.json"
trace_id="${LAW_MINING_TRACE_ID:-trace.rgc.810}"
decision_id="${LAW_MINING_DECISION_ID:-decision.rgc.810}"
policy_id="${LAW_MINING_POLICY_ID:-policy.rgc.810}"
run_id="run-law-mining-${timestamp}"
source_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
suite_commands_path="${run_dir}/suite_commands.txt"
local_binary_path="${root_dir}/target/debug/franken_law_mining"

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

run_local_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

verify_bundle() {
  local artifact
  for artifact in \
    candidate_law_catalog.json \
    invariant_seed_ledger.json \
    normal_form_hypotheses.json \
    law_provenance_index.json \
    candidate_scope_hypotheses.json \
    trace_ids.json \
    run_manifest.json \
    events.jsonl \
    commands.txt \
    env.json \
    manifest.json \
    repro.lock \
    summary.md; do
    [[ -f "${run_dir}/${artifact}" ]] || {
      echo "missing required artifact: ${artifact}" >&2
      return 1
    }
  done

  jq -e '.schema_version == "franken-engine.law-mining.candidate-law-catalog.v1"' \
    "${run_dir}/candidate_law_catalog.json" >/dev/null
  jq -e '.schema_version == "franken-engine.law-mining.run-manifest.v1"' \
    "${run_dir}/run_manifest.json" >/dev/null
  jq -e '.schema_version == "franken-engine.law-mining.artifact-index.v1"' \
    "${run_dir}/manifest.json" >/dev/null
  grep -q '^# Law Mining Summary' "${run_dir}/summary.md"
}

build_and_run_bundle_locally() {
  run_step "cargo build -p frankenengine-engine --bin franken_law_mining" \
    cargo build -p frankenengine-engine --bin franken_law_mining
  [[ -x "${local_binary_path}" ]] || {
    echo "missing local binary: ${local_binary_path}" >&2
    return 1
  }
  run_local_step "${local_binary_path} --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
    "${local_binary_path}" \
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
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining" \
        cargo check -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test law_mining_integration --test law_mining_cli --bin franken_law_mining" \
        cargo test -p frankenengine-engine --test law_mining_integration --test law_mining_cli --bin franken_law_mining
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining -- -D warnings
      ;;
    run)
      build_and_run_bundle_locally
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining" \
        cargo check -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining
      run_step "cargo test -p frankenengine-engine --test law_mining_integration --test law_mining_cli --bin franken_law_mining" \
        cargo test -p frankenengine-engine --test law_mining_integration --test law_mining_cli --bin franken_law_mining
      run_step "cargo clippy -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test law_mining_integration --test law_mining_cli --bin franken_law_mining -- -D warnings
      build_and_run_bundle_locally
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
    echo '  "schema_version": "franken-engine.law-mining.suite-run-manifest.v1",'
    echo '  "component": "law_mining",'
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
    echo "    \"suite_commands\": \"${suite_commands_path}\","
    echo "    \"candidate_law_catalog\": \"${run_dir}/candidate_law_catalog.json\","
    echo "    \"run_manifest\": \"${run_dir}/run_manifest.json\","
    echo "    \"summary\": \"${run_dir}/summary.md\","
    echo "    \"suite_manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${run_dir}/candidate_law_catalog.json\","
    echo "    \"cat ${run_dir}/run_manifest.json\","
    echo "    \"cat ${run_dir}/summary.md\","
    echo "    \"$0 ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
