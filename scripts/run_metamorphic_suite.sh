#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_metamorphic_uid$(id -u)}"
pairs="${METAMORPHIC_PAIRS:-1000}"
seed="${METAMORPHIC_SEED:-1}"
relation_filter_csv="${METAMORPHIC_RELATIONS:-}"
artifact_root="${METAMORPHIC_ARTIFACT_ROOT:-artifacts/metamorphic}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
runner_run_dir="$target_dir/debug/metamorphic_artifacts/$timestamp"
manifest_path="$run_dir/run_manifest.json"
commands_path="$run_dir/commands.txt"
events_path="$run_dir/events.jsonl"
relation_events_path="$run_dir/relation_events.jsonl"
evidence_path="$run_dir/metamorphic_evidence.jsonl"
seed_transcript_path="$run_dir/seed_transcript.jsonl"
seed_manifest_path="$run_dir/seed_manifest.json"
property_generator_catalog_path="$run_dir/property_generator_catalog.json"
generator_choice_stream_schema_path="$run_dir/generator_choice_stream_schema.json"
shrinker_verdict_report_path="$run_dir/shrinker_verdict_report.json"
minimized_counterexamples_path="$run_dir/minimized_property_counterexamples.jsonl"
triage_report_path="$run_dir/triage_report.json"
governance_actions_path="$run_dir/repro_governance_actions.json"
trace_ids_path="$run_dir/trace_ids.json"
env_path="$run_dir/env.json"
bundle_manifest_path="$run_dir/manifest.json"
repro_lock_path="$run_dir/repro.lock"
failures_dir="$run_dir/failures"
runner_relation_events_path="$runner_run_dir/relation_events.jsonl"
runner_evidence_path="$runner_run_dir/metamorphic_evidence.jsonl"
runner_seed_transcript_path="$runner_run_dir/seed_transcript.jsonl"
runner_seed_manifest_path="$runner_run_dir/seed_manifest.json"
runner_property_generator_catalog_path="$runner_run_dir/property_generator_catalog.json"
runner_generator_choice_stream_schema_path="$runner_run_dir/generator_choice_stream_schema.json"
runner_shrinker_verdict_report_path="$runner_run_dir/shrinker_verdict_report.json"
runner_minimized_counterexamples_path="$runner_run_dir/minimized_property_counterexamples.jsonl"
runner_triage_report_path="$runner_run_dir/triage_report.json"
runner_governance_actions_path="$runner_run_dir/repro_governance_actions.json"
runner_failures_dir="$runner_run_dir/failures"
trace_id="trace-metamorphic-$timestamp"
decision_id="decision-metamorphic-$timestamp"
policy_id="policy-metamorphic-v1"
rch_required=true
rch_present=true
rch_missing=false
rch_missing_error_code="FE-META-RCH-0002"
declare -a relation_filters=()
declare -a relation_args=()
relation_command_suffix=""
relation_filters_manifest_json="[]"
replay_command="./scripts/e2e/metamorphic_suite_replay.sh ${mode}"

mkdir -p "$run_dir" "$failures_dir"

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    rch_present=false
    rch_missing=true
    echo "error: rch is required for metamorphic suite heavy cargo execution (${rch_missing_error_code})" >&2
    return 127
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

trim_ascii_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

configure_relation_filters() {
  local raw_filter trimmed idx comma
  local raw_filters=()

  if [[ -z "$relation_filter_csv" ]]; then
    return
  fi

  IFS=',' read -r -a raw_filters <<< "$relation_filter_csv"
  for raw_filter in "${raw_filters[@]}"; do
    trimmed="$(trim_ascii_whitespace "$raw_filter")"
    if [[ -z "$trimmed" ]]; then
      continue
    fi
    relation_filters+=("$trimmed")
    relation_args+=(--relation "$trimmed")
  done

  if [[ "${#relation_filters[@]}" -eq 0 ]]; then
    return
  fi

  relation_filters_manifest_json="["
  for idx in "${!relation_filters[@]}"; do
    relation_command_suffix+=" --relation=${relation_filters[$idx]}"
    comma=","
    if [[ "$idx" == "$(( ${#relation_filters[@]} - 1 ))" ]]; then
      comma=""
    fi
    relation_filters_manifest_json+="\"$(json_escape "${relation_filters[$idx]}")\"${comma}"
  done
  relation_filters_manifest_json+="]"
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  shift
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  local rc
  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch "$@" > >(tee "$step_log_path") 2>&1
  rc=$?
  set -e
  if ! reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
  if ! require_remote_success_marker "$step_log_path"; then
    failed_command="${command_text} (rch-success-marker-missing)"
    return 87
  fi
}

run_metamorphic_runner_step() {
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  local command_text="cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$evidence_path --events=$relation_events_path --seed-transcript=$seed_transcript_path --seed-manifest=$seed_manifest_path --property-generator-catalog=$property_generator_catalog_path --generator-choice-stream-schema=$generator_choice_stream_schema_path --shrinker-verdict-report=$shrinker_verdict_report_path --minimized-counterexamples=$minimized_counterexamples_path --triage-report=$triage_report_path --governance-actions=$governance_actions_path --failures-dir=$failures_dir${relation_command_suffix}"
  local rc
  local runner_command remote_script
  local -a runner_args=(
    cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite --
    --pairs "$pairs"
    --seed "$seed"
    --trace-id "$trace_id"
    --decision-id "$decision_id"
    --policy-id "$policy_id"
    --evidence "$evidence_path"
    --events "$relation_events_path"
    --seed-transcript "$seed_transcript_path"
    --seed-manifest "$seed_manifest_path"
    --property-generator-catalog "$property_generator_catalog_path"
    --generator-choice-stream-schema "$generator_choice_stream_schema_path"
    --shrinker-verdict-report "$shrinker_verdict_report_path"
    --minimized-counterexamples "$minimized_counterexamples_path"
    --triage-report "$triage_report_path"
    --governance-actions "$governance_actions_path"
    --failures-dir "$failures_dir"
    "${relation_args[@]}"
  )

  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"

  printf -v runner_command '%q ' "${runner_args[@]}"
  remote_script="${runner_command% }"
  remote_script="'${remote_script//\'/\'\\\'\'}'"

  set +e
  run_rch bash -lc "$remote_script" > >(tee "$step_log_path") 2>&1
  rc=$?
  set -e

  if ! reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
}

ensure_rch() {
  if command -v rch >/dev/null 2>&1; then
    return 0
  fi
  rch_present=false
  rch_missing=true
  failed_command="rch exec (required preflight)"
  echo "error: rch is required for ${0##*/} and local fallback is disabled (${rch_missing_error_code})" >&2
  return 127
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      ;;
    test)
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_metamorphic_runner_step
      hydrate_local_metamorphic_artifacts
      if ! ensure_metamorphic_artifacts_complete; then
        echo "error: metamorphic artifact contract missing after test mode" >&2
        failed_command="test_artifact_validation"
        return 1
      fi
      ;;
    ci)
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_metamorphic_runner_step
      hydrate_local_metamorphic_artifacts
      if ! ensure_metamorphic_artifacts_complete; then
        echo "error: metamorphic artifact contract missing after ci mode" >&2
        failed_command="ci_artifact_validation"
        return 1
      fi
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json failure_reason_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
    failure_reason_json='null'
  else
    outcome="fail"
    if [[ "$rch_missing" == true ]]; then
      error_code_json="\"${rch_missing_error_code}\""
      failure_reason_json='"rch_unavailable"'
    else
      error_code_json='"FE-META-0001"'
      failure_reason_json='null'
    fi
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{"
    echo '  "component": "metamorphic_suite",'
    echo '  "bead_id": "bd-1lsy.9.3",'
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"rch_required\": ${rch_required},"
    echo "  \"rch_present\": ${rch_present},"
    echo "  \"error_code\": ${error_code_json},"
    echo "  \"failure_reason\": ${failure_reason_json},"
    echo "  \"pairs\": ${pairs},"
    echo "  \"seed\": ${seed},"
    echo "  \"relation_filter_count\": ${#relation_filters[@]},"
    echo "  \"relation_filters\": ${relation_filters_manifest_json},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"replay_command\": \"$(json_escape "${replay_command}")\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\"," 
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(json_escape "${failed_command}")\"," 
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"relation_events\": \"${relation_events_path}\"," 
    echo "    \"evidence\": \"${evidence_path}\"," 
    echo "    \"seed_transcript\": \"${seed_transcript_path}\"," 
    echo "    \"seed_manifest\": \"${seed_manifest_path}\"," 
    echo "    \"property_generator_catalog\": \"${property_generator_catalog_path}\"," 
    echo "    \"generator_choice_stream_schema\": \"${generator_choice_stream_schema_path}\"," 
    echo "    \"shrinker_verdict_report\": \"${shrinker_verdict_report_path}\"," 
    echo "    \"minimized_property_counterexamples\": \"${minimized_counterexamples_path}\"," 
    echo "    \"triage_report\": \"${triage_report_path}\"," 
    echo "    \"governance_actions\": \"${governance_actions_path}\"," 
    echo "    \"trace_ids\": \"${trace_ids_path}\"," 
    echo "    \"env\": \"${env_path}\"," 
    echo "    \"manifest_bundle\": \"${bundle_manifest_path}\"," 
    echo "    \"repro_lock\": \"${repro_lock_path}\"," 
    echo "    \"failures_dir\": \"${failures_dir}\"," 
    echo "    \"command_log\": \"${commands_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${relation_events_path}\"," 
    echo "    \"cat ${evidence_path}\"," 
    echo "    \"cat ${seed_transcript_path}\"," 
    echo "    \"cat ${seed_manifest_path}\"," 
    echo "    \"cat ${property_generator_catalog_path}\"," 
    echo "    \"cat ${generator_choice_stream_schema_path}\"," 
    echo "    \"cat ${shrinker_verdict_report_path}\"," 
    echo "    \"cat ${minimized_counterexamples_path}\"," 
    echo "    \"cat ${triage_report_path}\"," 
    echo "    \"cat ${governance_actions_path}\"," 
    echo "    \"cat ${trace_ids_path}\"," 
    echo "    \"cat ${env_path}\"," 
    echo "    \"cat ${bundle_manifest_path}\"," 
    echo "    \"cat ${repro_lock_path}\"," 
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"metamorphic_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  write_trace_ids
  write_env_json "$git_commit" "$dirty_worktree"
  write_repro_lock "$git_commit"
  write_bundle_manifest "$git_commit" "$dirty_worktree" "$outcome"

  echo "metamorphic manifest: $manifest_path"
  echo "metamorphic events: $events_path"
  echo "metamorphic evidence: $evidence_path"
}

configure_relation_filters

file_sha256() {
  local path="$1"
  if [[ -f "$path" ]]; then
    sha256sum "$path" | awk '{print $1}'
  fi
}

file_sha256_json() {
  local path="$1"
  local digest
  digest="$(file_sha256 "$path")"
  if [[ -n "$digest" ]]; then
    printf '"sha256:%s"' "$digest"
  else
    printf 'null'
  fi
}

file_bytes() {
  local path="$1"
  if [[ -f "$path" ]]; then
    wc -c <"$path" | tr -d '[:space:]'
  else
    printf '0'
  fi
}

write_trace_ids() {
  {
    echo "{"
    echo '  "schema_version": "franken-engine.metamorphic.trace-ids.v1",'
    echo '  "component": "metamorphic_suite",'
    echo '  "bead_id": "bd-1lsy.9.3.1",'
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\""
    echo "}"
  } >"$trace_ids_path"
}

write_env_json() {
  local git_commit="$1"
  local dirty_worktree="$2"
  local kernel arch cpu_model cpu_cores memory_bytes rustc_version cargo_version llvm_version

  kernel="$(uname -r 2>/dev/null || echo "unknown")"
  arch="$(uname -m 2>/dev/null || echo "unknown")"
  cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || true)"
  cpu_model="${cpu_model:-unknown}"
  cpu_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)"
  memory_bytes="$(awk '/MemTotal/ {print $2 * 1024; exit}' /proc/meminfo 2>/dev/null || echo 0)"
  rustc_version="$(rustc -V 2>/dev/null || echo "unknown")"
  cargo_version="$(cargo -V 2>/dev/null || echo "unknown")"
  llvm_version="$(rustc -Vv 2>/dev/null | awk -F': ' '/^LLVM version/ {print $2; exit}' || true)"
  llvm_version="${llvm_version:-unknown}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.env.v1",'
    echo '  "schema_hash": "sha256:env-schema-v1",'
    echo "  \"captured_at_utc\": \"${timestamp}\","
    echo '  "project": {'
    echo '    "name": "franken_engine",'
    echo '    "repo_url": "https://github.com/Dicklesworthstone/franken_engine",'
    echo "    \"commit\": \"${git_commit}\","
    echo "    \"dirty\": ${dirty_worktree}"
    echo '  },'
    echo '  "host": {'
    echo '    "os": "linux",'
    echo "    \"kernel\": \"$(json_escape "${kernel}")\","
    echo "    \"arch\": \"$(json_escape "${arch}")\","
    echo "    \"cpu_model\": \"$(json_escape "${cpu_model}")\","
    echo "    \"cpu_cores_logical\": ${cpu_cores},"
    echo "    \"memory_bytes\": ${memory_bytes}"
    echo '  },'
    echo '  "toolchain": {'
    echo "    \"rustc\": \"$(json_escape "${rustc_version}")\","
    echo "    \"cargo\": \"$(json_escape "${cargo_version}")\","
    echo "    \"llvm\": \"$(json_escape "${llvm_version}")\","
    echo "    \"target_triple\": \"$(json_escape "${arch}")-unknown-linux-gnu\","
    echo "    \"profile\": \"${mode}\""
    echo '  },'
    echo '  "runtime": {'
    echo '    "mode": "rch_remote",'
    echo '    "lane": "metamorphic_property_campaign",'
    echo '    "safe_mode_enabled": true,'
    echo '    "feature_flags": ["metamorphic", "property_generator", "choice_stream_shrinking"]'
    echo '  },'
    echo '  "policy": {'
    echo "    \"policy_id\": \"${policy_id}\","
    echo '    "policy_digest_sha256": "sha256:metamorphic-policy-v1"'
    echo '  }'
    echo "}"
  } >"$env_path"
}

write_repro_lock() {
  local git_commit="$1"
  local idx comma
  local relation_catalog_path="crates/franken-metamorphic/metamorphic_relations.toml"
  local relation_catalog_sha relation_catalog_bytes

  relation_catalog_sha="$(file_sha256 "$relation_catalog_path")"
  relation_catalog_bytes="$(file_bytes "$relation_catalog_path")"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.repro-lock.v1",'
    echo '  "schema_hash": "sha256:repro-lock-schema-v1",'
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"lock_id\": \"metamorphic-repro-lock-${timestamp}\","
    echo "  \"manifest_id\": \"metamorphic-manifest-${timestamp}\","
    echo "  \"source_commit\": \"${git_commit}\","
    echo '  "determinism": {'
    echo '    "allow_network": false,'
    echo '    "allow_wall_clock": false,'
    echo '    "allow_randomness": false,'
    echo '    "max_clock_skew_seconds": 0'
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "inputs": ['
    echo '    {'
    echo "      \"path\": \"${relation_catalog_path}\","
    echo "      \"sha256\": \"sha256:${relation_catalog_sha}\","
    echo "      \"bytes\": ${relation_catalog_bytes},"
    echo '      "kind": "input"'
    echo '    }'
    echo '  ],'
    echo '  "expected_outputs": ['
    emit_repro_output "$manifest_path" "run_manifest" true
    emit_repro_output "$events_path" "events" true
    emit_repro_output "$relation_events_path" "relation_events" true
    emit_repro_output "$evidence_path" "evidence" true
    emit_repro_output "$seed_transcript_path" "seed_transcript" true
    emit_repro_output "$seed_manifest_path" "seed_manifest" true
    emit_repro_output "$property_generator_catalog_path" "property_generator_catalog" true
    emit_repro_output "$generator_choice_stream_schema_path" "generator_choice_stream_schema" true
    emit_repro_output "$shrinker_verdict_report_path" "shrinker_verdict_report" true
    emit_repro_output "$minimized_counterexamples_path" "minimized_property_counterexamples" true
    emit_repro_output "$triage_report_path" "triage_report" true
    emit_repro_output "$governance_actions_path" "repro_governance_actions" true
    emit_repro_output "$trace_ids_path" "trace_ids" true
    emit_repro_output "$env_path" "env" false
    echo '  ],'
    echo '  "replay": {'
    echo "    \"trace_id\": \"${trace_id}\","
    echo "    \"replay_pointer\": \"replay://metamorphic/${timestamp}\""
    echo '  },'
    echo '  "verification": {'
    echo "    \"command\": \"frankenctl repro verify --bundle ${run_dir} --output ${run_dir}/verify_report.json\","
    echo '    "expected_verdict": "pass"'
    echo '  }'
    echo "}"
  } >"$repro_lock_path"
}

emit_repro_output() {
  local path="$1"
  local kind="$2"
  local trailing_comma="$3"
  local digest bytes comma

  digest="$(file_sha256 "$path")"
  bytes="$(file_bytes "$path")"
  comma=""
  if [[ "$trailing_comma" == true ]]; then
    comma=","
  fi

  {
    echo '    {'
    echo "      \"path\": \"${path}\","
    if [[ -n "$digest" ]]; then
      echo "      \"sha256\": \"sha256:${digest}\","
    else
      echo '      "sha256": null,'
    fi
    echo "      \"bytes\": ${bytes},"
    echo "      \"kind\": \"${kind}\""
    echo "    }${comma}"
  }
}

write_bundle_manifest() {
  local git_commit="$1"
  local dirty_worktree="$2"
  local outcome="$3"
  local claim_status commands_sha env_sha repro_sha

  if [[ "$outcome" == "pass" ]]; then
    claim_status="observed"
  else
    claim_status="intent"
  fi

  commands_sha="$(file_sha256_json "$commands_path")"
  env_sha="$(file_sha256_json "$env_path")"
  repro_sha="$(file_sha256_json "$repro_lock_path")"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.manifest.v1",'
    echo '  "schema_hash": "sha256:manifest-schema-v1",'
    echo "  \"manifest_id\": \"metamorphic-manifest-${timestamp}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo '  "claim": {'
    echo '    "claim_id": "claim.metamorphic.property_generator_choice_stream",'
    echo '    "class": "DETERMINISM",'
    echo '    "statement": "Metamorphic campaign emits deterministic property-generator, choice-stream, and shrinker artifacts.",'
    echo "    \"status\": \"${claim_status}\","
    echo "    \"bundle_root\": \"${run_dir}\""
    echo '  },'
    echo '  "source_revision": {'
    echo '    "repo": "franken_engine",'
    echo '    "branch": "main",'
    echo "    \"commit\": \"${git_commit}\""
    echo '  },'
    echo '  "provenance": {'
    echo "    \"trace_id\": \"${trace_id}\","
    echo "    \"decision_id\": \"${decision_id}\","
    echo "    \"policy_id\": \"${policy_id}\","
    echo "    \"replay_pointer\": \"replay://metamorphic/${timestamp}\","
    echo "    \"evidence_pointer\": \"evidence://metamorphic/${timestamp}\","
    echo '    "receipt_ids": ["rcpt-metamorphic-suite"]'
    echo '  },'
    echo '  "artifacts": {'
    echo '    "env": {'
    echo "      \"path\": \"${env_path}\","
    echo "      \"sha256\": ${env_sha}"
    echo '    },'
    echo '    "lock": {'
    echo "      \"path\": \"${repro_lock_path}\","
    echo "      \"sha256\": ${repro_sha}"
    echo '    },'
    echo '    "commands": {'
    echo "      \"path\": \"${commands_path}\","
    echo "      \"sha256\": ${commands_sha}"
    echo '    },'
    echo '    "run_manifest": {'
    echo "      \"path\": \"${manifest_path}\","
    echo "      \"sha256\": $(file_sha256_json "$manifest_path")"
    echo '    },'
    echo '    "trace_ids": {'
    echo "      \"path\": \"${trace_ids_path}\","
    echo "      \"sha256\": $(file_sha256_json "$trace_ids_path")"
    echo '    }'
    echo '  },'
    echo '  "inputs": ['
    echo '    {'
    echo '      "path": "crates/franken-metamorphic/metamorphic_relations.toml",'
    echo "      \"sha256\": $(file_sha256_json "crates/franken-metamorphic/metamorphic_relations.toml")"
    echo '    }'
    echo '  ],'
    echo '  "outputs": ['
    echo '    {'
    echo "      \"path\": \"${property_generator_catalog_path}\","
    echo "      \"sha256\": $(file_sha256_json "$property_generator_catalog_path")"
    echo '    },'
    echo '    {'
    echo "      \"path\": \"${generator_choice_stream_schema_path}\","
    echo "      \"sha256\": $(file_sha256_json "$generator_choice_stream_schema_path")"
    echo '    },'
    echo '    {'
    echo "      \"path\": \"${shrinker_verdict_report_path}\","
    echo "      \"sha256\": $(file_sha256_json "$shrinker_verdict_report_path")"
    echo '    },'
    echo '    {'
    echo "      \"path\": \"${minimized_counterexamples_path}\","
    echo "      \"sha256\": $(file_sha256_json "$minimized_counterexamples_path")"
    echo '    }'
    echo '  ],'
    echo '  "canonicalization": {'
    echo '    "format": "json",'
    echo '    "key_order": "lexicographic",'
    echo '    "newline": "lf",'
    echo '    "hash_algorithm": "sha256"'
    echo '  },'
    echo '  "validation": {'
    echo '    "validator": "frankenctl repro verify",'
    echo '    "error_taxonomy": "FE-REPRO-0001..FE-REPRO-0008"'
    echo '  },'
    echo '  "retention": {'
    echo '    "min_days": 365,'
    echo '    "high_impact_min_days": 730,'
    echo '    "rotation_policy": "archive-with-addressable-retrieval"'
    echo '  }'
    echo "}"
  } >"$bundle_manifest_path"
}

hydrate_local_metamorphic_artifacts() {
  local runner_file local_file

  mkdir -p "$run_dir" "$failures_dir"

  local runner_files=(
    "$runner_relation_events_path"
    "$runner_evidence_path"
    "$runner_seed_transcript_path"
    "$runner_seed_manifest_path"
    "$runner_property_generator_catalog_path"
    "$runner_generator_choice_stream_schema_path"
    "$runner_shrinker_verdict_report_path"
    "$runner_minimized_counterexamples_path"
    "$runner_triage_report_path"
    "$runner_governance_actions_path"
  )
  local local_files=(
    "$relation_events_path"
    "$evidence_path"
    "$seed_transcript_path"
    "$seed_manifest_path"
    "$property_generator_catalog_path"
    "$generator_choice_stream_schema_path"
    "$shrinker_verdict_report_path"
    "$minimized_counterexamples_path"
    "$triage_report_path"
    "$governance_actions_path"
  )

  local idx
  for idx in "${!runner_files[@]}"; do
    runner_file="${runner_files[$idx]}"
    local_file="${local_files[$idx]}"
    if [[ -f "$runner_file" ]]; then
      mkdir -p "$(dirname "$local_file")"
      cp "$runner_file" "$local_file"
    fi
  done

  if [[ -d "$runner_failures_dir" ]]; then
    mkdir -p "$failures_dir"
    while IFS= read -r -d '' runner_file; do
      cp "$runner_file" "$failures_dir/"
    done < <(find "$runner_failures_dir" -maxdepth 1 -mindepth 1 -type f -print0)
  fi
}

metamorphic_artifacts_complete() {
  local required
  for required in \
    "$relation_events_path" \
    "$evidence_path" \
    "$seed_transcript_path" \
    "$seed_manifest_path" \
    "$property_generator_catalog_path" \
    "$generator_choice_stream_schema_path" \
    "$shrinker_verdict_report_path" \
    "$minimized_counterexamples_path" \
    "$triage_report_path" \
    "$governance_actions_path"; do
    if [[ ! -f "$required" ]]; then
      return 1
    fi
  done
  return 0
}

pull_remote_file_if_missing() {
  local remote_path="$1"
  local path="$2"
  local tmp_path

  if [[ -f "$path" ]]; then
    return 0
  fi

  if ! RCH_LOG_LEVEL=error run_rch test -f "$remote_path" >/dev/null 2>&1; then
    return 1
  fi

  mkdir -p "$(dirname "$path")"
  tmp_path="${path}.remote.$$"
  if ! RCH_LOG_LEVEL=error run_rch cat "$remote_path" >"$tmp_path"; then
    rm -f "$tmp_path"
    return 1
  fi

  mv "$tmp_path" "$path"
}

sync_metamorphic_artifacts_from_remote() {
  local remote_file local_file idx
  local missing_any=false
  local remote_files=(
    "$runner_relation_events_path"
    "$runner_evidence_path"
    "$runner_seed_transcript_path"
    "$runner_seed_manifest_path"
    "$runner_property_generator_catalog_path"
    "$runner_generator_choice_stream_schema_path"
    "$runner_shrinker_verdict_report_path"
    "$runner_minimized_counterexamples_path"
    "$runner_triage_report_path"
    "$runner_governance_actions_path"
  )
  local local_files=(
    "$relation_events_path"
    "$evidence_path"
    "$seed_transcript_path"
    "$seed_manifest_path"
    "$property_generator_catalog_path"
    "$generator_choice_stream_schema_path"
    "$shrinker_verdict_report_path"
    "$minimized_counterexamples_path"
    "$triage_report_path"
    "$governance_actions_path"
  )

  for idx in "${!remote_files[@]}"; do
    remote_file="${remote_files[$idx]}"
    local_file="${local_files[$idx]}"
    if [[ -f "$local_file" ]]; then
      continue
    fi
    if ! pull_remote_file_if_missing "$remote_file" "$local_file"; then
      missing_any=true
    fi
  done

  [[ "$missing_any" == false ]]
}

ensure_metamorphic_artifacts_complete() {
  hydrate_local_metamorphic_artifacts
  if metamorphic_artifacts_complete; then
    return 0
  fi

  sync_metamorphic_artifacts_from_remote || true
  metamorphic_artifacts_complete
}

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|running locally|Failed to query daemon:.*running locally|RCH-E326' "$log_path"; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

require_remote_success_marker() {
  local log_path="$1"
  if ! grep -Eq 'Remote command finished: exit=0' "$log_path"; then
    echo "error: missing successful remote completion marker in ${log_path}" >&2
    return 1
  fi
}

trap 'write_manifest $?' EXIT
ensure_rch
run_mode
